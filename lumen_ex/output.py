"""Contract-safe serialization and validation for sanitized release artifacts."""

import copy
import csv
from dataclasses import dataclass, field
from decimal import Decimal
import hashlib
import hmac
import io
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from lumen_ex.contracts.models import (
    InputFileMetadata,
    InputFormat,
    NormalizedRecord,
    OutputManifestEntry,
    ParsedRecord,
    ProcessingStatus,
    SanitizationResult,
)
from lumen_ex.errors import ProcessingError, SAFE_ERROR_CODES
from lumen_ex.identity import is_json_envelope_identity
from lumen_ex.ingestion import validate_fhir_document
from lumen_ex.security import SensitiveDataLeakScanner


_OUTPUT_EXTENSIONS = {
    InputFormat.CSV: ".csv",
    InputFormat.TSV: ".tsv",
    InputFormat.JSON: ".json",
    InputFormat.FHIR: ".json",
    InputFormat.TEXT: ".txt",
}
# Keep token bytes out of the scanner's numeric-identifier patterns.
_PATH_TOKEN_ALPHABET = str.maketrans("0123456789", "qrstuvwxyz")

_SAFE_HEADER_NAMES = {
    "name",
    "fullname",
    "patientname",
    "patientfullname",
    "firstname",
    "lastname",
    "givenname",
    "familyname",
    "relative",
    "relativename",
    "fathername",
    "mothername",
    "age",
    "patientage",
    "gender",
    "sex",
    "dob",
    "dateofbirth",
    "birthdate",
    "phone",
    "phonenumber",
    "mobile",
    "mobilenumber",
    "email",
    "address",
    "location",
    "city",
    "village",
    "district",
    "state",
    "pin",
    "pincode",
    "postalcode",
    "patientid",
    "patientidentifier",
    "hospitalid",
    "uhid",
    "mrn",
    "medicalrecordnumber",
    "insuranceid",
    "aadhaar",
    "aadhar",
    "abha",
    "pan",
    "diagnosis",
    "condition",
    "procedure",
    "medication",
    "medicine",
    "drug",
    "dose",
    "dosage",
    "frequency",
    "vital",
    "vitals",
    "labresult",
    "test",
    "unit",
    "loinc",
    "laboratory",
    "complaint",
    "history",
    "ward",
    "clinician",
    "doctor",
    "icd",
    "date",
    "visitdate",
    "encounterdate",
    "admissiondate",
    "dischargedate",
    "hospital",
    "facility",
    "lengthofstay",
    "staydays",
    "status",
    "result",
    "code",
}
_HEADER_IDENTIFIER = re.compile(
    r"(?i)(?<![A-Z0-9])[A-Z0-9][A-Z0-9-]{7,}(?![A-Z0-9])"
)


@dataclass(frozen=True)
class ReleaseRecord:
    parsed: ParsedRecord
    normalized: NormalizedRecord
    result: SanitizationResult
    sensitive_values: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class FileWriteResult:
    manifest: OutputManifestEntry
    records: tuple[dict[str, object], ...] = ()
    records_quarantined: int = 0


class SanitizedOutputWriter:
    """Serialize complete source files only after all of their records pass checks."""

    def __init__(
        self,
        input_root: Path,
        output_root: Path,
        leak_scanner: SensitiveDataLeakScanner,
        *,
        secret: str | bytes,
    ) -> None:
        self.input_root = input_root
        self.output_root = output_root
        self._scanner = leak_scanner
        if not isinstance(secret, (str, bytes)) or not secret:
            raise ProcessingError("secret_missing")
        self._path_key = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._claimed_paths: set[str] = set()
        self._directory_prefixes: dict[str, bytes] = {}

    def write_file(
        self,
        source: InputFileMetadata,
        records: Sequence[ReleaseRecord],
    ) -> FileWriteResult:
        quarantined = tuple(
            item
            for item in records
            if item.result.status is ProcessingStatus.QUARANTINED
        )
        if quarantined and not any(
            item.result.status is ProcessingStatus.SANITIZED
            for item in records
        ):
            reason = next(
                item.result.error_code
                for item in quarantined
            )
            return self._quarantine(source, reason or "internal_error", len(records))

        sanitized = [
            item for item in records
            if item.result.status is ProcessingStatus.SANITIZED
        ]
        if records and not sanitized:
            return FileWriteResult(
                OutputManifestEntry(
                    source.sha256, None, ProcessingStatus.SUPPRESSED
                )
            )

        try:
            output_path = self._output_path(source)
            content, entries = self._serialize(source, records, output_path)
            if not self._scanner.scan_artifact_text(
                content,
                filename=output_path,
                sensitive_values=tuple(
                    value
                    for item in records
                    for value in item.sensitive_values
                ),
                allow_cohort_quasi_identifiers=all(
                    item.result.status is not ProcessingStatus.SANITIZED
                    or (
                        item.result.generalized
                        and item.result.risk_assessment is not None
                    )
                    for item in records
                ),
            ) or not all(self._scanner.scan_value(entry) for entry in entries):
                return self._quarantine(source, "leak_scan_failed", len(records))
            destination = self._destination(output_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._assert_no_symlink(destination)
            created = False
            try:
                with destination.open(
                    "x", encoding="utf-8", newline=""
                ) as stream:
                    created = True
                    stream.write(content)
            except OSError:
                if created and destination.is_file() and not destination.is_symlink():
                    destination.unlink(missing_ok=True)
                raise
        except ProcessingError as error:
            return self._quarantine(source, error.code, len(records))
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError, csv.Error):
            return self._quarantine(source, "internal_error", len(records))

        return FileWriteResult(
            OutputManifestEntry(
                source.sha256, output_path, ProcessingStatus.SANITIZED
            ),
            tuple(entries),
            records_quarantined=len(quarantined),
        )

    def _output_path(self, source: InputFileMetadata) -> str:
        extension = _OUTPUT_EXTENSIONS.get(source.detected_format)
        if extension is None:
            raise ProcessingError("unsupported_format")
        parts = source.relative_path.split("/")
        if "\\" in source.relative_path or any(
            part in {"", ".", ".."} for part in parts
        ):
            raise ProcessingError("input_path_invalid")
        derived = ["sanitized"]
        for depth in range(1, len(parts)):
            digest = self._path_digest(b"directory", "/".join(parts[:depth]))
            derived.append("d_" + digest[:16].hex().translate(_PATH_TOKEN_ALPHABET))
            directory = "/".join(derived)
            if self._directory_prefixes.setdefault(directory, digest) != digest:
                raise ProcessingError("filesystem_error")
        digest = self._path_digest(b"file", source.relative_path)
        derived.append("f_" + digest[:16].hex().translate(_PATH_TOKEN_ALPHABET) + extension)
        candidate = "/".join(derived)
        if candidate in self._claimed_paths:
            raise ProcessingError("filesystem_error")
        self._claimed_paths.add(candidate)
        return candidate

    def _path_digest(self, component: bytes, relative_path: str) -> bytes:
        return hmac.digest(
            self._path_key,
            b"lumen-ex/output-path/v1\0" + component + b"\0" + relative_path.encode("utf-8"),
            "sha256",
        )

    def _serialize(
        self,
        source: InputFileMetadata,
        records: Sequence[ReleaseRecord],
        output_path: str,
    ) -> tuple[str, list[dict[str, object]]]:
        path = self.input_root.joinpath(*source.relative_path.replace("\\", "/").split("/"))
        if path.is_symlink():
            raise ProcessingError("unsafe_symlink")
        try:
            path.resolve(strict=True).relative_to(
                self.input_root.resolve(strict=True)
            )
        except (OSError, ValueError):
            raise ProcessingError("unsafe_symlink") from None
        raw = path.read_bytes()
        if (
            len(raw) != source.size_bytes
            or hashlib.sha256(raw).hexdigest() != source.sha256
        ):
            raise ProcessingError("source_changed")
        try:
            text = raw.decode(source.encoding or "utf-8-sig")
        except UnicodeError:
            raise ProcessingError("undecodable_text") from None

        extension = _OUTPUT_EXTENSIONS.get(source.detected_format)
        if extension in {".csv", ".tsv"}:
            return self._serialize_delimited(
                records, output_path, text, "\t" if extension == ".tsv" else ","
            )
        if extension == ".txt":
            return self._serialize_text(records, output_path)
        if extension == ".json":
            return self._serialize_json(source, records, output_path, text)
        raise ProcessingError("unsupported_format")

    def _serialize_delimited(
        self,
        records: Sequence[ReleaseRecord],
        output_path: str,
        text: str,
        delimiter: str,
    ) -> tuple[str, list[dict[str, object]]]:
        original_rows = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        headers = next(original_rows, None)
        if not headers:
            raise ProcessingError("empty_file")
        if len(set(headers)) != len(headers):
            raise ProcessingError("format_mismatch")
        output_headers = _merge_output_headers(headers, records)
        if any(not isinstance(header, str) for header in output_headers):
            raise ProcessingError("invalid_record")
        if len(set(output_headers)) != len(output_headers):
            raise ProcessingError("format_mismatch")

        stream = io.StringIO(newline="")
        writer = csv.writer(stream, delimiter=delimiter, lineterminator="\n")
        writer.writerow(output_headers)
        entries: list[dict[str, object]] = []
        output_row = 0
        for item in records:
            if item.result.status in {
                ProcessingStatus.SUPPRESSED,
                ProcessingStatus.QUARANTINED,
            }:
                continue
            fields = copy.deepcopy(item.result.output_fields)
            patient = _inject_patient_reference(item, fields)
            output_keys = list(fields)
            original_keys = list(item.normalized.fields)
            if len(output_keys) != len(original_keys) or len(output_keys) < len(headers):
                raise ProcessingError("invalid_record")
            row = [fields[output_keys[index]] for index in range(len(headers))]
            overflow = fields.get("None")
            if isinstance(overflow, list):
                row.extend(overflow)
            if len(row) != len(output_headers) and not isinstance(overflow, list):
                raise ProcessingError("invalid_record")
            writer.writerow(row)
            input_locator = item.parsed.locator
            output_locator = f"row:{output_row}"
            entries.append(
                _record_entry(
                    output_path, input_locator, output_locator, patient
                )
            )
            output_row += 1
        return stream.getvalue(), entries

    def _serialize_text(
        self, records: Sequence[ReleaseRecord], output_path: str
    ) -> tuple[str, list[dict[str, object]]]:
        if len(records) != 1 or records[0].result.status is ProcessingStatus.SUPPRESSED:
            raise ProcessingError("invalid_record")
        item = records[0]
        fields = copy.deepcopy(item.result.output_fields)
        text = fields.get("text")
        if not isinstance(text, str):
            raise ProcessingError("invalid_record")
        patient = item.result.patient_pseudonym
        if patient is not None:
            text = f"Patient: {patient}\n{text}"
        return text, [
            _record_entry(output_path, item.parsed.locator, item.parsed.locator, patient)
        ]

    def _serialize_json(
        self,
        source: InputFileMetadata,
        records: Sequence[ReleaseRecord],
        output_path: str,
        text: str,
    ) -> tuple[str, list[dict[str, object]]]:
        try:
            document = json.loads(
                text,
                object_pairs_hook=_unique_json_object,
                parse_float=Decimal,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, RecursionError):
            raise ProcessingError("JSONDecodeError") from None
        except ValueError:
            raise ProcessingError("format_mismatch") from None
        if isinstance(document, dict):
            _redact_export_source_paths(document)
        if source.detected_format is InputFormat.FHIR:
            validate_fhir_document(document)
        entries: list[dict[str, object]] = []
        if not records:
            return _json_dumps(document) + "\n", entries

        if len(records) == 1 and records[0].parsed.locator == "doc":
            item = records[0]
            if item.result.status is ProcessingStatus.SUPPRESSED:
                raise ProcessingError("invalid_record")
            replacement = copy.deepcopy(item.result.output_fields)
            patient = _inject_patient_reference(item, replacement)
            document = replacement
            if isinstance(document, dict):
                _redact_export_source_paths(document)
            if source.detected_format is InputFormat.FHIR:
                validate_fhir_document(document)
            entries.append(
                _record_entry(output_path, "doc", "doc", patient)
            )
            return _json_dumps(document) + "\n", entries

        pointers: list[tuple[tuple[str, ...], ReleaseRecord, object, str | None]] = []
        envelope_owners: set[tuple[str | int, ...]] = set()
        for item in records:
            for owner, context in item.parsed.identity_context:
                if owner not in envelope_owners:
                    envelope_owners.add(owner)
                    envelope = _get_pointer(document, tuple(map(str, owner)))
                    _remove_envelope_identity(envelope, context)
            segments = _parse_pointer(item.parsed.locator)
            _get_pointer(document, segments)
            replacement: object = None
            patient: str | None = None
            if item.result.status is ProcessingStatus.SANITIZED:
                replacement = copy.deepcopy(item.result.output_fields)
                patient = _inject_patient_reference(item, replacement)
            pointers.append((segments, item, replacement, patient))

        output_locators: dict[str, str] = {}
        for segments, item, _, _ in pointers:
            parent = segments[:-1]
            index = _array_index(segments[-1])
            removed_before = sum(
                1
                for other_segments, other, _, _ in pointers
                if other.result.status
                in {
                    ProcessingStatus.SUPPRESSED,
                    ProcessingStatus.QUARANTINED,
                }
                and other_segments[:-1] == parent
                and _array_index(other_segments[-1]) < index
            )
            output_segments = (*parent, str(index - removed_before))
            output_locators[item.parsed.locator] = _format_pointer(output_segments)

        for segments, item, replacement, _ in sorted(
            pointers,
            key=lambda record: tuple(
                (0, int(segment)) if segment.isdecimal() else (1, segment)
                for segment in record[0]
            ),
            reverse=True,
        ):
            if item.result.status in {
                ProcessingStatus.SUPPRESSED,
                ProcessingStatus.QUARANTINED,
            }:
                _remove_pointer(document, segments)
            elif item.result.status is ProcessingStatus.SANITIZED:
                _set_pointer(document, segments, replacement)

        for _, item, _, patient in pointers:
            if item.result.status is ProcessingStatus.SANITIZED:
                entries.append(
                    _record_entry(
                        output_path,
                        item.parsed.locator,
                        output_locators[item.parsed.locator],
                        patient,
                    )
                )
        return _json_dumps(document) + "\n", entries

    def _destination(self, output_path: str) -> Path:
        destination = self.output_root.joinpath(*output_path.split("/"))
        try:
            destination.resolve().relative_to(self.output_root.resolve())
        except (OSError, ValueError):
            raise ProcessingError("invalid_record") from None
        return destination

    @staticmethod
    def _assert_no_symlink(destination: Path) -> None:
        current = destination
        while current != current.parent:
            if current.is_symlink():
                raise ProcessingError("unsafe_symlink")
            current = current.parent

    @staticmethod
    def _quarantine(
        source: InputFileMetadata, reason: str, record_count: int
    ) -> FileWriteResult:
        return FileWriteResult(
            OutputManifestEntry(
                source.sha256,
                None,
                ProcessingStatus.QUARANTINED,
                reason if reason in SAFE_ERROR_CODES else "internal_error",
            ),
            records_quarantined=record_count,
        )


class OutputContractValidator:
    """Check manifest counts, safe paths, and record-to-artifact pseudonym consistency."""

    def validate(
        self,
        output_root: Path,
        manifest: Sequence[OutputManifestEntry],
        records: Sequence[dict[str, object]],
        report: Mapping[str, object],
    ) -> None:
        if report.get("schema") != "raksha-report/1":
            raise ProcessingError("invalid_record")
        counts = report.get("counts")
        if not isinstance(counts, Mapping):
            raise ProcessingError("invalid_record")
        if counts.get("files_total") != len(manifest):
            raise ProcessingError("invalid_record")
        if counts.get("files_sanitized") != sum(
            entry.status is ProcessingStatus.SANITIZED for entry in manifest
        ):
            raise ProcessingError("invalid_record")
        if counts.get("files_quarantined") != sum(
            entry.status is ProcessingStatus.QUARANTINED for entry in manifest
        ):
            raise ProcessingError("invalid_record")
        if counts.get("records_processed") != len(records):
            raise ProcessingError("invalid_record")
        if counts.get("records_linked") != sum(record.get("patient") is not None for record in records):
            raise ProcessingError("invalid_record")

        exported = {
            entry.output
            for entry in manifest
            if entry.status is ProcessingStatus.SANITIZED
        }
        seen_records: set[tuple[str, str]] = set()
        for record in records:
            output = record.get("file")
            if not isinstance(output, str) or output not in exported:
                raise ProcessingError("invalid_record")
            locator = record.get("loc")
            if (
                not isinstance(locator, str)
                or not locator
                or "patient" not in record
                or record["patient"] is not None
                and not isinstance(record["patient"], str)
            ):
                raise ProcessingError("invalid_record")
            record_key = (output, locator)
            if record_key in seen_records:
                raise ProcessingError("invalid_record")
            seen_records.add(record_key)
            path = output_root.joinpath(*output.split("/"))
            if path.is_symlink() or not path.is_file():
                raise ProcessingError("invalid_record")
            try:
                path.resolve().relative_to(output_root.resolve())
            except (OSError, ValueError):
                raise ProcessingError("invalid_record") from None
            patient = record.get("patient")
            if patient is not None and (
                not isinstance(patient, str)
                or not _record_contains_patient(path, record, patient)
            ):
                raise ProcessingError("invalid_record")


def _record_entry(
    output_path: str, input_locator: str, output_locator: str, patient: str | None
) -> dict[str, object]:
    entry: dict[str, object] = {
        "file": output_path,
        "loc": input_locator,
        "patient": patient,
    }
    if output_locator != input_locator:
        entry["out"] = output_locator
    return entry


def _inject_patient_reference(item: ReleaseRecord, fields: object) -> str | None:
    patient = item.result.patient_pseudonym
    if patient is None:
        return None
    normalized_fields = getattr(item.normalized, "fields", None)
    identities = getattr(item.normalized, "identities", ())
    if not isinstance(normalized_fields, Mapping) or len(identities) != 1:
        return None
    identity = identities[0]
    for field_name in (
        "government_identifier",
        "insurance_identifier",
        "hospital_identifier",
        "phone",
        "email",
        "name",
        "relative_name",
    ):
        if field_name in identity.inherited_fields:
            continue
        for value in getattr(identity, field_name, ()):
            segments = _identity_path(value.source_key)
            if (
                item.parsed.source.detected_format is InputFormat.FHIR
                and len(identities) == 1
            ):
                patient_locator = getattr(identity, "record_locator", "")
                if isinstance(patient_locator, str) and patient_locator.startswith("/"):
                    segments = (*_parse_pointer(patient_locator), *segments)
            if segments and _set_corresponding_value(
                normalized_fields, fields, segments, patient
            ):
                return patient
    if (
        identity.inherited_fields
        and isinstance(fields, dict)
        and "patient_ref" not in normalized_fields
    ):
        fields["patient_ref"] = patient
        return patient
    return None


def _identity_path(source_key: str) -> tuple[str, ...]:
    if not source_key or source_key == "name_parts":
        return ()
    delimiter = "/" if "/" in source_key else "."
    return tuple(part for part in source_key.split(delimiter) if part)


def _set_corresponding_value(
    original: object, transformed: object, segments: tuple[str, ...], value: str
) -> bool:
    if not segments:
        return False
    if isinstance(original, Mapping) and isinstance(transformed, dict):
        key: object | None = None
        remaining = segments
        if ".".join(segments) in original:
            key = ".".join(segments)
            remaining = ()
        elif segments[0] in original:
            key = segments[0]
            remaining = segments[1:]
        if key is None:
            return False
        original_keys = list(original)
        transformed_keys = list(transformed)
        try:
            transformed_key = transformed_keys[original_keys.index(key)]
        except (ValueError, IndexError):
            return False
        if not remaining:
            if isinstance(original[key], str) and isinstance(transformed.get(transformed_key), str):
                transformed[transformed_key] = value
                return True
            return False
        return _set_corresponding_value(
            original[key], transformed.get(transformed_key), remaining, value
        )
    if isinstance(original, list) and isinstance(transformed, list):
        try:
            index = int(segments[0])
        except ValueError:
            return False
        if index < 0 or index >= len(original) or index >= len(transformed):
            return False
        if len(segments) == 1:
            if isinstance(original[index], str) and isinstance(transformed[index], str):
                transformed[index] = value
                return True
            return False
        return _set_corresponding_value(
            original[index], transformed[index], segments[1:], value
        )
    return False


def _remove_envelope_identity(
    envelope: object,
    context: Mapping[str, object],
    path: tuple[str, ...] = (),
) -> None:
    if not isinstance(envelope, dict):
        raise ProcessingError("format_mismatch")
    for key, value in context.items():
        child_path = (*path, key)
        if isinstance(value, Mapping):
            _remove_envelope_identity(envelope.get(key), value, child_path)
        elif is_json_envelope_identity(child_path):
            envelope.pop(key, None)


def _parse_pointer(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise ProcessingError("invalid_record")
    return tuple(
        segment.replace("~1", "/").replace("~0", "~")
        for segment in pointer[1:].split("/")
    )


def _format_pointer(segments: Sequence[str]) -> str:
    return "/" + "/".join(
        segment.replace("~", "~0").replace("/", "~1") for segment in segments
    )


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _merge_output_headers(
    original_headers: list[str], records: Sequence[ReleaseRecord]
) -> list[str]:
    candidates: list[list[str]] = []
    for item in records:
        headers = item.result.output_structure.get("headers")
        if headers is None:
            continue
        if (
            not isinstance(headers, (list, tuple))
            or len(headers) != len(original_headers)
            or any(not isinstance(header, str) for header in headers)
        ):
            raise ProcessingError("format_mismatch")
        candidates.append(list(headers))

    merged = list(original_headers)
    for index, original in enumerate(original_headers):
        replacements = {
            headers[index]
            for headers in candidates
            if headers[index] != original
        }
        if len(replacements) > 1:
            raise ProcessingError("format_mismatch")
        if replacements:
            merged[index] = replacements.pop()
        if _contains_unlabeled_identifier(original):
            merged[index] = f"field_{index + 1}"
    return [
        header
        if not _is_ambiguous_single_word_header(header)
        else f"field_{index + 1}"
        for index, header in enumerate(merged)
    ]


def _contains_unlabeled_identifier(value: str) -> bool:
    return any(
        any(character.isalpha() for character in match.group())
        and any(character.isdigit() for character in match.group())
        for match in _HEADER_IDENTIFIER.finditer(value)
    )


def _is_ambiguous_single_word_header(value: str) -> bool:
    words = re.findall(r"[^\W_]+", value, re.UNICODE)
    if len(words) != 1:
        return False
    normalized = "".join(
        character for character in value.casefold() if character.isalnum()
    )
    return normalized not in _SAFE_HEADER_NAMES


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid_json_number:{value}")


def _redact_export_source_paths(document: dict[str, object]) -> None:
    """Remove raw filesystem provenance retained around arrays of records."""
    for key, metadata in document.items():
        if _compact_export_key(key) not in {"metadata", "exportmetadata", "exportmeta"}:
            continue
        if not isinstance(metadata, dict):
            continue
        for field, value in metadata.items():
            if (
                isinstance(value, str)
                and _compact_export_key(field) in {"sourcepath", "sourcefilepath"}
            ):
                metadata[field] = "[REDACTED]"


def _compact_export_key(key: str) -> str:
    return "".join(character for character in key.casefold() if character.isalnum())


def _json_dumps(value: object, indent: int = 2) -> str:
    def encode(current: object, depth: int) -> str:
        if current is None:
            return "null"
        if current is True:
            return "true"
        if current is False:
            return "false"
        if isinstance(current, str):
            return json.dumps(current, ensure_ascii=False)
        if isinstance(current, int):
            return str(current)
        if isinstance(current, Decimal):
            if not current.is_finite():
                raise ValueError("invalid_json_number")
            return str(current)
        if isinstance(current, float):
            return json.dumps(current, allow_nan=False)
        if isinstance(current, Mapping):
            if not all(isinstance(key, str) for key in current):
                raise TypeError("json_object_key_invalid")
            if not current:
                return "{}"
            prefix = " " * (indent * (depth + 1))
            closing = " " * (indent * depth)
            items = (
                prefix
                + json.dumps(key, ensure_ascii=False)
                + ": "
                + encode(child, depth + 1)
                for key, child in current.items()
            )
            return "{\n" + ",\n".join(items) + "\n" + closing + "}"
        if isinstance(current, (list, tuple)):
            if not current:
                return "[]"
            prefix = " " * (indent * (depth + 1))
            closing = " " * (indent * depth)
            items = (
                prefix + encode(child, depth + 1)
                for child in current
            )
            return "[\n" + ",\n".join(items) + "\n" + closing + "]"
        raise TypeError("json_value_invalid")

    return encode(value, 0)


def _array_index(segment: str) -> int:
    if not segment.isdecimal():
        raise ProcessingError("invalid_record")
    return int(segment)


def _get_pointer(document: object, segments: Sequence[str]) -> object:
    current = document
    for segment in segments:
        if isinstance(current, list):
            index = _array_index(segment)
            if index >= len(current):
                raise ProcessingError("invalid_record")
            current = current[index]
        elif isinstance(current, Mapping) and segment in current:
            current = current[segment]
        else:
            raise ProcessingError("invalid_record")
    return current


def _set_pointer(document: object, segments: Sequence[str], value: object) -> None:
    if not segments:
        raise ProcessingError("invalid_record")
    parent = _get_pointer(document, segments[:-1])
    segment = segments[-1]
    if isinstance(parent, list):
        index = _array_index(segment)
        if index >= len(parent):
            raise ProcessingError("invalid_record")
        parent[index] = value
    elif isinstance(parent, dict) and segment in parent:
        parent[segment] = value
    else:
        raise ProcessingError("invalid_record")


def _remove_pointer(document: object, segments: Sequence[str]) -> None:
    if not segments:
        raise ProcessingError("invalid_record")
    parent = _get_pointer(document, segments[:-1])
    segment = segments[-1]
    if isinstance(parent, list):
        index = _array_index(segment)
        if index >= len(parent):
            raise ProcessingError("invalid_record")
        del parent[index]
    elif isinstance(parent, dict) and segment in parent:
        del parent[segment]
    else:
        raise ProcessingError("invalid_record")


def _record_contains_patient(path: Path, record: Mapping[str, object], patient: str) -> bool:
    locator = record.get("out", record.get("loc"))
    suffix = path.suffix.casefold()
    try:
        if suffix in {".csv", ".tsv"}:
            with path.open("r", encoding="utf-8", newline="") as stream:
                rows = csv.reader(stream, delimiter="\t" if suffix == ".tsv" else ",")
                next(rows, None)
                if not isinstance(locator, str) or not locator.startswith("row:"):
                    return False
                index = int(locator[4:])
                for row_index, row in enumerate(rows):
                    if row_index == index:
                        return patient in row
            return False
        content = path.read_text(encoding="utf-8")
        if suffix != ".json":
            return locator == "doc" and patient in content
        document = json.loads(content)
        if locator == "doc":
            return _contains_value(document, patient)
        if not isinstance(locator, str):
            return False
        return _contains_value(_get_pointer(document, _parse_pointer(locator)), patient)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, ProcessingError):
        return False


def _contains_value(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, Mapping):
        return any(_contains_value(child, expected) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_value(child, expected) for child in value)
    return False
