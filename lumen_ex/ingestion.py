"""Safe, deterministic discovery and streaming readers for supported source formats."""

from collections.abc import Generator, Iterator
from contextlib import contextmanager
import codecs
import csv
import hashlib
import io
import os
from dataclasses import dataclass, replace
from pathlib import Path

import ijson
from ijson.common import JSONError

from lumen_ex.contracts.models import (
    IngestionFileResult,
    IngestionResult,
    IngestionStatistics,
    IngestionStatus,
    InputFileMetadata,
    InputFormat,
    ParsedRecord,
)
from lumen_ex.errors import ProcessingError
from lumen_ex.identity import is_json_envelope_identity


_HASH_CHUNK_SIZE = 1024 * 1024
_MAX_JSON_DEPTH = 512
_JSON_RECORD_ARRAYS = frozenset(
    {"patients", "visits", "records", "items", "results", "data", "resources"}
)
_SUPPORTED_SUFFIXES = {
    ".csv": InputFormat.CSV,
    ".tsv": InputFormat.TSV,
    ".json": InputFormat.JSON,
    ".txt": InputFormat.TEXT,
}
_BINARY_SIGNATURES = (b"%PDF-", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"PK\x03\x04")
_FHIR_RESOURCE_TYPES = frozenset(
    """
    Account ActivityDefinition AdverseEvent AllergyIntolerance Appointment
    AppointmentResponse AuditEvent Basic Binary BiologicallyDerivedProduct
    BodyStructure Bundle CapabilityStatement CarePlan CareTeam CatalogEntry
    ChargeItem ChargeItemDefinition Claim ClaimResponse ClinicalImpression
    CodeSystem Communication CommunicationRequest CompartmentDefinition
    Composition ConceptMap Condition Consent Contract Coverage
    CoverageEligibilityRequest CoverageEligibilityResponse DetectedIssue Device
    DeviceDefinition DeviceMetric DeviceRequest DeviceUseStatement
    DiagnosticReport DocumentManifest DocumentReference EffectEvidenceSynthesis
    Encounter Endpoint EnrollmentRequest EnrollmentResponse EpisodeOfCare
    EventDefinition Evidence EvidenceVariable ExampleScenario
    ExplanationOfBenefit FamilyMemberHistory Flag Goal GraphDefinition Group
    GuidanceResponse HealthcareService ImagingStudy Immunization
    ImmunizationEvaluation ImmunizationRecommendation ImplementationGuide
    InsurancePlan Invoice Library Linkage List Location Measure MeasureReport
    Media Medication MedicationAdministration MedicationDispense
    MedicationKnowledge MedicationRequest MedicationStatement MedicinalProduct
    MedicinalProductAuthorization MedicinalProductContraindication
    MedicinalProductIndication MedicinalProductIngredient
    MedicinalProductInteraction MedicinalProductManufactured
    MedicinalProductPackaged MedicinalProductPharmaceutical
    MedicinalProductUndesirableEffect MessageDefinition MessageHeader
    MolecularSequence NamingSystem NutritionOrder Observation
    ObservationDefinition OperationDefinition OperationOutcome Organization
    OrganizationAffiliation Parameters Patient PaymentNotice
    PaymentReconciliation Person PlanDefinition Practitioner PractitionerRole
    Procedure Provenance Questionnaire QuestionnaireResponse RelatedPerson
    RequestGroup ResearchDefinition ResearchElementDefinition ResearchStudy
    ResearchSubject RiskAssessment RiskEvidenceSynthesis Schedule SearchParameter
    ServiceRequest Slot Specimen SpecimenDefinition StructureDefinition
    StructureMap Subscription Substance SubstanceNucleicAcid SubstancePolymer
    SubstanceProtein SubstanceReferenceInformation SubstanceSourceMaterial
    SubstanceSpecification SupplyDelivery SupplyRequest Task
    TerminologyCapabilities TestReport TestScript ValueSet VerificationResult
    VisionPrescription
    """.split()
)
_FHIR_BUNDLE_TYPES = frozenset(
    {
        "document",
        "message",
        "transaction",
        "transaction-response",
        "batch",
        "batch-response",
        "history",
        "searchset",
        "collection",
    }
)
_SCALAR_EVENTS = frozenset({"boolean", "null", "number", "string"})


class _Utf8ByteReader:
    """Expose decoded text as UTF-8 bytes for ijson's incremental parser."""

    def __init__(self, text_stream: io.TextIOBase) -> None:
        self._text_stream = text_stream

    def read(self, size: int = -1) -> bytes:
        return self._text_stream.read(size).encode("utf-8")


@dataclass
class _JSONFrame:
    kind: str
    path: tuple[str | int, ...]
    next_index: int = 0
    pending_key: str | None = None


@dataclass
class _CaptureFrame:
    kind: str
    value: object
    pending_key: str | None = None


class StreamingIngestor:
    """Prevalidate each file, quarantine failures, then stream usable records."""

    def __init__(self) -> None:
        self._input_root: Path | None = None

    def discover(self, input_root: Path) -> Iterator[InputFileMetadata]:
        root = self._set_input_root(input_root)
        return self._discover_from(root)

    def ingest(self, input_root: Path) -> IngestionResult:
        """Return per-file outcomes and a lazy iterator for records from safe files."""
        root = self._set_input_root(input_root)
        outcomes: list[IngestionFileResult] = []
        usable: list[tuple[InputFileMetadata, Path]] = []

        for relative_path, path, error_code in _walk_candidates(root):
            source: InputFileMetadata | None = None
            if error_code is not None:
                outcomes.append(
                    IngestionFileResult(
                        relative_path=relative_path,
                        source=None,
                        status=IngestionStatus.QUARANTINED,
                        error_code=error_code,
                    )
                )
                continue
            try:
                assert path is not None
                source = _file_metadata(path, relative_path)
                source, record_count = _prepare_file(source, path)
                outcomes.append(
                    IngestionFileResult(
                        relative_path=relative_path,
                        source=source,
                        status=IngestionStatus.INGESTED,
                        record_count=record_count,
                    )
                )
                usable.append((source, path))
            except ProcessingError as error:
                outcomes.append(
                    IngestionFileResult(
                        relative_path=relative_path,
                        source=source,
                        status=IngestionStatus.QUARANTINED,
                        error_code=error.code,
                    )
                )
            except OSError:
                outcomes.append(
                    IngestionFileResult(
                        relative_path=relative_path,
                        source=source,
                        status=IngestionStatus.QUARANTINED,
                        error_code="filesystem_error",
                    )
                )

        outcomes.sort(key=lambda result: result.relative_path)
        statistics = IngestionStatistics(
            files_discovered=len(outcomes),
            files_ingested=sum(
                result.status is IngestionStatus.INGESTED for result in outcomes
            ),
            files_quarantined=sum(
                result.status is IngestionStatus.QUARANTINED for result in outcomes
            ),
            records_parsed=sum(result.record_count for result in outcomes),
            bytes_scanned=sum(
                result.source.size_bytes
                for result in outcomes
                if result.source is not None
            ),
        )
        return IngestionResult(
            files=tuple(outcomes),
            records=self._records_from(usable),
            statistics=statistics,
        )

    def read(self, source: InputFileMetadata) -> Iterator[ParsedRecord]:
        path = self._resolve_source(source)
        prepared_source, _ = _prepare_file(source, path)
        return self._records_from([(prepared_source, path)])

    def iter_batches(
        self, input_root: Path, batch_size: int = 1000
    ) -> Iterator[tuple[ParsedRecord, ...]]:
        """Yield bounded batches; use ingest() to inspect quarantined file outcomes."""
        if batch_size < 1:
            raise ValueError("batch_size_invalid")
        result = self.ingest(input_root)
        quarantined = next(
            (
                item
                for item in result.files
                if item.status is IngestionStatus.QUARANTINED
            ),
            None,
        )
        if quarantined is not None:
            raise ProcessingError(quarantined.error_code or "filesystem_error")

        batch: list[ParsedRecord] = []
        for record in result.records:
            batch.append(record)
            if len(batch) == batch_size:
                yield tuple(batch)
                batch.clear()
        if batch:
            yield tuple(batch)

    def _set_input_root(self, input_root: Path) -> Path:
        try:
            if input_root.is_symlink():
                raise ProcessingError("unsafe_symlink")
            root = input_root.resolve(strict=True)
        except ProcessingError:
            raise
        except OSError:
            raise ProcessingError("input_output_path_invalid") from None
        if not root.is_dir():
            raise ProcessingError("input_output_path_invalid")
        self._input_root = root
        return root

    def _discover_from(self, root: Path) -> Iterator[InputFileMetadata]:
        for relative_path, path, error_code in _walk_candidates(root):
            if error_code is not None:
                raise ProcessingError(error_code)
            assert path is not None
            yield _file_metadata(path, relative_path)

    def _resolve_source(self, source: InputFileMetadata) -> Path:
        if self._input_root is None:
            raise ProcessingError("invalid_record")
        path = self._input_root
        for part in Path(source.relative_path).parts:
            path = path / part
            if path.is_symlink():
                raise ProcessingError("unsafe_symlink")
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self._input_root)
        except (OSError, ValueError):
            raise ProcessingError("invalid_record") from None
        if not resolved.is_file():
            raise ProcessingError("unsupported_file_type")
        return resolved

    def _records_from(
        self, sources: list[tuple[InputFileMetadata, Path]]
    ) -> Iterator[ParsedRecord]:
        for source, path in sources:
            _verify_source(source, path)
            yield from _iter_records(source, path)


def _walk_candidates(root: Path) -> list[tuple[str, Path | None, str | None]]:
    candidates: list[tuple[str, Path | None, str | None]] = []

    def record_walk_error(error: OSError) -> None:
        filename = getattr(error, "filename", None)
        path = Path(filename) if filename else root
        try:
            relative_path = path.relative_to(root).as_posix()
        except ValueError:
            relative_path = "unreadable"
        if relative_path in ("", "."):
            relative_path = "unreadable"
        candidates.append((relative_path, None, "filesystem_error"))

    for directory, subdirectories, filenames in os.walk(
        root, followlinks=False, onerror=record_walk_error
    ):
        base = Path(directory)
        remaining_directories: list[str] = []
        for name in sorted(subdirectories):
            path = base / name
            relative_path = path.relative_to(root).as_posix()
            if path.is_symlink():
                candidates.append((relative_path, None, "unsafe_symlink"))
            else:
                remaining_directories.append(name)
        subdirectories[:] = remaining_directories

        for filename in sorted(filenames):
            path = base / filename
            relative_path = path.relative_to(root).as_posix()
            if path.is_symlink():
                candidates.append((relative_path, None, "unsafe_symlink"))
            elif not path.is_file():
                candidates.append((relative_path, None, "unsupported_file_type"))
            else:
                candidates.append((relative_path, path, None))
    candidates.sort(key=lambda item: item[0])
    return candidates


def _file_metadata(path: Path, relative_path: str) -> InputFileMetadata:
    try:
        stat = path.stat()
        digest = _sha256_file(path)
    except OSError:
        raise ProcessingError("filesystem_error") from None

    file_format = _format_for_suffix(path.suffix.casefold())
    encoding: str | None = None
    if file_format is not InputFormat.UNSUPPORTED:
        try:
            encoding = _detect_encoding(path)
        except ProcessingError as error:
            if error.code not in ("unsupported_format", "undecodable_text"):
                raise
        except OSError:
            raise ProcessingError("filesystem_error") from None

    return InputFileMetadata(
        relative_path=relative_path,
        sha256=digest,
        size_bytes=stat.st_size,
        media_type=_media_type(path.suffix.casefold()),
        detected_format=file_format,
        encoding=encoding,
    )


def _prepare_file(
    source: InputFileMetadata, path: Path
) -> tuple[InputFileMetadata, int]:
    if source.size_bytes == 0:
        raise ProcessingError("empty_file")
    file_format = _format_for_suffix(path.suffix.casefold())
    if file_format is InputFormat.UNSUPPORTED:
        raise ProcessingError("unsupported_format")

    encoding = source.encoding
    if encoding is None:
        encoding = _detect_encoding(path)
    prepared = replace(source, detected_format=file_format, encoding=encoding)
    _check_content_format(path, file_format, encoding)

    if file_format in (InputFormat.CSV, InputFormat.TSV):
        delimiter = "\t" if file_format is InputFormat.TSV else ","
        return prepared, _count_csv(path, encoding, delimiter)
    if file_format is InputFormat.JSON:
        try:
            root_type, arrays = _json_layout(path, encoding)
            if root_type is not None:
                if root_type not in _FHIR_RESOURCE_TYPES:
                    raise ProcessingError("invalid_fhir")
                document = _json_document(path, encoding)
                _validate_fhir(document)
                prepared = replace(
                    prepared,
                    detected_format=InputFormat.FHIR,
                    media_type="application/fhir+json",
                )
                return prepared, 1
            if arrays:
                return prepared, sum(
                    1
                    for array_path in arrays
                    for _ in _json_array_items(path, array_path, encoding)
                )
            _json_document(path, encoding)
            return prepared, 1
        except ProcessingError:
            raise
        except (JSONError, ValueError, UnicodeError):
            raise ProcessingError("JSONDecodeError") from None
    if _is_blank_text(path, encoding):
        raise ProcessingError("empty_file")
    return prepared, 1


def _check_content_format(
    path: Path, file_format: InputFormat, encoding: str
) -> None:
    try:
        with path.open("rb") as stream:
            prefix = stream.read(4096)
        if prefix.startswith(_BINARY_SIGNATURES):
            raise ProcessingError("unsupported_format")
        sample = prefix.decode(encoding, errors="ignore").lstrip("\ufeff \t\r\n")
    except UnicodeError:
        raise ProcessingError("undecodable_text") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None

    if file_format in (InputFormat.CSV, InputFormat.TSV) and sample.startswith(
        ("{", "[")
    ):
        raise ProcessingError("format_mismatch")
    if file_format is InputFormat.JSON and sample.startswith("<"):
        raise ProcessingError("format_mismatch")


def _count_csv(path: Path, encoding: str, delimiter: str) -> int:
    count = 0
    try:
        with _open_text(path, encoding) as text_stream:
            reader = csv.reader(text_stream, delimiter=delimiter, strict=True)
            headers = next(reader, None)
            if not headers:
                raise ProcessingError("empty_file")
            for cells in reader:
                if cells:
                    count += 1
    except ProcessingError:
        raise
    except csv.Error:
        raise ProcessingError("CSVError") from None
    except UnicodeError:
        raise ProcessingError("undecodable_text") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None
    return count


def _iter_records(
    source: InputFileMetadata, path: Path
) -> Iterator[ParsedRecord]:
    file_format = source.detected_format
    if file_format in (InputFormat.CSV, InputFormat.TSV):
        yield from _read_csv(
            source,
            path,
            "\t" if file_format is InputFormat.TSV else ",",
        )
    elif file_format in (InputFormat.JSON, InputFormat.FHIR):
        yield from _read_json(source, path)
    elif file_format is InputFormat.TEXT:
        yield from _read_text(source, path)
    else:
        raise ProcessingError("unsupported_format")


def _read_csv(
    source: InputFileMetadata, path: Path, delimiter: str
) -> Iterator[ParsedRecord]:
    if source.encoding is None:
        raise ProcessingError("undecodable_text")
    try:
        with _open_text(path, source.encoding) as text_stream:
            reader = csv.reader(text_stream, delimiter=delimiter, strict=True)
            headers = next(reader, None)
            if not headers:
                raise ProcessingError("empty_file")
            for index, cells in enumerate(row for row in reader if row):
                values: dict[object, object] = {
                    header: cells[column] if column < len(cells) else None
                    for column, header in enumerate(headers)
                }
                if len(cells) > len(headers):
                    values[None] = cells[len(headers) :]
                yield ParsedRecord(
                    source,
                    f"row:{index}",
                    values,
                    {"headers": tuple(headers), "cells": tuple(cells)},
                )
    except ProcessingError:
        raise
    except csv.Error:
        raise ProcessingError("CSVError") from None
    except UnicodeError:
        raise ProcessingError("undecodable_text") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None


def _read_json(source: InputFileMetadata, path: Path) -> Iterator[ParsedRecord]:
    if source.encoding is None:
        raise ProcessingError("undecodable_text")
    try:
        root_type, arrays = _json_layout(path, source.encoding)
        if root_type is not None:
            yield ParsedRecord(source, "doc", _json_document(path, source.encoding))
            return
        if arrays:
            contexts = _json_identity_contexts(path, source.encoding, arrays)
            for array_path in arrays:
                for index, value in enumerate(
                    _json_array_items(path, array_path, source.encoding)
                ):
                    yield ParsedRecord(
                        source,
                        _json_pointer((*array_path, index)),
                        value,
                        identity_context=contexts[array_path],
                    )
            return
        yield ParsedRecord(source, "doc", _json_document(path, source.encoding))
    except ProcessingError:
        raise
    except (JSONError, ValueError, UnicodeError):
        raise ProcessingError("JSONDecodeError") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None


def _json_identity_contexts(
    path: Path,
    encoding: str,
    arrays: tuple[tuple[str | int, ...], ...],
) -> dict[tuple[str | int, ...], tuple[tuple[tuple[str | int, ...], dict[str, object]], ...]]:
    # Only follow envelope paths to known patient record arrays. An enclosing
    # array item starts a new patient scope.
    eligible = {}
    for array in arrays:
        if not array or not isinstance(array[-1], str) or array[-1].casefold() not in {
            "items", "results", "visits",
        }:
            continue
        start = max(
            (
                index + 1
                for index, part in enumerate(array)
                if isinstance(part, int) and array[index - 1] != "panels"
            ),
            default=0,
        )
        eligible[array] = tuple(array[:length] for length in range(start, len(array)))
    if not eligible:
        return dict.fromkeys(arrays, ())
    owners = {owner for ancestors in eligible.values() for owner in ancestors}
    contexts: dict[tuple[str | int, ...], dict[str, object]] = {}
    for event_path, event, value in _walk_json_events(path, encoding):
        if event not in _SCALAR_EVENTS:
            continue
        for length in range(len(event_path)):
            owner = event_path[:length]
            if owner not in owners:
                continue
            tail = event_path[length:]
            first = tail[0]
            if not isinstance(first, str):
                continue
            if any(not isinstance(part, str) for part in tail):
                continue
            key = first.casefold().replace("_", "")
            patient_field = is_json_envelope_identity(tail)
            export_hospital = key == "exportmeta" and tail[1:] == ("hospital",)
            source_field = len(tail) == 1 and key in {
                "hospitalname", "hospitalcode", "hospitalnamespace", "sourcesystem",
                "sourcenamespace", "facilityid", "facilityname",
            }
            if not (patient_field or export_hospital or source_field):
                continue
            target = contexts.setdefault(owner, {})
            for part in tail[:-1]:
                target = target.setdefault(part, {})
                if not isinstance(target, dict):
                    break
            if isinstance(target, dict):
                target[tail[-1]] = value
    return {
        array: tuple(
            (owner, context)
            for owner in eligible.get(array, ())
            if (context := contexts.get(owner))
        )
        for array in arrays
    }


def _read_text(source: InputFileMetadata, path: Path) -> Iterator[ParsedRecord]:
    if source.encoding is None:
        raise ProcessingError("undecodable_text")
    try:
        with _open_text(path, source.encoding) as text_stream:
            yield ParsedRecord(source, "doc", {"text": text_stream.read()})
    except UnicodeError:
        raise ProcessingError("undecodable_text") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None


def _json_layout(
    path: Path, encoding: str
) -> tuple[str | None, tuple[tuple[str | int, ...], ...]]:
    root_type: str | None = None
    arrays: list[tuple[str | int, ...]] = []
    selected_arrays: list[tuple[str | int, ...]] = []
    for event_path, event, value in _walk_json_events(path, encoding):
        if event_path == ("resourceType",) and event == "string":
            root_type = value
        if event == "start_array":
            is_record_array = not event_path or (
                isinstance(event_path[-1], str)
                and event_path[-1].casefold() in _JSON_RECORD_ARRAYS
            )
            if not selected_arrays and is_record_array:
                arrays.append(event_path)
                selected_arrays.append(event_path)
        elif (
            event == "end_array"
            and selected_arrays
            and event_path == selected_arrays[-1]
        ):
            selected_arrays.pop()
    return root_type, tuple(arrays)


def _walk_json_events(
    path: Path, encoding: str
) -> Iterator[tuple[tuple[str | int, ...], str, object]]:
    frames: list[_JSONFrame] = []
    try:
        with _open_text(path, encoding) as text_stream:
            for _, event, value in ijson.parse(_Utf8ByteReader(text_stream)):
                if event == "map_key":
                    if not frames or frames[-1].kind != "map":
                        raise ValueError("json_structure_invalid")
                    frames[-1].pending_key = value
                    yield frames[-1].path, event, value
                    continue
                if event in ("end_map", "end_array"):
                    if not frames:
                        raise ValueError("json_structure_invalid")
                    frame = frames.pop()
                    if (event == "end_map") != (frame.kind == "map"):
                        raise ValueError("json_structure_invalid")
                    yield frame.path, event, value
                    continue

                event_path = _next_json_path(frames)
                yield event_path, event, value
                if event in ("start_map", "start_array"):
                    if len(frames) >= _MAX_JSON_DEPTH:
                        raise ProcessingError("json_depth_exceeded")
                    frames.append(
                        _JSONFrame(
                            kind="map" if event == "start_map" else "array",
                            path=event_path,
                        )
                    )
    except ProcessingError:
        raise
    except (JSONError, UnicodeError):
        raise


def _next_json_path(frames: list[_JSONFrame]) -> tuple[str | int, ...]:
    if not frames:
        return ()
    parent = frames[-1]
    if parent.kind == "map":
        if parent.pending_key is None:
            raise ValueError("json_structure_invalid")
        key = parent.pending_key
        parent.pending_key = None
        return (*parent.path, key)
    index = parent.next_index
    parent.next_index += 1
    return (*parent.path, index)


def _json_array_items(
    path: Path, array_path: tuple[str | int, ...], encoding: str
) -> Iterator[object]:
    inside_array = False
    capture: list[_CaptureFrame] = []
    captured_root: object = None

    for event_path, event, value in _walk_json_events(path, encoding):
        if event == "map_key":
            if capture and capture[-1].kind == "map":
                capture[-1].pending_key = str(value)
            continue
        if event == "start_array" and event_path == array_path:
            inside_array = True
            continue
        if event == "end_array" and event_path == array_path:
            inside_array = False
            continue

        if inside_array and not capture and len(event_path) == len(array_path) + 1:
            if event in ("start_map", "start_array"):
                captured_root = {} if event == "start_map" else []
                capture.append(
                    _CaptureFrame(
                        kind="map" if event == "start_map" else "array",
                        value=captured_root,
                    )
                )
            elif event in _SCALAR_EVENTS:
                yield value
            continue

        if not capture:
            continue
        if event in ("start_map", "start_array"):
            child: object = {} if event == "start_map" else []
            _attach_json_value(capture[-1], child)
            capture.append(
                _CaptureFrame(
                    kind="map" if event == "start_map" else "array",
                    value=child,
                )
            )
        elif event in _SCALAR_EVENTS:
            _attach_json_value(capture[-1], value)
        elif event in ("end_map", "end_array"):
            capture.pop()
            if not capture:
                yield captured_root


def _attach_json_value(frame: _CaptureFrame, value: object) -> None:
    if frame.kind == "array":
        assert isinstance(frame.value, list)
        frame.value.append(value)
        return
    if frame.pending_key is None:
        raise ValueError("json_structure_invalid")
    assert isinstance(frame.value, dict)
    frame.value[frame.pending_key] = value
    frame.pending_key = None


def _json_document(path: Path, encoding: str) -> object:
    with _open_text(path, encoding) as text_stream:
        documents = ijson.items(_Utf8ByteReader(text_stream), "")
        try:
            return next(documents)
        except StopIteration:
            raise ProcessingError("empty_file") from None


def _validate_fhir(document: object) -> None:
    if not isinstance(document, dict):
        raise ProcessingError("invalid_fhir")
    pending = [document]
    while pending:
        resource = pending.pop()
        if not isinstance(resource, dict):
            raise ProcessingError("invalid_fhir")
        resource_type = resource.get("resourceType")
        if resource_type not in _FHIR_RESOURCE_TYPES:
            raise ProcessingError("invalid_fhir")
        if resource_type != "Bundle":
            continue
        if resource.get("type") not in _FHIR_BUNDLE_TYPES:
            raise ProcessingError("invalid_fhir")
        entries = resource.get("entry", [])
        if not isinstance(entries, list):
            raise ProcessingError("invalid_fhir")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ProcessingError("invalid_fhir")
            nested = entry.get("resource")
            if nested is not None:
                pending.append(nested)


def validate_fhir_document(document: object) -> None:
    """Validate the supported FHIR resource and Bundle shape before release."""
    _validate_fhir(document)


def _json_pointer(path: tuple[str | int, ...]) -> str:
    return "/" + "/".join(
        str(segment).replace("~", "~0").replace("/", "~1") for segment in path
    )


def _is_blank_text(path: Path, encoding: str) -> bool:
    try:
        with _open_text(path, encoding) as text_stream:
            for chunk in iter(lambda: text_stream.read(_HASH_CHUNK_SIZE), ""):
                if any(not character.isspace() for character in chunk):
                    return False
    except UnicodeError:
        raise ProcessingError("undecodable_text") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None
    return True


def _verify_source(source: InputFileMetadata, path: Path) -> None:
    try:
        if (
            path.stat().st_size != source.size_bytes
            or _sha256_file(path) != source.sha256
        ):
            raise ProcessingError("source_changed")
    except ProcessingError:
        raise
    except OSError:
        raise ProcessingError("filesystem_error") from None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_for_suffix(suffix: str) -> InputFormat:
    return _SUPPORTED_SUFFIXES.get(suffix, InputFormat.UNSUPPORTED)


def _media_type(suffix: str) -> str:
    return {
        ".csv": "text/csv",
        ".tsv": "text/tab-separated-values",
        ".json": "application/json",
        ".txt": "text/plain",
    }.get(suffix, "application/octet-stream")


def _detect_encoding(path: Path) -> str:
    try:
        with path.open("rb") as binary:
            prefix = binary.read(8)
            if prefix.startswith(_BINARY_SIGNATURES):
                raise ProcessingError("unsupported_format")
            if prefix.startswith(codecs.BOM_UTF8):
                encoding = "utf-8-sig"
            elif prefix.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                encoding = "utf-16"
            elif b"\x00" in prefix:
                raise ProcessingError("unsupported_format")
            else:
                binary.seek(0)
                encoding = _detect_unmarked_encoding(binary)
        _validate_text_encoding(path, encoding)
        return encoding
    except ProcessingError:
        raise
    except OSError:
        raise ProcessingError("filesystem_error") from None


def _detect_unmarked_encoding(binary: io.BufferedReader) -> str:
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        for chunk in iter(lambda: binary.read(_HASH_CHUNK_SIZE), b""):
            decoder.decode(chunk)
        decoder.decode(b"", final=True)
        return "utf-8"
    except UnicodeDecodeError:
        return "cp1252"


def _validate_text_encoding(path: Path, encoding: str) -> None:
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    character_count = 0
    control_count = 0
    try:
        with path.open("rb") as binary:
            for chunk in iter(lambda: binary.read(_HASH_CHUNK_SIZE), b""):
                text = decoder.decode(chunk)
                character_count += len(text)
                control_count += sum(
                    ord(character) < 32
                    and character not in "\t\n\r\f"
                    or 127 <= ord(character) <= 159
                    for character in text
                )
            text = decoder.decode(b"", final=True)
            character_count += len(text)
            control_count += sum(
                ord(character) < 32
                and character not in "\t\n\r\f"
                or 127 <= ord(character) <= 159
                for character in text
            )
    except UnicodeError:
        raise ProcessingError("undecodable_text") from None
    except OSError:
        raise ProcessingError("filesystem_error") from None
    if character_count and control_count / character_count > 0.01:
        raise ProcessingError("unsupported_format")


@contextmanager
def _open_text(
    path: Path, encoding: str | None = None
) -> Generator[io.TextIOWrapper, None, None]:
    try:
        binary = path.open("rb")
    except OSError:
        raise ProcessingError("filesystem_error") from None
    with binary:
        selected_encoding = encoding or _detect_encoding(path)
        binary.seek(0)
        yield io.TextIOWrapper(binary, encoding=selected_encoding, newline="")


__all__ = ["StreamingIngestor"]
