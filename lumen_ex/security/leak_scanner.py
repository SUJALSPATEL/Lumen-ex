"""PII-aware scanning for results, metadata, logs, and on-disk artifacts."""

import csv
import io
import json
import os
from pathlib import Path
import re
import sqlite3

from lumen_ex.contracts.models import (
    DetectionResult,
    DetectionEntityType,
    InputFileMetadata,
    NormalizedRecord,
    ProcessingStatus,
    SanitizationResult,
)
from lumen_ex.detection.pii import MultilingualPIIDetector
from lumen_ex.errors import ProcessingError


_MAX_SCAN_BYTES = 64 * 1024 * 1024
_MAX_STRUCTURED_BYTES = 4 * 1024 * 1024
_MAX_STRUCTURED_ITEMS = 100_000
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SHA256_VALUE = re.compile(r"^[0-9a-fA-F]{64}$")
_JSON_SHA256_FIELD = re.compile(
    r'("(?:input_)?sha256"\s*:\s*")[0-9a-fA-F]{64}(")',
    re.IGNORECASE,
)
_RELEASE_PLACEHOLDER = re.compile(r"\[(?:REDACTED|LOCATION|DATE REDACTED)\]")
_RELEASE_PSEUDONYM = re.compile(r"PSN-[0-9A-HJKMNP-TV-Z]{16}")
_ENTITY_COUNT_NAMES = frozenset(item.value for item in DetectionEntityType)
_COHORT_QUASI_IDENTIFIER_TYPES = frozenset(
    {DetectionEntityType.DATE_OF_BIRTH, DetectionEntityType.GENDER}
)


class SensitiveDataLeakScanner:
    """Fail-closed scanner with optional synthetic or runtime canaries."""

    def __init__(
        self,
        *,
        canaries: tuple[str, ...] = (),
        max_file_bytes: int = _MAX_SCAN_BYTES,
    ) -> None:
        if (
            isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or max_file_bytes < 1
        ):
            raise ValueError("leak_scan_policy_invalid")
        if any(not isinstance(value, str) for value in canaries):
            raise ValueError("leak_scan_policy_invalid")
        self._detector = MultilingualPIIDetector()
        self._canaries = tuple(
            value.casefold() for value in canaries if len(value) >= 4
        )
        self.max_file_bytes = max_file_bytes

    def __repr__(self) -> str:
        return "SensitiveDataLeakScanner()"

    def clear_canaries(self) -> None:
        self._canaries = ()

    def is_safe(
        self,
        result: SanitizationResult,
        *,
        sensitive_values: tuple[str, ...] = (),
    ) -> bool:
        allow_cohort_quasi_identifiers = (
            result.status is ProcessingStatus.SANITIZED
            and result.generalized
            and result.risk_assessment is not None
        )
        values = {
            "fields": result.output_fields,
            "output_relative_path": result.output_relative_path,
            "pseudonym": result.patient_pseudonym,
            "error_code": result.error_code,
            "locator": result.locator,
        }
        if not self.scan_value(
            values,
            sensitive_values=sensitive_values,
            allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
        ):
            return False
        structure = result.output_structure
        if isinstance(structure, dict) and isinstance(
            structure.get("headers"), (list, tuple)
        ):
            header_values = structure["headers"]
            if not all(isinstance(header, str) for header in header_values):
                return False
            other_structure = {
                key: value for key, value in structure.items() if key != "headers"
            }
            if not self.scan_value(
                other_structure,
                headers=tuple(header_values),
                sensitive_values=sensitive_values,
                allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
            ):
                return False
        elif not self.scan_value(
            {"structure": structure},
            sensitive_values=sensitive_values,
            allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
        ):
            return False
        if result.output_relative_path and not self.scan_text(
            result.output_relative_path,
            sensitive_values=sensitive_values,
        ):
            return False
        return True

    def scan_text(
        self,
        text: str,
        *,
        filename: str | None = None,
        sensitive_values: tuple[str, ...] = (),
        allow_cohort_quasi_identifiers: bool = False,
    ) -> bool:
        if not isinstance(text, str):
            return False
        if not self._fits_utf8_limit(text, self.max_file_bytes):
            return False
        canaries = self._sensitive_canaries(sensitive_values)
        if self._contains_canary(text, canaries):
            return False
        if filename is not None and self._contains_canary(filename, canaries):
            return False
        result = self._detect(
            {
                "text": _RELEASE_PSEUDONYM.sub(
                    "; ", _RELEASE_PLACEHOLDER.sub("; ", text)
                )
            },
            headers=(),
            allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
        )
        if result.identifier_count:
            return False
        if filename is not None and self._detect({"filename": filename}).identifier_count:
            return False
        return True

    def scan_value(
        self,
        value: object,
        *,
        headers: tuple[str, ...] = (),
        filename: str | None = None,
        sensitive_values: tuple[str, ...] = (),
        allow_cohort_quasi_identifiers: bool = False,
    ) -> bool:
        canaries = self._sensitive_canaries(sensitive_values)
        if self._contains_canary_value(value, canaries):
            return False
        if filename is not None and not self.scan_text("", filename=filename):
            return False
        fields = value if isinstance(value, dict) else {"value": value}
        fields_for_scan = self._mask_public_hashes(fields)
        if fields_for_scan is None:
            return False
        return self._detect(
            fields_for_scan,
            headers=headers,
            allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
        ).identifier_count == 0

    def scan_artifact_text(
        self,
        text: str,
        *,
        filename: str,
        sensitive_values: tuple[str, ...] = (),
        allow_cohort_quasi_identifiers: bool = False,
    ) -> bool:
        scan_text = _JSON_SHA256_FIELD.sub(r"\1[SHA256]\2", text)
        suffix = Path(filename).suffix.casefold()
        if suffix in {".json", ".jsonl", ".csv", ".tsv"}:
            if not isinstance(scan_text, str) or not self._fits_utf8_limit(
                scan_text, self.max_file_bytes
            ):
                return False
            canaries = self._sensitive_canaries(sensitive_values)
            if self._contains_canary(scan_text, canaries):
                return False
            if self._contains_canary(filename, canaries):
                return False
            if self._detect({"filename": filename}).identifier_count:
                return False
        elif not self.scan_text(
            scan_text,
            filename=filename,
            sensitive_values=sensitive_values,
            allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
        ):
            return False
        if suffix == ".json":
            if not self._fits_utf8_limit(text, _MAX_STRUCTURED_BYTES):
                return False
            try:
                payload = json.loads(text)
            except (json.JSONDecodeError, RecursionError):
                return False
            return self.scan_value(
                payload,
                filename=filename,
                sensitive_values=sensitive_values,
                allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
            )
        if suffix == ".jsonl":
            item_count = 0
            for line in text.splitlines():
                if not line.strip():
                    continue
                item_count += 1
                if item_count > _MAX_STRUCTURED_ITEMS or not self._fits_utf8_limit(
                    line, _MAX_STRUCTURED_BYTES
                ):
                    return False
                try:
                    payload = json.loads(line)
                except (json.JSONDecodeError, RecursionError):
                    return False
                if not self.scan_value(
                    payload,
                    filename=filename,
                    sensitive_values=sensitive_values,
                    allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
                ):
                    return False
            return True
        if suffix in {".csv", ".tsv"}:
            try:
                rows = csv.reader(
                    io.StringIO(text, newline=""),
                    delimiter="\t" if suffix == ".tsv" else ",",
                )
            except csv.Error:
                return False
            try:
                raw_headers = next(rows, None)
            except csv.Error:
                return False
            if raw_headers is None:
                return True
            headers = tuple(raw_headers)
            if len(headers) > _MAX_STRUCTURED_ITEMS:
                return False
            if not self.scan_value(
                {},
                headers=headers,
                filename=filename,
                sensitive_values=sensitive_values,
                allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
            ):
                return False
            item_count = len(headers)
            try:
                for row in rows:
                    item_count += len(row)
                    if (
                        item_count > _MAX_STRUCTURED_ITEMS
                        or len(row) != len(headers)
                    ):
                        return False
                    for header, cell in zip(headers, row):
                        if not self.scan_value(
                            {header: cell},
                            sensitive_values=sensitive_values,
                            allow_cohort_quasi_identifiers=allow_cohort_quasi_identifiers,
                        ):
                            return False
            except csv.Error:
                return False
            return True
        return True

    def scan_path(self, path: Path | str) -> bool:
        artifact = Path(path)
        if artifact.is_symlink():
            return False
        if not self.scan_text(artifact.name):
            return False
        try:
            if artifact.is_dir():
                return self.scan_tree(artifact)
            if not artifact.is_file():
                return False
            size = artifact.stat().st_size
            if size > self.max_file_bytes:
                return False
            content = artifact.read_bytes()
        except OSError:
            return False

        if content.startswith(_SQLITE_MAGIC):
            return self._scan_sqlite(artifact, content)
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return False
        return self.scan_artifact_text(text, filename=artifact.name)

    def scan_tree(self, root: Path | str) -> bool:
        directory = Path(root)
        if directory.is_symlink() or not directory.is_dir():
            return False
        if not self.scan_text(directory.name):
            return False
        try:
            for current, subdirectories, files in os.walk(
                directory,
                topdown=True,
                followlinks=False,
                onerror=self._raise_walk_error,
            ):
                current_path = Path(current)
                for name in subdirectories:
                    child = current_path / name
                    relative_path = child.relative_to(directory).as_posix()
                    if (
                        child.is_symlink()
                        or not self.scan_text(name)
                        or not self.scan_text(relative_path)
                    ):
                        return False
                for name in files:
                    child = current_path / name
                    relative_path = child.relative_to(directory).as_posix()
                    if (
                        child.is_symlink()
                        or not self.scan_text(relative_path)
                        or not self.scan_path(child)
                    ):
                        return False
        except OSError:
            return False
        return True

    def _detect(
        self,
        fields: dict[object, object],
        *,
        headers: tuple[str, ...] = (),
        allow_cohort_quasi_identifiers: bool = False,
    ) -> DetectionResult:
        metadata = InputFileMetadata(
            relative_path="security-scan/payload.txt",
            sha256="0" * 64,
            size_bytes=0,
        )
        record = NormalizedRecord(
            source=metadata,
            locator="scan",
            fields=fields,
            structure={"headers": list(headers)} if headers else {},
        )
        try:
            result = self._detector.detect(record)
        except ProcessingError:
            return DetectionResult(identifier_count=1)
        if not allow_cohort_quasi_identifiers or not result.findings:
            return result
        findings = tuple(
            finding
            for finding in result.findings
            if finding.entity_type not in _COHORT_QUASI_IDENTIFIER_TYPES
        )
        if len(findings) == len(result.findings):
            return result
        counts: dict[str, int] = {}
        for finding in findings:
            entity_type = finding.entity_type.value
            counts[entity_type] = counts.get(entity_type, 0) + 1
        return DetectionResult(
            identifier_count=len(findings),
            entity_counts=counts,
            findings=findings,
        )

    def _scan_sqlite(self, path: Path, content: bytes) -> bool:
        if self._contains_canary_bytes(content):
            return False
        uri = f"{path.resolve().as_uri()}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=1.0)
            try:
                connection.execute("PRAGMA query_only = ON")
                objects = connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                )
                for name, definition in objects:
                    if not self.scan_text(str(name)) or (
                        definition is not None
                        and not self.scan_text(str(definition))
                    ):
                        return False
                tables = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
                scanned_cells = 0
                for (table_name,) in tables:
                    if not self.scan_text(str(table_name)):
                        return False
                    escaped_name = str(table_name).replace('"', '""')
                    columns = connection.execute(
                        f'PRAGMA table_info("{escaped_name}")'
                    )
                    for column in columns:
                        if not self.scan_text(str(column[1])):
                            return False
                    rows = connection.execute(
                        f'SELECT * FROM "{escaped_name}"'
                    )
                    for row in rows:
                        for cell in row:
                            scanned_cells += 1
                            if scanned_cells > _MAX_STRUCTURED_ITEMS:
                                return False
                            if isinstance(cell, bytes):
                                if not self._scan_bytes(cell):
                                    return False
                            elif cell is not None and not self.scan_value(cell):
                                return False
            finally:
                connection.close()
        except sqlite3.Error:
            return False
        return True

    def _scan_bytes(self, content: bytes) -> bool:
        if self._contains_canary_bytes(content):
            return False
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            try:
                text = content.decode(encoding)
            except UnicodeDecodeError:
                continue
            if not self.scan_text(text):
                return False
        return True

    @staticmethod
    def _raise_walk_error(error: OSError) -> None:
        raise error

    def _sensitive_canaries(
        self, sensitive_values: tuple[str, ...]
    ) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                self._canaries
                + tuple(
                    value.casefold()
                    for value in sensitive_values
                    if isinstance(value, str) and len(value) >= 4
                )
            )
        )

    def _contains_canary(
        self, text: str, canaries: tuple[str, ...] | None = None
    ) -> bool:
        folded = text.casefold()
        return any(canary in folded for canary in (canaries or self._canaries))

    def _contains_canary_value(
        self,
        value: object,
        canaries: tuple[str, ...] | None = None,
    ) -> bool:
        pending = [value]
        visited: set[int] = set()
        item_count = 0
        while pending:
            item = pending.pop()
            item_count += 1
            if item_count > _MAX_STRUCTURED_ITEMS:
                return True
            if isinstance(item, str):
                if self._contains_canary(item, canaries):
                    return True
            elif isinstance(item, dict):
                identity = id(item)
                if identity in visited:
                    continue
                visited.add(identity)
                for key, child in item.items():
                    if self._contains_canary(str(key), canaries):
                        return True
                    pending.append(child)
            elif isinstance(item, (list, tuple)):
                identity = id(item)
                if identity in visited:
                    continue
                visited.add(identity)
                pending.extend(item)
        return False

    @staticmethod
    def _mask_public_hashes(
        fields: dict[object, object],
    ) -> dict[object, object] | None:
        root: dict[object, object] = {}
        pending: list[tuple[object, object]] = [(fields, root)]
        clones: dict[int, object] = {id(fields): root}
        visited: set[int] = set()
        item_count = 0
        while pending:
            source, target = pending.pop()
            source_id = id(source)
            if source_id in visited:
                continue
            visited.add(source_id)
            if isinstance(source, dict) and isinstance(target, dict):
                for key, value in source.items():
                    item_count += 1
                    if item_count > _MAX_STRUCTURED_ITEMS:
                        return None
                    safe_key = (
                        _RELEASE_PLACEHOLDER.sub("", key)
                        if isinstance(key, str)
                        else key
                    )
                    if (
                        isinstance(key, str)
                        and key.casefold() in {"sha256", "input_sha256"}
                        and isinstance(value, str)
                        and _SHA256_VALUE.fullmatch(value)
                    ):
                        target[safe_key] = "[SHA256]"
                    elif (
                        isinstance(key, str)
                        and key.casefold() == "entities"
                        and isinstance(value, dict)
                        and all(
                            isinstance(entity, str)
                            and entity in _ENTITY_COUNT_NAMES
                            and isinstance(count, int)
                            and not isinstance(count, bool)
                            and count >= 0
                            for entity, count in value.items()
                        )
                    ):
                        target[safe_key] = {
                            f"entity_{index}": count
                            for index, count in enumerate(value.values())
                        }
                    elif isinstance(value, dict):
                        child = clones.get(id(value))
                        if child is None:
                            child = {}
                            clones[id(value)] = child
                            pending.append((value, child))
                        target[safe_key] = child
                    elif isinstance(value, (list, tuple)):
                        child = clones.get(id(value))
                        if child is None:
                            child = []
                            clones[id(value)] = child
                            pending.append((value, child))
                        target[safe_key] = child
                    else:
                        target[safe_key] = _mask_release_tokens(value)
            elif isinstance(source, (list, tuple)) and isinstance(target, list):
                for value in source:
                    item_count += 1
                    if item_count > _MAX_STRUCTURED_ITEMS:
                        return None
                    if isinstance(value, (dict, list, tuple)):
                        child = clones.get(id(value))
                        if child is None:
                            child = {} if isinstance(value, dict) else []
                            clones[id(value)] = child
                            pending.append((value, child))
                        target.append(child)
                    else:
                        target.append(_mask_release_tokens(value))
        return root

    @staticmethod
    def _fits_utf8_limit(text: str, limit: int) -> bool:
        byte_count = 0
        for character in text:
            code_point = ord(character)
            if 0xD800 <= code_point <= 0xDFFF:
                return False
            if code_point <= 0x7F:
                byte_count += 1
            elif code_point <= 0x7FF:
                byte_count += 2
            elif code_point <= 0xFFFF:
                byte_count += 3
            else:
                byte_count += 4
            if byte_count > limit:
                return False
        return True

    def _contains_canary_bytes(self, content: bytes) -> bool:
        lowered = content.lower()
        return any(canary.encode("utf-8") in lowered for canary in self._canaries)


def _mask_release_tokens(value: object) -> object:
    if not isinstance(value, str):
        return value
    return _RELEASE_PSEUDONYM.sub(
        "; ", _RELEASE_PLACEHOLDER.sub("; ", value)
    )
