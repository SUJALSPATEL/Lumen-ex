"""Cohort orchestration for producing a validated sanitized release."""

from collections import defaultdict
from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import platform
import time
from typing import Sequence

from lumen_ex.config import PipelineConfig
from lumen_ex.contracts.identity import IdentityDecision
from lumen_ex.contracts.models import (
    DetectionEntityType,
    DetectionResult,
    IngestionStatus,
    LinkageAction,
    LinkageDecision,
    NormalizedRecord,
    OutputManifestEntry,
    ParsedRecord,
    PipelineReport,
    ProcessingStatus,
    SanitizationResult,
)
from lumen_ex.detection import MultilingualPIIDetector
from lumen_ex.errors import ProcessingError
from lumen_ex.identity import PatientIdentityNormalizer
from lumen_ex.ingestion import StreamingIngestor
from lumen_ex.matching import IdentityMatcher
from lumen_ex.output import (
    FileWriteResult,
    OutputContractValidator,
    ReleaseRecord,
    SanitizedOutputWriter,
)
from lumen_ex.privacy import PrivacyInput, PrivacyTransformer
from lumen_ex.registry import EncryptedIdentityRegistry
from lumen_ex.security import SensitiveDataLeakScanner


_LOGGER = logging.getLogger("lumen_ex")


@dataclass(frozen=True)
class _PreparedRecord:
    parsed: ParsedRecord
    normalized: NormalizedRecord
    detection: DetectionResult
    linkage: LinkageDecision
    result: SanitizationResult
    linked: bool


class ReleasePipeline:
    """Run existing M02–M07 stages and release only validated whole-file outputs."""

    def __init__(
        self,
        input_root: Path,
        output_root: Path,
        config: PipelineConfig,
        secret: str,
        leak_scanner: SensitiveDataLeakScanner,
    ) -> None:
        self.input_root = input_root
        self.output_root = output_root
        self.config = config
        self.secret = secret
        self.leak_scanner = leak_scanner

    def run(self) -> PipelineReport:
        started = time.monotonic()
        self._prepare_output_root()
        ingestion = StreamingIngestor().ingest(self.input_root)
        parsed_records = tuple(ingestion.records)
        records_by_file: dict[str, list[_PreparedRecord]] = defaultdict(list)
        entity_counts: dict[str, int] = defaultdict(int)
        registry = EncryptedIdentityRegistry.temporary(self.secret)
        try:
            prepared = self._prepare_records(parsed_records, registry, entity_counts)
            for record in prepared:
                records_by_file[record.parsed.source.relative_path].append(record)

            writer = SanitizedOutputWriter(
                self.input_root, self.output_root, self.leak_scanner, secret=self.secret
            )
            file_results: list[FileWriteResult] = []
            report_files: list[OutputManifestEntry] = []
            records_quarantined = 0
            records_suppressed = 0
            exported_record_keys: set[tuple[str, str]] = set()
            exported_patient_keys: set[tuple[str, str]] = set()
            for outcome in ingestion.files:
                source = outcome.source
                if source is None:
                    raise ProcessingError(outcome.error_code or "filesystem_error")
                if outcome.status is IngestionStatus.QUARANTINED:
                    report_files.append(
                        OutputManifestEntry(
                            source.sha256,
                            None,
                            ProcessingStatus.QUARANTINED,
                            outcome.error_code or "internal_error",
                        )
                    )
                    continue
                file_records = tuple(
                    records_by_file.get(source.relative_path, ())
                )
                if len(file_records) != outcome.record_count:
                    report_files.append(
                        OutputManifestEntry(
                            source.sha256,
                            None,
                            ProcessingStatus.QUARANTINED,
                            "source_changed",
                        )
                    )
                    records_quarantined += outcome.record_count
                    continue
                file_result = writer.write_file(
                    source,
                    tuple(
                        ReleaseRecord(
                            item.parsed,
                            item.normalized,
                            item.result,
                            _sensitive_values(item),
                        )
                        for item in file_records
                    ),
                )
                file_results.append(file_result)
                report_files.append(file_result.manifest)
                records_quarantined += file_result.records_quarantined
                if file_result.manifest.status is not ProcessingStatus.QUARANTINED:
                    records_suppressed += sum(
                        item.result.status is ProcessingStatus.SUPPRESSED
                        for item in file_records
                    )
                for entry in file_result.records:
                    key = (source.relative_path, str(entry["loc"]))
                    exported_record_keys.add(key)
                    if entry.get("patient") is not None:
                        exported_patient_keys.add(key)

            exported = tuple(
                record
                for result in file_results
                for record in result.records
            )
            linked_count = len(exported_patient_keys)
            generalized_count = sum(
                1
                for item in prepared
                if item.result.status is ProcessingStatus.SANITIZED
                and item.result.generalized
                and (
                    item.parsed.source.relative_path,
                    item.parsed.locator,
                )
                in exported_record_keys
            )
            report = PipelineReport(
                files=tuple(report_files),
                records_processed=len(exported),
                identifiers_detected=sum(
                    item.detection.identifier_count for item in prepared
                ),
                records_linked=linked_count,
                records_generalized=generalized_count,
                records_suppressed=records_suppressed,
                records_quarantined=records_quarantined,
                seconds=round(time.monotonic() - started, 2),
                peak_rss_mb=_peak_rss_mb(),
                entity_counts=dict(sorted(entity_counts.items())),
            )
            report_data = report.to_official_dict()
            records_text = "".join(
                json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
                for record in exported
            )
            if not self.leak_scanner.scan_artifact_text(
                records_text, filename="records.jsonl"
            ):
                raise ProcessingError("leak_scan_failed")
            (self.output_root / "records.jsonl").write_text(
                records_text, encoding="utf-8", newline=""
            )

            report_text = json.dumps(
                report_data, ensure_ascii=False, indent=2
            ) + "\n"
            if not self.leak_scanner.scan_artifact_text(
                report_text, filename="report.json"
            ):
                raise ProcessingError("leak_scan_failed")
            (self.output_root / "report.json").write_text(
                report_text, encoding="utf-8", newline=""
            )
            OutputContractValidator().validate(
                self.output_root, report.files, exported, report_data
            )
        finally:
            registry.close()

        _LOGGER.info(
            "Release complete: files=%d sanitized=%d quarantined=%d records=%d",
            len(report.files),
            report_data["counts"]["files_sanitized"],
            report_data["counts"]["files_quarantined"],
            len(exported),
        )
        return report

    def _prepare_records(
        self,
        records: Sequence[ParsedRecord],
        registry: EncryptedIdentityRegistry,
        entity_counts: dict[str, int],
    ) -> tuple[_PreparedRecord, ...]:
        normalizer = PatientIdentityNormalizer(self.config)
        detector = MultilingualPIIDetector()
        matchers: dict[str, IdentityMatcher] = {}
        transformer = PrivacyTransformer(self.secret, self.config)
        prepared: list[_PreparedRecord] = []
        privacy_inputs: list[PrivacyInput] = []
        privacy_indices: list[int] = []
        normalized_by_record: dict[tuple[str, str], NormalizedRecord] = {}
        normalization_errors: dict[tuple[str, str], str] = {}
        names_by_file: dict[str, set[str]] = defaultdict(set)

        for parsed in records:
            key = (parsed.source.relative_path, parsed.locator)
            try:
                normalized = normalizer.normalize(parsed)
            except ProcessingError as error:
                normalization_errors[key] = error.code
                continue
            except Exception:
                normalization_errors[key] = "internal_error"
                continue
            normalized_by_record[key] = normalized
            names_by_file[parsed.source.relative_path].update(
                value.original
                for identity in normalized.identities
                for value in identity.name
            )

        source_namespaces = _source_namespaces_by_file(
            records, normalized_by_record
        )
        for parsed in records:
            key = (parsed.source.relative_path, parsed.locator)
            normalized = NormalizedRecord(
                source=parsed.source,
                locator=parsed.locator,
                fields={},
            )
            detection = DetectionResult(identifier_count=0)
            linkage = LinkageDecision(LinkageAction.ABSTAIN)
            linked = False
            try:
                if key in normalization_errors:
                    raise ProcessingError(normalization_errors[key])
                normalized = normalized_by_record[key]
                detection = detector.detect(
                    normalized,
                    known_names=tuple(
                        sorted(names_by_file[parsed.source.relative_path])
                    ),
                )
                for entity, count in detection.entity_counts.items():
                    entity_counts[entity] = entity_counts.get(entity, 0) + count
                namespace = source_namespaces[parsed.source.relative_path]
                if namespace not in matchers:
                    matchers[namespace] = IdentityMatcher(registry, hospital_namespace=namespace)
                linkage, linked = self._link_record(normalized, matchers[namespace], registry)
                privacy_indices.append(len(prepared))
                privacy_inputs.append(
                    PrivacyInput(
                        normalized,
                        detection,
                        linkage,
                    )
                )
                prepared.append(
                    _PreparedRecord(
                        parsed, normalized, detection, linkage,
                        SanitizationResult(
                            ProcessingStatus.QUARANTINED,
                            parsed.locator,
                            error_code="internal_error",
                        ),
                        linked,
                    )
                )
            except ProcessingError as error:
                prepared.append(
                    _PreparedRecord(
                        parsed,
                        normalized,
                        detection,
                        linkage,
                        SanitizationResult(
                            ProcessingStatus.QUARANTINED,
                            parsed.locator,
                            error_code=error.code,
                            identifiers_detected=detection.identifier_count,
                        ),
                        False,
                    )
                )
            except Exception:
                prepared.append(
                    _PreparedRecord(
                        parsed,
                        normalized,
                        detection,
                        linkage,
                        SanitizationResult(
                            ProcessingStatus.QUARANTINED,
                            parsed.locator,
                            error_code="internal_error",
                            identifiers_detected=detection.identifier_count,
                        ),
                        False,
                    )
                )

        transformed = transformer.transform_batch(privacy_inputs)
        for prepared_index, result in zip(privacy_indices, transformed):
            item = prepared[prepared_index]
            if (
                result.status is ProcessingStatus.SANITIZED
                and not self.leak_scanner.is_safe(
                    result,
                    sensitive_values=_sensitive_values(item),
                )
            ):
                result = SanitizationResult(
                    ProcessingStatus.QUARANTINED,
                    result.locator,
                    error_code="leak_scan_failed",
                    identifiers_detected=result.identifiers_detected,
                )
            prepared[prepared_index] = _PreparedRecord(
                item.parsed,
                item.normalized,
                item.detection,
                item.linkage,
                result,
                item.linked,
            )
        return tuple(prepared)

    @staticmethod
    def _link_record(
        record: NormalizedRecord,
        matcher: IdentityMatcher,
        registry: EncryptedIdentityRegistry,
    ) -> tuple[LinkageDecision, bool]:
        identity = record.identities[0] if len(record.identities) == 1 else None
        if identity is None:
            registry.add_record_mapping(
                record.source.sha256,
                record.locator,
                None,
                IdentityDecision.UNRESOLVED,
                0.0,
            )
            return LinkageDecision(LinkageAction.ABSTAIN), False

        match = matcher.evaluate(identity)
        if match.decision is IdentityDecision.UNRESOLVED:
            registry.add_record_mapping(
                record.source.sha256,
                record.locator,
                None,
                IdentityDecision.UNRESOLVED,
                match.confidence,
                evidence={
                    field_name: [asdict(value) for value in getattr(identity, field_name)]
                    for field_name in ("hospital_identifier", "insurance_identifier")
                    if getattr(identity, field_name)
                },
            )
            return LinkageDecision(LinkageAction.ABSTAIN), False

        patient_id = match.patient_id
        if match.decision is IdentityDecision.CREATE:
            patient_id = registry.create_patient(
                record.source.sha256, record.locator
            )
        if patient_id is None:
            raise ProcessingError("registry_reference_invalid")
        registry.add_record_mapping(
            record.source.sha256,
            record.locator,
            patient_id,
            match.decision,
            match.confidence,
        )
        registry.add_identity(
            patient_id,
            record.source.sha256,
            identity,
            namespace=matcher.hospital_namespace,
            record_locator=record.locator,
        )
        return (
            LinkageDecision(LinkageAction.LINK, patient_id),
            match.decision is IdentityDecision.LINK,
        )

    def _prepare_output_root(self) -> None:
        try:
            self.output_root.mkdir(parents=True, exist_ok=True)
            if any(self.output_root.iterdir()):
                raise ProcessingError("filesystem_error")
            (self.output_root / "sanitized").mkdir()
        except ProcessingError:
            raise
        except OSError:
            raise ProcessingError("filesystem_error") from None


def _source_namespaces_by_file(
    records: Sequence[ParsedRecord],
    normalized_by_record: dict[tuple[str, str], NormalizedRecord],
) -> dict[str, str]:
    candidates: dict[str, set[str]] = defaultdict(set)
    for (relative_path, _), normalized in normalized_by_record.items():
        for identity in normalized.identities:
            if identity.source_system:
                candidates[relative_path].add(identity.source_system)
            candidates[relative_path].update(
                value.namespace
                for value in identity.hospital_identifier
                if value.namespace and value.source_key != "patient_ref"
            )

    namespaces: dict[str, str] = {}
    for parsed in records:
        relative_path = parsed.source.relative_path
        source_candidates = candidates[relative_path]
        namespaces[relative_path] = (
            next(iter(source_candidates))
            if len(source_candidates) == 1
            else f"file:{parsed.source.sha256}"
        )
    return namespaces


def _peak_rss_mb() -> float:
    if platform.system() == "Windows":
        import ctypes
        from ctypes import wintypes

        class _ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t),
            ]

        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        get_memory_info = psapi.GetProcessMemoryInfo
        get_memory_info.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        get_memory_info.restype = wintypes.BOOL
        if not get_memory_info(
            kernel32.GetCurrentProcess(),
            ctypes.byref(counters),
            counters.cb,
        ):
            raise ProcessingError("internal_error")
        return round(counters.PeakWorkingSetSize / (1024 * 1024), 1)

    try:
        import resource

        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (ImportError, OSError):
        raise ProcessingError("internal_error") from None
    divisor = 1024 * 1024 if platform.system() == "Darwin" else 1024
    return round(peak_rss / divisor, 1)


def _sensitive_values(item: _PreparedRecord) -> tuple[str, ...]:
    values = {
        finding.value
        for finding in item.detection.findings
        if (
            len(finding.value) >= 4
            and finding.entity_type is not DetectionEntityType.GENDER
        )
    }
    for identity in item.normalized.identities:
        for field_name in (
            "date_of_birth",
            "phone",
            "email",
            "address",
            "location",
            "hospital_identifier",
            "insurance_identifier",
            "government_identifier",
        ):
            values.update(
                field_value.original
                for field_value in getattr(identity, field_name)
                if len(field_value.original) >= 4
            )
    return tuple(sorted(values))
