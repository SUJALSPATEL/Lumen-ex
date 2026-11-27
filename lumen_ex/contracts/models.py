"""Internal contracts kept separate from the evaluator's serialized formats."""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from collections.abc import Iterator
import re

from lumen_ex.contracts.identity import PatientIdentity
from lumen_ex.errors import SAFE_ERROR_CODES


def _safe_relative_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return False
    return all(part not in ("", ".", "..") for part in normalized.split("/"))


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProcessingStatus(str, Enum):
    SANITIZED = "sanitized"
    QUARANTINED = "quarantined"
    SUPPRESSED = "suppressed"


class LinkageAction(str, Enum):
    LINK = "LINK"
    DO_NOT_LINK = "DO_NOT_LINK"
    ABSTAIN = "ABSTAIN"


class InputFormat(str, Enum):
    CSV = "csv"
    TSV = "tsv"
    JSON = "json"
    FHIR = "fhir"
    TEXT = "text"
    UNSUPPORTED = "unsupported"


class IngestionStatus(str, Enum):
    INGESTED = "ingested"
    QUARANTINED = "quarantined"


class DetectionEntityType(str, Enum):
    PATIENT_NAME = "PATIENT_NAME"
    RELATIVE_NAME = "RELATIVE_NAME"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    AGE = "AGE"
    GENDER = "GENDER"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    AADHAAR = "AADHAAR"
    ABHA = "ABHA"
    PAN = "PAN"
    MEDICAL_RECORD_NUMBER = "MEDICAL_RECORD_NUMBER"
    INSURANCE_ID = "INSURANCE_ID"
    ADDRESS = "ADDRESS"
    LOCATION = "LOCATION"
    PIN_CODE = "PIN_CODE"
    OTHER_IDENTIFIER = "OTHER_IDENTIFIER"


class DetectionChannel(str, Enum):
    VALUE = "value"
    KEY = "key"
    HEADER = "header"
    FILENAME = "filename"


@dataclass(frozen=True)
class InputFileMetadata:
    relative_path: str = field(repr=False)
    sha256: str
    size_bytes: int
    media_type: str | None = None
    detected_format: InputFormat | None = None
    encoding: str | None = None

    def __post_init__(self) -> None:
        if not _safe_relative_path(self.relative_path):
            raise ValueError("input_path_invalid")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("input_sha256_invalid")
        if self.size_bytes < 0:
            raise ValueError("input_size_invalid")

    @property
    def source_id(self) -> str:
        identity = f"{self.relative_path}\0{self.sha256}".encode("utf-8")
        return hashlib.sha256(identity).hexdigest()


@dataclass(frozen=True)
class ParsedRecord:
    source: InputFileMetadata
    locator: str = field(repr=False)
    values: object = field(repr=False)
    structure: dict[str, object] = field(default_factory=dict, repr=False)
    identity_context: tuple[tuple[tuple[str | int, ...], dict[str, object]], ...] = field(
        default=(), repr=False
    )

    def __post_init__(self) -> None:
        if not self.locator:
            raise ValueError("record_locator_invalid")

    @property
    def record_id(self) -> str:
        return f"{self.source.source_id}:{self.locator}"


@dataclass(frozen=True)
class IngestionFileResult:
    relative_path: str = field(repr=False)
    source: InputFileMetadata | None
    status: IngestionStatus
    record_count: int = 0
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not _safe_relative_path(self.relative_path):
            raise ValueError("input_path_invalid")
        if self.record_count < 0:
            raise ValueError("ingestion_record_count_invalid")
        if self.source is not None and self.source.relative_path != self.relative_path:
            raise ValueError("ingestion_source_mismatch")
        if self.status is IngestionStatus.QUARANTINED:
            if self.error_code is None:
                raise ValueError("ingestion_error_required")
        elif self.error_code is not None:
            raise ValueError("ingestion_error_status_invalid")
        elif self.source is None:
            raise ValueError("ingestion_source_required")
        if self.error_code is not None and self.error_code not in SAFE_ERROR_CODES:
            raise ValueError("error_code_invalid")
        if self.status is IngestionStatus.QUARANTINED and self.record_count:
            raise ValueError("quarantined_record_count_invalid")


@dataclass(frozen=True)
class IngestionStatistics:
    files_discovered: int
    files_ingested: int
    files_quarantined: int
    records_parsed: int
    bytes_scanned: int

    def __post_init__(self) -> None:
        values = (
            self.files_discovered,
            self.files_ingested,
            self.files_quarantined,
            self.records_parsed,
            self.bytes_scanned,
        )
        if any(value < 0 for value in values):
            raise ValueError("ingestion_statistic_invalid")
        if self.files_ingested + self.files_quarantined != self.files_discovered:
            raise ValueError("ingestion_file_totals_invalid")


@dataclass(frozen=True)
class IngestionResult:
    files: tuple[IngestionFileResult, ...]
    records: Iterator[ParsedRecord] = field(repr=False, compare=False)
    statistics: IngestionStatistics

    def __post_init__(self) -> None:
        if len(self.files) != self.statistics.files_discovered:
            raise ValueError("ingestion_file_totals_invalid")
        if sum(item.status is IngestionStatus.INGESTED for item in self.files) != (
            self.statistics.files_ingested
        ):
            raise ValueError("ingestion_file_totals_invalid")
        if sum(item.status is IngestionStatus.QUARANTINED for item in self.files) != (
            self.statistics.files_quarantined
        ):
            raise ValueError("ingestion_file_totals_invalid")
        if sum(item.record_count for item in self.files) != self.statistics.records_parsed:
            raise ValueError("ingestion_record_totals_invalid")
        scanned_bytes = sum(
            item.source.size_bytes for item in self.files if item.source is not None
        )
        if scanned_bytes != self.statistics.bytes_scanned:
            raise ValueError("ingestion_byte_totals_invalid")


@dataclass(frozen=True)
class NormalizedRecord:
    source: InputFileMetadata
    locator: str = field(repr=False)
    fields: dict[object, object] = field(repr=False)
    identities: tuple[PatientIdentity, ...] = field(default=(), repr=False)
    structure: dict[str, object] = field(default_factory=dict, repr=False)

    @property
    def record_id(self) -> str:
        return f"{self.source.source_id}:{self.locator}"


@dataclass(frozen=True)
class DetectionFinding:
    entity_type: DetectionEntityType
    value: str = field(repr=False)
    source_key: str = field(repr=False)
    channel: DetectionChannel
    start: int | None = None
    end: int | None = None

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("detection_finding_value_invalid")
        if (self.start is None) != (self.end is None):
            raise ValueError("detection_finding_span_invalid")
        if self.start is not None and (
            self.start < 0 or self.end is None or self.end <= self.start
        ):
            raise ValueError("detection_finding_span_invalid")


@dataclass(frozen=True)
class DetectionResult:
    identifier_count: int
    entity_counts: dict[str, int] = field(default_factory=dict)
    findings: tuple[DetectionFinding, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if self.identifier_count < 0 or any(count < 0 for count in self.entity_counts.values()):
            raise ValueError("detection_count_invalid")
        if self.findings and self.identifier_count != len(self.findings):
            raise ValueError("detection_finding_count_invalid")
        if self.entity_counts and sum(self.entity_counts.values()) != self.identifier_count:
            raise ValueError("detection_entity_count_invalid")


@dataclass(frozen=True)
class LinkageDecision:
    action: LinkageAction
    patient_reference: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (self.action is LinkageAction.LINK) != (self.patient_reference is not None):
            raise ValueError("linkage_reference_invalid")
        if self.action is LinkageAction.LINK and not self.patient_reference:
            raise ValueError("linkage_reference_invalid")


@dataclass(frozen=True)
class SanitizationResult:
    status: ProcessingStatus
    locator: str = field(repr=False)
    output_fields: dict[str, object] = field(default_factory=dict, repr=False)
    error_code: str | None = None
    identifiers_detected: int = 0
    generalized: bool = False
    suppressed: bool = False
    output_structure: dict[str, object] = field(default_factory=dict, repr=False)
    output_relative_path: str | None = field(default=None, repr=False)
    patient_pseudonym: str | None = field(default=None, repr=False)
    risk_assessment: "PrivacyRiskAssessment | None" = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.identifiers_detected < 0:
            raise ValueError("sanitization_count_invalid")
        if self.status is ProcessingStatus.QUARANTINED and not self.error_code:
            raise ValueError("quarantine_reason_required")
        if self.error_code is not None and self.error_code not in SAFE_ERROR_CODES:
            raise ValueError("error_code_invalid")
        if self.status is not ProcessingStatus.QUARANTINED and self.error_code is not None:
            raise ValueError("error_code_status_invalid")
        if self.output_relative_path is not None and (
            not _safe_relative_path(self.output_relative_path)
            or not self.output_relative_path.startswith("sanitized/")
        ):
            raise ValueError("sanitization_output_path_invalid")
        if self.patient_pseudonym is not None and not re.fullmatch(
            r"PSN-[A-Z0-9]+", self.patient_pseudonym
        ):
            raise ValueError("sanitization_pseudonym_invalid")


@dataclass(frozen=True)
class PrivacyRiskAssessment:
    records_assessed: int
    equivalence_classes: int
    unique_records: int
    minimum_equivalence_class_size: int
    mean_reidentification_risk: float
    rare_value_count: int
    equivalence_class_sizes: tuple[int, ...] = field(repr=False)
    rare_attributes_by_record: tuple[tuple[str, ...], ...] = field(repr=False)

    def __post_init__(self) -> None:
        counts = (
            self.records_assessed,
            self.equivalence_classes,
            self.unique_records,
            self.minimum_equivalence_class_size,
            self.rare_value_count,
        )
        if any(value < 0 for value in counts):
            raise ValueError("privacy_risk_count_invalid")
        if (
            not 0.0 <= self.mean_reidentification_risk <= 1.0
            or len(self.equivalence_class_sizes) != self.records_assessed
            or len(self.rare_attributes_by_record) != self.records_assessed
        ):
            raise ValueError("privacy_risk_assessment_invalid")
        if any(size < 1 for size in self.equivalence_class_sizes):
            raise ValueError("privacy_risk_class_size_invalid")


@dataclass(frozen=True)
class OutputManifestEntry:
    input_sha256: str
    output: str | None
    status: ProcessingStatus
    reason: str | None = None

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.input_sha256):
            raise ValueError("manifest_sha256_invalid")
        if self.status is ProcessingStatus.SANITIZED and not self.output:
            raise ValueError("manifest_output_required")
        if self.status is ProcessingStatus.SANITIZED and (
            not _safe_relative_path(self.output)
            or not self.output.startswith("sanitized/")
        ):
            raise ValueError("manifest_output_invalid")
        if self.status is ProcessingStatus.QUARANTINED and not self.reason:
            raise ValueError("manifest_reason_required")
        if self.status is ProcessingStatus.QUARANTINED and self.output is not None:
            raise ValueError("manifest_quarantine_output_invalid")
        if self.reason is not None and self.reason not in SAFE_ERROR_CODES:
            raise ValueError("manifest_reason_invalid")
        if self.status is not ProcessingStatus.QUARANTINED and self.reason is not None:
            raise ValueError("manifest_reason_status_invalid")

    def to_official_dict(self) -> dict[str, str | None]:
        """Serialize only fields permitted by docs/SPEC.md for a file entry."""
        entry: dict[str, str | None] = {
            "input_sha256": self.input_sha256,
            "output": self.output,
            "status": self.status.value,
        }
        if self.reason is not None:
            entry["reason"] = self.reason
        return entry


@dataclass(frozen=True)
class PipelineReport:
    files: tuple[OutputManifestEntry, ...]
    records_processed: int = 0
    identifiers_detected: int = 0
    records_linked: int = 0
    records_generalized: int = 0
    records_suppressed: int = 0
    records_quarantined: int = 0
    seconds: float = 0.0
    peak_rss_mb: float = 0.0
    entity_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        numeric_values = (
            self.records_processed,
            self.identifiers_detected,
            self.records_linked,
            self.records_generalized,
            self.records_suppressed,
            self.records_quarantined,
            self.seconds,
            self.peak_rss_mb,
        )
        if any(value < 0 for value in numeric_values) or any(
            value < 0 for value in self.entity_counts.values()
        ):
            raise ValueError("report_metric_invalid")

    def to_official_dict(self) -> dict[str, object]:
        """Serialize the existing raksha-report/1 contract without new required fields."""
        sanitized = sum(item.status is ProcessingStatus.SANITIZED for item in self.files)
        quarantined = sum(item.status is ProcessingStatus.QUARANTINED for item in self.files)
        report: dict[str, object] = {
            "schema": "raksha-report/1",
            "files": [item.to_official_dict() for item in self.files],
            "counts": {
                "files_total": len(self.files),
                "files_sanitized": sanitized,
                "files_quarantined": quarantined,
                "records_processed": self.records_processed,
                "identifiers_detected": self.identifiers_detected,
                "records_linked": self.records_linked,
                "records_generalized": self.records_generalized,
                "records_suppressed": self.records_suppressed,
                "records_quarantined": self.records_quarantined,
            },
            "timing": {"seconds": self.seconds},
            "resources": {"peak_rss_mb": self.peak_rss_mb},
        }
        if self.entity_counts:
            report["entities"] = dict(self.entity_counts)
        return report
