"""Cohort-aware privacy transformation stage."""

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from decimal import Decimal
import math
from pathlib import PurePosixPath
import re

from lumen_ex.config import PipelineConfig
from lumen_ex.contracts.models import (
    DetectionChannel,
    DetectionEntityType,
    DetectionFinding,
    DetectionResult,
    LinkageAction,
    LinkageDecision,
    NormalizedRecord,
    ProcessingStatus,
    SanitizationResult,
)
from lumen_ex.errors import ProcessingError
from lumen_ex.privacy.dates import DateShifter
from lumen_ex.privacy.generalization import AgeGeneralizer, LocationGeneralizer
from lumen_ex.privacy.integrity import ClinicalIntegrityValidator
from lumen_ex.privacy.pseudonym import Pseudonymizer
from lumen_ex.privacy.risk import QuasiIdentifierRiskAnalyzer, RareValueSuppressor
from lumen_ex.value_normalization import DateOrder


_KEY_NORMALIZER = re.compile(r"[^a-z0-9]+")
_AGE_KEYS = {"age", "ageyears", "patientage"}
_DIRECT_IDENTIFIER_TYPES = {
    DetectionEntityType.PATIENT_NAME,
    DetectionEntityType.RELATIVE_NAME,
    DetectionEntityType.DATE_OF_BIRTH,
    DetectionEntityType.AGE,
    DetectionEntityType.PHONE,
    DetectionEntityType.EMAIL,
    DetectionEntityType.AADHAAR,
    DetectionEntityType.ABHA,
    DetectionEntityType.PAN,
    DetectionEntityType.MEDICAL_RECORD_NUMBER,
    DetectionEntityType.INSURANCE_ID,
    DetectionEntityType.OTHER_IDENTIFIER,
    DetectionEntityType.ADDRESS,
    DetectionEntityType.LOCATION,
    DetectionEntityType.PIN_CODE,
}
_VERIFY_FINDING_TYPES = {
    DetectionEntityType.PATIENT_NAME,
    DetectionEntityType.RELATIVE_NAME,
    DetectionEntityType.DATE_OF_BIRTH,
    DetectionEntityType.PHONE,
    DetectionEntityType.EMAIL,
    DetectionEntityType.AADHAAR,
    DetectionEntityType.ABHA,
    DetectionEntityType.PAN,
    DetectionEntityType.MEDICAL_RECORD_NUMBER,
    DetectionEntityType.INSURANCE_ID,
    DetectionEntityType.OTHER_IDENTIFIER,
}
_MAX_DEPTH = 100


@dataclass(frozen=True)
class PrivacyInput:
    record: NormalizedRecord
    detection: DetectionResult
    linkage: LinkageDecision
    source_namespace: str | None = field(default=None, repr=False)


class PrivacyTransformer:
    """Apply deterministic transformations and assess the supplied cohort."""

    def __init__(
        self,
        secret: str | bytes,
        config: PipelineConfig | None = None,
    ) -> None:
        self.config = config or PipelineConfig()
        self._pseudonymizer = Pseudonymizer(secret)
        self._date_shifter = DateShifter(
            secret,
            self.config.date_shift_max_days,
            self.config.ambiguous_date_action,
        )
        self._age_generalizer = AgeGeneralizer(self.config.age_band_years)
        self._location_generalizer = LocationGeneralizer(
            self.config.location_hierarchy
        )
        self._risk_analyzer = QuasiIdentifierRiskAnalyzer()
        self._rare_value_suppressor = RareValueSuppressor()
        self._integrity_validator = ClinicalIntegrityValidator()

    def transform(
        self,
        record: NormalizedRecord,
        detection: DetectionResult,
        linkage: LinkageDecision,
    ) -> SanitizationResult:
        """Transform one record; without cohort context, fail closed on k-risk."""
        return self.transform_batch((PrivacyInput(record, detection, linkage),))[0]

    def transform_batch(
        self, records: Sequence[PrivacyInput]
    ) -> tuple[SanitizationResult, ...]:
        if not records:
            return ()

        results: list[SanitizationResult] = []
        valid_indices: list[int] = []
        for index, item in enumerate(records):
            try:
                results.append(self._transform_one(item))
                valid_indices.append(index)
            except ProcessingError as error:
                results.append(
                    SanitizationResult(
                        status=ProcessingStatus.QUARANTINED,
                        locator=item.record.locator,
                        error_code=error.code,
                        identifiers_detected=item.detection.identifier_count,
                    )
                )

        if not valid_indices:
            return tuple(results)

        cohort_fields = tuple(results[index].output_fields for index in valid_indices)
        initial_assessment = self._risk_analyzer.assess(
            cohort_fields, self.config.min_group_size
        )
        suppressed_fields = self._rare_value_suppressor.suppress(
            cohort_fields, initial_assessment
        )
        final_assessment = self._risk_analyzer.assess(
            suppressed_fields, self.config.min_group_size
        )

        for cohort_index, result_index in enumerate(valid_indices):
            result = results[result_index]
            if (
                final_assessment.equivalence_class_sizes[cohort_index]
                < self.config.min_group_size
            ):
                results[result_index] = SanitizationResult(
                    status=ProcessingStatus.SUPPRESSED,
                    locator=result.locator,
                    risk_assessment=final_assessment,
                    identifiers_detected=result.identifiers_detected,
                    generalized=result.generalized,
                    suppressed=True,
                )
                continue
            results[result_index] = SanitizationResult(
                status=ProcessingStatus.SANITIZED,
                locator=result.locator,
                output_fields=suppressed_fields[cohort_index],
                output_structure=result.output_structure,
                output_relative_path=result.output_relative_path,
                patient_pseudonym=result.patient_pseudonym,
                risk_assessment=final_assessment,
                identifiers_detected=result.identifiers_detected,
                generalized=True,
                suppressed=suppressed_fields[cohort_index]
                != result.output_fields,
            )
        return tuple(results)

    def _transform_one(self, item: PrivacyInput) -> SanitizationResult:
        record = item.record
        if item.detection.identifier_count != len(item.detection.findings):
            raise ProcessingError("invalid_record")
        if not isinstance(record.fields, Mapping):
            raise ProcessingError("invalid_record")
        try:
            original_fields = deepcopy(record.fields)
        except (TypeError, RecursionError):
            raise ProcessingError("privacy_structure_depth_exceeded") from None
        if not isinstance(original_fields, Mapping):
            raise ProcessingError("invalid_record")
        _validate_depth(original_fields, depth=0)

        patient_reference = (
            item.linkage.patient_reference
            if item.linkage.action is LinkageAction.LINK
            else record.record_id
        )
        if patient_reference is None:
            raise ProcessingError("privacy_patient_reference_invalid")

        generalized_fields = self._location_generalizer.generalize(original_fields)
        transformed_fields = self._transform_tree(
            generalized_fields,
            path=(),
            findings=item.detection.findings,
            patient_reference=patient_reference,
            date_order=self.config.date_order_for_source(
                record.source.relative_path
            ),
            depth=0,
        )
        if not isinstance(transformed_fields, dict):
            raise ProcessingError("invalid_record")
        fields = transformed_fields
        self._integrity_validator.validate(original_fields, fields)

        structure = self._safe_structure(record, item.detection.findings)
        source_namespace = item.source_namespace or f"file:{record.source.sha256}"
        output_relative_path = self._output_relative_path(
            record,
            item.detection.findings,
            source_namespace,
        )
        _verify_findings_removed(
            item.detection.findings,
            fields,
            structure,
            output_relative_path,
        )
        pseudonym = self._pseudonymizer.for_decision(item.linkage)
        return SanitizationResult(
            status=ProcessingStatus.SANITIZED,
            locator=record.locator,
            output_fields=fields,
            output_structure=structure,
            output_relative_path=output_relative_path,
            patient_pseudonym=pseudonym,
            identifiers_detected=item.detection.identifier_count,
            generalized=True,
        )

    def _transform_tree(
        self,
        value: object,
        *,
        path: tuple[str, ...],
        findings: tuple[DetectionFinding, ...],
        patient_reference: str,
        date_order: DateOrder | None,
        depth: int,
    ) -> object:
        if depth > _MAX_DEPTH:
            raise ProcessingError("privacy_structure_depth_exceeded")
        if isinstance(value, Mapping):
            transformed: dict[str, object] = {}
            for original_key, child in value.items():
                key = str(original_key)
                key_path = path + (key,)
                key_findings = tuple(
                    finding
                    for finding in findings
                    if finding.channel is DetectionChannel.KEY
                    and _source_path_matches(finding.source_key, key_path)
                )
                safe_key = _rewrite_text(
                    key, key_findings, self._age_generalizer
                )
                transformed_value = self._transform_tree(
                    child,
                    path=key_path,
                    findings=findings,
                    patient_reference=patient_reference,
                    date_order=date_order,
                    depth=depth + 1,
                )
                if _KEY_NORMALIZER.sub("", key.casefold()) in _AGE_KEYS:
                    transformed_value = self._age_generalizer.generalize(
                        transformed_value
                    )
                safe_key = _unique_key(safe_key, transformed)
                transformed[safe_key] = transformed_value
            return transformed
        if isinstance(value, list):
            return [
                self._transform_tree(
                    child,
                    path=path + (str(index),),
                    findings=findings,
                    patient_reference=patient_reference,
                    date_order=date_order,
                    depth=depth + 1,
                )
                for index, child in enumerate(value)
            ]
        if isinstance(value, tuple):
            return tuple(
                self._transform_tree(
                    child,
                    path=path + (str(index),),
                    findings=findings,
                    patient_reference=patient_reference,
                    date_order=date_order,
                    depth=depth + 1,
                )
                for index, child in enumerate(value)
            )
        if isinstance(value, str):
            value_findings = tuple(
                finding
                for finding in findings
                if finding.channel is DetectionChannel.VALUE
                and _source_path_matches(finding.source_key, path)
            )
            text = _rewrite_text(value, value_findings, self._age_generalizer)
            return self._date_shifter.shift_text(
                text, patient_reference, date_order=date_order
            )
        if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
            if isinstance(value, (float, Decimal)) and not math.isfinite(value):
                raise ProcessingError("invalid_record")
            text = str(value)
            value_findings = tuple(
                finding
                for finding in findings
                if finding.channel is DetectionChannel.VALUE
                and _source_path_matches(finding.source_key, path)
            )
            sanitized = _rewrite_text(text, value_findings, self._age_generalizer)
            if sanitized != text:
                return sanitized
            if path and _KEY_NORMALIZER.sub("", path[-1].casefold()) in _AGE_KEYS:
                return self._age_generalizer.generalize(value)
            return value
        if isinstance(value, bool) and path and (
            _KEY_NORMALIZER.sub("", path[-1].casefold()) in _AGE_KEYS
        ):
            return None
        if value is None or isinstance(value, bool):
            return value
        raise ProcessingError("invalid_record")

    def _safe_structure(
        self,
        record: NormalizedRecord,
        findings: tuple[DetectionFinding, ...],
    ) -> dict[str, object]:
        headers = record.structure.get("headers")
        if not isinstance(headers, (list, tuple)):
            return {}
        output_headers: list[object] = []
        for index, header in enumerate(headers):
            if not isinstance(header, str):
                raise ProcessingError("invalid_record")
            header_findings = tuple(
                finding
                for finding in findings
                if finding.channel is DetectionChannel.HEADER
                and finding.source_key == f"@header/{index}"
            )
            output_headers.append(
                _rewrite_text(header, header_findings, self._age_generalizer)
            )
        return {"headers": output_headers}

    def _output_relative_path(
        self,
        record: NormalizedRecord,
        findings: Sequence[DetectionFinding],
        source_namespace: str,
    ) -> str:
        source_path = PurePosixPath(record.source.relative_path.replace("\\", "/"))
        source_directory = (
            f"sanitized/src_{self._pseudonymizer.source_token(source_namespace)}"
        )
        if not any(finding.channel is DetectionChannel.FILENAME for finding in findings):
            return f"{source_directory}/{source_path}"
        suffix = source_path.suffix.casefold()
        if suffix not in {".csv", ".tsv", ".txt", ".json"}:
            suffix = ".dat"
        token = self._pseudonymizer.filename_token(record.source.sha256)
        return f"{source_directory}/file_{token}{suffix}"


def _rewrite_text(
    text: str,
    findings: Sequence[DetectionFinding],
    age_generalizer: AgeGeneralizer,
) -> str:
    replacements: list[tuple[int, int, str]] = []
    for finding in findings:
        if finding.start is None or finding.end is None:
            if finding.value == text:
                replacements.append(
                    (0, len(text), _replacement(finding.entity_type, text, age_generalizer))
                )
            continue
        if finding.end > len(text) or text[finding.start : finding.end] != finding.value:
            continue
        replacements.append(
            (
                finding.start,
                finding.end,
                _replacement(
                    finding.entity_type,
                    text[finding.start : finding.end],
                    age_generalizer,
                ),
            )
        )
    replacements.sort(key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, str]] = []
    for start, end, replacement in replacements:
        if merged and start < merged[-1][1]:
            previous_start, previous_end, _ = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end), "[REDACTED]")
        else:
            merged.append((start, end, replacement))
    merged.sort(key=lambda item: (item[0], item[1]), reverse=True)
    last_start = len(text) + 1
    for start, end, replacement in merged:
        if end > last_start:
            continue
        text = text[:start] + replacement + text[end:]
        last_start = start
    return text


def _replacement(
    entity_type: DetectionEntityType,
    value: str,
    age_generalizer: AgeGeneralizer,
) -> str:
    if entity_type is DetectionEntityType.AGE:
        return age_generalizer.generalize(value) or "[REDACTED]"
    if entity_type in {
        DetectionEntityType.ADDRESS,
        DetectionEntityType.LOCATION,
        DetectionEntityType.PIN_CODE,
    }:
        return "[LOCATION]"
    if entity_type in _DIRECT_IDENTIFIER_TYPES:
        return "[REDACTED]"
    return value


def _verify_findings_removed(
    findings: Sequence[DetectionFinding],
    fields: Mapping[str, object],
    structure: Mapping[str, object],
    output_relative_path: str,
) -> None:
    sensitive_values = tuple(
        finding.value
        for finding in findings
        if finding.entity_type in _VERIFY_FINDING_TYPES
    )
    for sensitive_value in sensitive_values:
        if (
            _contains_text(fields, sensitive_value)
            or _contains_text(structure, sensitive_value)
            or sensitive_value in output_relative_path
        ):
            raise ProcessingError("invalid_record")


def _contains_text(value: object, needle: str) -> bool:
    if isinstance(value, str):
        searchable = value.replace("[REDACTED]", "").replace("[LOCATION]", "")
        return needle in searchable
    if isinstance(value, Mapping):
        return any(
            _contains_text(str(key), needle) or _contains_text(child, needle)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_text(child, needle) for child in value)
    return False


def _source_path_matches(source_key: str, path: tuple[str, ...]) -> bool:
    if not source_key or source_key.startswith("@") or not path:
        return False
    source_parts = tuple(part.casefold() for part in source_key.split("."))
    path_parts = tuple(part.casefold() for part in path)
    shortest = min(len(source_parts), len(path_parts))
    return (
        source_parts[-shortest:] == path_parts[-shortest:]
        or path_parts[-shortest:] == source_parts[-shortest:]
    )


def _unique_key(key: str, existing: Mapping[str, object]) -> str:
    if key not in existing:
        return key
    index = 2
    while f"{key}_{index}" in existing:
        index += 1
    return f"{key}_{index}"


def _validate_depth(value: object, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise ProcessingError("privacy_structure_depth_exceeded")
    if isinstance(value, Mapping):
        for child in value.values():
            _validate_depth(child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_depth(child, depth + 1)
