"""Cohort-level quasi-identifier risk measurement and permitted suppression."""

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import date
import re
import unicodedata

from lumen_ex.contracts.models import PrivacyRiskAssessment
from lumen_ex.privacy.temporal import normalize_temporal_date


_KEY_NORMALIZER = re.compile(r"[^a-z0-9]+")
_QI_KEY_GROUPS = {
    "age": {"age", "ageyears", "ageband"},
    "gender": {"gender", "sex", "patientgender", "ling"},
    "village": {"village", "gaon", "gram", "mohalla", "locality", "town", "city"},
    "tehsil": {"tehsil", "taluk", "taluka", "subdistrict"},
    "district": {"district", "jila", "zilla"},
    "state": {"state", "province"},
    "pin": {"pin", "pincode", "postalcode", "zipcode", "postal"},
    "date": {
        "date",
        "dob",
        "dateofbirth",
        "janmtithi",
        "janamtithi",
        "janmtarikh",
        "janamtarikh",
        "admissiondate",
        "dateofadmission",
        "dischargedate",
        "dateofdischarge",
        "visitdate",
        "encounterdate",
    },
    "stay_length": {"lengthofstay", "staydays", "los"},
    "rare_diagnosis": {"diagnosis", "condition", "procedure"},
}
_SUPPRESSIBLE = {
    "age",
    "gender",
    "village",
    "tehsil",
    "district",
    "state",
    "pin",
}
_ADMISSION_KEYS = {
    "admissiondate",
    "dateofadmission",
    "admitdate",
    "periodstart",
    "start",
    "startdate",
}
_DISCHARGE_KEYS = {
    "dischargedate",
    "dateofdischarge",
    "end",
    "enddate",
    "periodend",
}


class QuasiIdentifierRiskAnalyzer:
    def assess(
        self,
        records: Sequence[Mapping[str, object]],
        min_group_size: int,
    ) -> PrivacyRiskAssessment:
        if (
            isinstance(min_group_size, bool)
            or not isinstance(min_group_size, int)
            or min_group_size < 2
        ):
            raise ValueError("privacy_risk_policy_invalid")
        profiles = tuple(extract_quasi_identifiers(record) for record in records)
        if not profiles:
            return PrivacyRiskAssessment(0, 0, 0, 0, 0.0, 0, (), ())

        class_keys = tuple(tuple(sorted(profile.items())) for profile in profiles)
        class_counts = Counter(class_keys)
        class_sizes = tuple(class_counts[key] for key in class_keys)
        attribute_counts: dict[str, Counter[str]] = {}
        for profile in profiles:
            for name, value in profile.items():
                attribute_counts.setdefault(name, Counter())[value] += 1
        rare_fields: list[tuple[str, ...]] = []
        rare_value_count = 0
        for counts in attribute_counts.values():
            rare_value_count += sum(count < min_group_size for count in counts.values())
        for profile in profiles:
            rare_fields.append(
                tuple(
                    sorted(
                        name
                        for name, value in profile.items()
                        if attribute_counts[name][value] < min_group_size
                    )
                )
            )
        return PrivacyRiskAssessment(
            records_assessed=len(profiles),
            equivalence_classes=len(class_counts),
            unique_records=sum(size == 1 for size in class_counts.values()),
            minimum_equivalence_class_size=min(class_counts.values()),
            mean_reidentification_risk=sum(1 / size for size in class_sizes)
            / len(class_sizes),
            rare_value_count=rare_value_count,
            equivalence_class_sizes=class_sizes,
            rare_attributes_by_record=tuple(rare_fields),
        )


class RareValueSuppressor:
    def suppress(
        self,
        records: Sequence[Mapping[object, object]],
        assessment: PrivacyRiskAssessment,
    ) -> tuple[dict[str, object], ...]:
        if len(records) != assessment.records_assessed:
            raise ValueError("privacy_suppression_cohort_mismatch")
        suppressible = {
            name
            for row in assessment.rare_attributes_by_record
            for name in row
            if name in _SUPPRESSIBLE
        }
        return tuple(
            _suppress_fields(record, suppressible)
            for record in records
        )


def extract_quasi_identifiers(record: Mapping[object, object]) -> dict[str, str]:
    result: dict[str, str] = {}

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            normalized_values = {
                _KEY_NORMALIZER.sub("", str(key).casefold()): child
                for key, child in value.items()
            }
            admission = _first_normalized_date(normalized_values, _ADMISSION_KEYS)
            discharge = _first_normalized_date(normalized_values, _DISCHARGE_KEYS)
            if admission is not None and discharge is not None:
                length = str((discharge - admission).days)
                result["stay_length"] = (
                    result["stay_length"] + "|" + length
                    if "stay_length" in result
                    else length
                )
            for key, child in value.items():
                normalized = _KEY_NORMALIZER.sub("", str(key).casefold())
                category = next(
                    (
                        name
                        for name, aliases in _QI_KEY_GROUPS.items()
                        if normalized in aliases
                    ),
                    None,
                )
                if category is not None and not isinstance(child, (Mapping, list, tuple)):
                    canonical = _normalize_qi_value(category, child)
                    if canonical is not None:
                        result[category] = (
                            result[category] + "|" + canonical
                            if category in result
                            else canonical
                        )
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(record)
    return result


def _first_normalized_date(
    values: Mapping[str, object], keys: set[str]
) -> date | None:
    for key in sorted(keys):
        value = values.get(key)
        if isinstance(value, str):
            normalized = normalize_temporal_date(value)
            if normalized is not None:
                return date.fromisoformat(normalized)
    return None


def _normalize_qi_value(category: str, value: object) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    if not text or text in {"[redacted]", "[location]", "unknown", "none"}:
        return None
    if category == "date":
        normalized = normalize_temporal_date(text)
        return normalized[:7] if normalized is not None else text
    return " ".join(text.split())


def _suppress_fields(
    record: Mapping[object, object], suppressible: set[str]
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in record.items():
        normalized = _KEY_NORMALIZER.sub("", str(key).casefold())
        category = next(
            (
                name
                for name, aliases in _QI_KEY_GROUPS.items()
                if normalized in aliases
            ),
            None,
        )
        if category in suppressible:
            result[str(key)] = None
        elif isinstance(value, Mapping):
            result[str(key)] = _suppress_fields(value, suppressible)
        elif isinstance(value, list):
            result[str(key)] = [
                _suppress_fields(item, suppressible)
                if isinstance(item, Mapping)
                else item
                for item in value
            ]
        elif isinstance(value, tuple):
            result[str(key)] = tuple(
                _suppress_fields(item, suppressible)
                if isinstance(item, Mapping)
                else item
                for item in value
            )
        else:
            result[str(key)] = value
    return result
