"""Checks that privacy transformations preserve protected clinical values."""

from collections.abc import Mapping
from datetime import date
import re

from lumen_ex.errors import ProcessingError
from lumen_ex.privacy.dates import canonicalize_date_tokens
from lumen_ex.privacy.temporal import normalize_temporal_date
from lumen_ex.value_normalization import DateOrder


_KEY_NORMALIZER = re.compile(r"[^a-z0-9]+")
_CLINICAL_KEY_PARTS = (
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
    "laboratory",
    "labresult",
    "complaint",
    "history",
    "ward",
    "clinician",
    "doctor",
    "icd",
)
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


class ClinicalIntegrityValidator:
    def validate(
        self,
        original: Mapping[object, object],
        transformed: Mapping[object, object],
        *,
        date_order: DateOrder | None = None,
    ) -> None:
        if _clinical_values(original) != _clinical_values(transformed):
            raise ProcessingError("clinical_integrity_failed")
        original_intervals = _stay_intervals(original, date_order=date_order)
        transformed_intervals = _stay_intervals(transformed, date_order=date_order)
        # If both have stay intervals and they differ, flag a failure.
        # Missing intervals (e.g., when dates are redacted) are acceptable – they will be handled elsewhere.
        if original_intervals and transformed_intervals and original_intervals != transformed_intervals:
            raise ProcessingError("clinical_integrity_failed")


def _clinical_values(value: object, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], object]:
    result: dict[tuple[str, ...], object] = {}
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = _KEY_NORMALIZER.sub("", str(key).casefold())
            child_path = path + (str(key),)
            if any(part in name for part in _CLINICAL_KEY_PARTS):
                result[child_path] = _canonicalize_date_values(child)
            result.update(_clinical_values(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            result.update(_clinical_values(child, path + (str(index),)))
    return result


def _canonicalize_date_values(value: object) -> object:
    if isinstance(value, str):
        return canonicalize_date_tokens(value)
    if isinstance(value, Mapping):
        return {
            key: _canonicalize_date_values(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_canonicalize_date_values(child) for child in value]
    if isinstance(value, tuple):
        return tuple(_canonicalize_date_values(child) for child in value)
    return value


def _stay_intervals(
    value: object, *, date_order: DateOrder | None = None
) -> tuple[tuple[str, int], ...]:
    intervals: list[tuple[str, int]] = []

    def visit(node: object, path: tuple[str, ...]) -> None:
        if isinstance(node, Mapping):
            normalized = {
                _KEY_NORMALIZER.sub("", str(key).casefold()): child
                for key, child in node.items()
            }
            admission = _first_date(normalized, _ADMISSION_KEYS, date_order)
            discharge = _first_date(normalized, _DISCHARGE_KEYS, date_order)
            if admission is not None and discharge is not None:
                intervals.append((".".join(path), (discharge - admission).days))
            for key, child in node.items():
                visit(child, path + (str(key),))
        elif isinstance(node, (list, tuple)):
            for index, child in enumerate(node):
                visit(child, path + (str(index),))

    visit(value, ())
    return tuple(sorted(intervals))


def _first_date(
    values: Mapping[str, object], keys: set[str], date_order: DateOrder | None
) -> date | None:
    for key in sorted(keys):
        value = values.get(key)
        if isinstance(value, str):
            normalized = normalize_temporal_date(value, date_order=date_order)
            if normalized is not None:
                return date.fromisoformat(normalized)
    return None
