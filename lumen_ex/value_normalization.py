"""Low-level value normalizers shared without importing pipeline packages."""

from datetime import date, datetime
import re
from typing import Literal
import unicodedata


DateOrder = Literal["dmy", "mdy"]
AmbiguousDateAction = Literal["redact", "quarantine"]

_AGE = re.compile(
    r"^\s*(\d{1,3})(?:\s*(?:years?|yrs?|y|saal|sal|varsh|वर्ष|साल))?"
    r"(?:\s*/\s*[mfx])?\s*$",
    re.IGNORECASE,
)
_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d/%m/%Y",
    "%d-%m-%Y",
    "%d.%m.%Y",
    "%m/%d/%Y",
    "%m-%d-%Y",
)
_ORDERED_DATE_FORMATS: dict[DateOrder, tuple[str, ...]] = {
    "dmy": ("%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y"),
    "mdy": ("%m/%d/%Y", "%m-%d-%Y", "%m.%d.%Y"),
}


def normalize_date(
    value: str | date | datetime,
    *,
    date_order: DateOrder | None = None,
) -> str | None:
    """Return a calendar date as ISO, refusing ambiguous dates without a source hint."""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()

    text = _ascii_digits(unicodedata.normalize("NFKC", value).strip())
    if not text:
        return None
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError:
        pass
    date_formats = (
        ("%Y/%m/%d",) + _ORDERED_DATE_FORMATS[date_order]
        if date_order is not None
        else _DATE_FORMATS
    )
    for date_format in date_formats:
        try:
            parsed = datetime.strptime(text, date_format).date()
        except ValueError:
            continue
        if date_order is None and date_format in {
            "%d/%m/%Y",
            "%d-%m-%Y",
            "%d.%m.%Y",
            "%m/%d/%Y",
            "%m-%d-%Y",
        }:
            first, second = _date_components(text, date_format)
            if first <= 12 and second <= 12 and first != second:
                return None
        return parsed.isoformat()
    return None


def normalize_age(value: str | int | float) -> str | None:
    """Return a plausible age in whole years as a canonical decimal string."""
    text = unicodedata.normalize("NFKC", str(value)).strip()
    match = _AGE.fullmatch(text)
    if match is None:
        return None
    age = int(match.group(1))
    return str(age) if age <= 125 else None


def _ascii_digits(value: str) -> str:
    return "".join(
        str(unicodedata.digit(character)) if character.isdecimal() else character
        for character in value
    )


def _date_components(value: str, date_format: str) -> tuple[int, int]:
    separator = "/" if "/" in date_format else "-" if "-" in date_format else "."
    first, second, _ = value.split(separator)
    return int(first), int(second)
