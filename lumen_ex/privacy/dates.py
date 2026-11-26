"""Patient-specific deterministic date shifting."""

from datetime import date, datetime, timedelta
import hashlib
import hmac
import re

from lumen_ex.errors import ProcessingError
from lumen_ex.key_derivation import derive_key
from lumen_ex.value_normalization import (
    AmbiguousDateAction,
    DateOrder,
    normalize_date,
)


_DATE_TOKEN = re.compile(
    r"(?<!\d)(?:"
    r"\d{4}-\d{2}-\d{2}(?:[T ][0-9]{2}:[0-9]{2}"
    r"(?::[0-9]{2}(?:\.\d+)?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?"
    r"|\d{4}/\d{1,2}/\d{1,2}"
    r"|\d{1,2}[./-]\d{1,2}[./-]\d{4}"
    r")(?!\d)"
)
_ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ].+")
_REDACTED_DATE = "[DATE REDACTED]"


class DateShifter:
    def __init__(
        self,
        secret: str | bytes,
        max_days: int = 180,
        ambiguous_date_action: AmbiguousDateAction = "redact",
    ) -> None:
        if not isinstance(secret, (str, bytes)) or not secret:
            raise ProcessingError("secret_missing")
        if isinstance(max_days, bool) or not isinstance(max_days, int) or max_days < 1:
            raise ProcessingError("privacy_policy_invalid")
        if ambiguous_date_action not in {"redact", "quarantine"}:
            raise ProcessingError("privacy_policy_invalid")
        self._key = derive_key(secret, b"patient-date-shift")
        self.max_days = max_days
        self.ambiguous_date_action = ambiguous_date_action

    def offset_for(self, patient_reference: str) -> int:
        if not isinstance(patient_reference, str) or not patient_reference:
            raise ProcessingError("privacy_patient_reference_invalid")
        digest = hmac.new(
            self._key,
            b"lumen-ex/date-shift/v1\0" + patient_reference.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        magnitude = 1 + (int.from_bytes(digest[:8], "big") % self.max_days)
        direction = -1 if digest[8] & 1 else 1
        return direction * magnitude

    def shift(self, value: date | datetime, patient_reference: str) -> date | datetime:
        offset = self.offset_for(patient_reference)
        try:
            return value + timedelta(days=offset)
        except OverflowError:
            raise ProcessingError("privacy_date_out_of_range") from None

    def shift_text(
        self,
        text: str,
        patient_reference: str,
        *,
        date_order: DateOrder | None = None,
    ) -> str:
        offset = self.offset_for(patient_reference)

        def replace(match: re.Match[str]) -> str:
            token = match.group(0)
            if _ISO_DATETIME.fullmatch(token):
                return _shift_datetime_token(token, offset)
            normalized = normalize_date(token, date_order=date_order)
            if normalized is None:
                if date_order is None and _is_ambiguous_date(token):
                    if self.ambiguous_date_action == "redact":
                        return _REDACTED_DATE
                    raise ProcessingError("privacy_date_format_ambiguous")
                raise ProcessingError("privacy_date_invalid")
            shifted = _shift_date(date.fromisoformat(normalized), offset)
            return shifted.isoformat()

        return _DATE_TOKEN.sub(replace, text)


def canonicalize_date_tokens(text: str) -> str:
    return _DATE_TOKEN.sub("[DATE]", text).replace(_REDACTED_DATE, "[DATE]")


def _shift_date(value: date, offset: int) -> date:
    try:
        return value + timedelta(days=offset)
    except OverflowError:
        raise ProcessingError("privacy_date_out_of_range") from None


def _shift_datetime_token(token: str, offset: int) -> str:
    source = token.replace("Z", "+00:00")
    try:
        value = datetime.fromisoformat(source)
    except ValueError:
        raise ProcessingError("privacy_date_invalid") from None
    try:
        shifted = value + timedelta(days=offset)
    except OverflowError:
        raise ProcessingError("privacy_date_out_of_range") from None
    result = shifted.isoformat()
    if token.endswith("Z") and result.endswith("+00:00"):
        result = result[:-6] + "Z"
    return result


def _is_ambiguous_date(token: str) -> bool:
    parts = re.split(r"[./-]", token)
    if len(parts) != 3 or len(parts[2]) != 4:
        return False
    try:
        first, second, year = (int(part) for part in parts)
        if not (1 <= first <= 12 and 1 <= second <= 12):
            return False
        date(year, first, second)
        date(year, second, first)
    except ValueError:
        return False
    return first != second
