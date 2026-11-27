"""Deterministic, context-aware PII detection for normalized records."""

from collections.abc import Mapping
import base64
import binascii
from decimal import Decimal
import re
import unicodedata
from typing import Sequence

from lumen_ex.contracts.models import (
    DetectionChannel,
    DetectionEntityType,
    DetectionFinding,
    DetectionResult,
    NormalizedRecord,
)
from lumen_ex.detection.indic_names import normalize_name
from lumen_ex.errors import ProcessingError
from lumen_ex.identity import (
    normalize_age,
    normalize_date,
    normalize_gender,
    normalize_phone,
)


_MAX_DEPTH = 128
_MAX_NODES = 100_000
_MISSING_KEYS = {"", "na", "nil", "none", "null", "unknown"}


def _compact_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _reject_printable_base64_payload(value: str) -> None:
    if len(value) < 24 or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) is None:
        return
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            validate=True,
        ).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return
    printable = sum(
        character.isprintable() or character in "\r\n\t"
        for character in decoded
    )
    if decoded.strip() and printable / len(decoded) >= 0.95:
        raise ProcessingError("unsupported_format")


_NON_PATIENT_CONTEXTS = {
    "author",
    "clinician",
    "doctor",
    "facility",
    "hospital",
    "lab",
    "medication",
    "drug",
    "disease",
    "condition",
    "diagnosis",
    "panels",
    "procedure",
    "provider",
    "practitioner",
    "physician",
    "staff",
    "organization",
    "organisation",
}
_NAME_KEYS = {
    "name",
    "fullname",
    "patientname",
    "patientfullname",
    "personname",
    "naam",
    "patientnaam",
    "mareezkanam",
    "रोगीकानाम",
    "मरीजकानाम",
    "नाम",
}
_NAME_PART_KEYS = {
    "firstname",
    "given",
    "givenname",
    "lastname",
    "family",
    "familyname",
    "surname",
}
_KEY_TYPES: dict[DetectionEntityType, frozenset[str]] = {
    DetectionEntityType.DATE_OF_BIRTH: frozenset(
        {
            "dob",
            "dateofbirth",
            "birthdate",
            "patientdob",
            "janmtithi",
            "janamtithi",
            "janmtarikh",
            "janamtarikh",
            "जन्मतिथि",
        }
    ),
    DetectionEntityType.AGE: frozenset(
        {"age", "patientage", "umar", "umr", "उम्र", "आयु"}
    ),
    DetectionEntityType.GENDER: frozenset(
        {"gender", "sex", "patientgender", "ling", "लिंग"}
    ),
    DetectionEntityType.PHONE: frozenset(
        {
            "phone",
            "phonenumber",
            "phoneno",
            "mobile",
            "mobilenumber",
            "mobileno",
            "contactnumber",
            "telephone",
            "samparknumber",
            "फोन",
            "मोबाइल",
        }
    ),
    DetectionEntityType.EMAIL: frozenset({"email", "emailaddress", "e-mail", "ईमेल"}),
    DetectionEntityType.AADHAAR: frozenset(
        {
            "aadhaar",
            "aadhar",
            "aadhaarnumber",
            "aadharnumber",
            "aadhaarno",
            "aadharno",
            "आधार",
        }
    ),
    DetectionEntityType.ABHA: frozenset(
        {"abha", "abhaid", "abhanumber", "abhaaddress", "healthid"}
    ),
    DetectionEntityType.PAN: frozenset({"pan", "pannumber", "panno"}),
    DetectionEntityType.MEDICAL_RECORD_NUMBER: frozenset(
        {
            "patientid",
            "patientidentifier",
            "patientref",
            "hospitalid",
            "hospitalpatientid",
            "uhid",
            "hospitaluhid",
            "mrn",
            "medicalrecordnumber",
            "registrationnumber",
            "registrationid",
            "regno",
            "regnno",
            "ipdno",
            "ipdnumber",
            "opdno",
            "opdnumber",
            "caseid",
            "casenumber",
            "mareezid",
            "रोगीआईडी",
        }
    ),
    DetectionEntityType.INSURANCE_ID: frozenset(
        {
            "insuranceid",
            "insuranceidentifier",
            "insurancenumber",
            "insurancepolicynumber",
            "policyid",
            "policynumber",
            "policyno",
            "pmjayid",
            "memberid",
            "membernumber",
            "subscriberid",
            "insurancememberid",
            "policyholderid",
            "bima",
            "bimaid",
            "bimanumber",
            "बीमापहचान",
        }
    ),
    DetectionEntityType.ADDRESS: frozenset(
        {"address", "patientaddress", "pata", "gharkapata", "पता"}
    ),
    DetectionEntityType.LOCATION: frozenset(
        {
            "city",
            "village",
            "villagemohalla",
            "tehsil",
            "district",
            "state",
            "location",
            "gaon",
            "gram",
            "jila",
            "zilla",
            "shehar",
            "गाँव",
            "ग्राम",
            "जिला",
        }
    ),
    DetectionEntityType.PIN_CODE: frozenset(
        {"pin", "pincode", "zip", "zipcode", "postalcode", "postal"}
    ),
    DetectionEntityType.OTHER_IDENTIFIER: frozenset(
        {"governmentid", "nationalid", "identifier", "insurance"}
    ),
}
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])")
_PHONE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+?91[\s().-]*)?(?:0[\s().-]*)?[6-9\u0966-\u0969]"
    r"(?:[\s().-]*\d){9}(?![A-Za-z0-9])"
)
_AADHAAR = re.compile(r"(?<!\d)(?:\d{12}|\d{4}[\s-]\d{4}[\s-]\d{4})(?!\d)")
_MASKED_AADHAAR = re.compile(r"(?i)(?<!\w)X{4}[\s-]?X{4}[\s-]?\d{4}(?!\w)")
_ABHA = re.compile(r"(?<!\d)\d{2}-\d{4}-\d{4}-\d{4}(?!\d)")
_PAN = re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")
_PREFIXED_RECORD_NUMBER = re.compile(
    r"(?i)(?<![A-Z0-9])(?:UHID|MRN|IPD|OPD|IP)[-_/]"
    r"(?:\d{2}[-_/])?\d{3,}(?:-\d{2,})*(?![A-Z0-9])"
)
_RELATIVE_NAME = re.compile(
    r"(?<!\w)(?i:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|k\s*/\s*c\s*/\s*o|"
    r"son\s+of|daughter\s+of|wife\s+of|husband\s+of|care\s+of|c\s*/\s*o|"
    r"पुत्र|पुत्री|पति|पत्नी)[ \t]*[:：-]?[ \t]*"
    r"(?P<name>(?:[A-Z][A-Za-z'.’\-]*|[\u0900-\u097f]+)"
    r"(?:[ \t]+(?:[A-Z][A-Za-z'.’\-]*|[\u0900-\u097f]+)){0,2})"
)
_NAME_BEFORE_RELATIVE = re.compile(
    r"(?<!\w)(?P<name>(?:[A-Z][A-Za-z'.’\-]*|[\u0900-\u097f]+)"
    r"(?:[ \t]+(?:[A-Z][A-Za-z'.’\-]*|[\u0900-\u097f]+)){0,2})"
    r"[, \t]+(?i:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|k\s*/\s*c\s*/\s*o|"
    r"c\s*/\s*o|son\s+of|daughter\s+of|wife\s+of|husband\s+of)(?!\w)"
)
_HONORIFIC_NAME = re.compile(
    r"(?<!\w)(?P<name>[A-Z][A-Za-z'.’\-]+|[\u0900-\u097f]+)"
    r"[ \t]+(?P<title>(?i:ji|sahab|sahib|didi|behenji|bhai|babu|amma))\b"
)
_PROPER_NAME_SEQUENCE = re.compile(
    r"(?<![\w])(?P<name>[A-Z][a-z]{1,}(?:[ '-][A-Z][a-z]{1,}){1,2})(?![\w])"
)
_CLINICAL_HISTORY = re.compile(
    r"K[ \t]*/[ \t]*C[ \t]*/[ \t]*O"
    r"(?:[ \t]*:[ \t]*[A-Z][0-9]{2}(?:\.[A-Z0-9]{1,4})?"
    r"|[ \t]+(?:HTN[ \t]+on[ \t]+treatment|DM2[ \t]+x[ \t]+[0-9]{1,3}[ \t]+yrs?))"
    r'[ \t]*(?=\r?$|")',
    re.IGNORECASE | re.MULTILINE,
)
_JSON_HISTORY_PREFIX = re.compile(r'"history"[ \t]*:[ \t]*"$', re.IGNORECASE)
_LAB_TEST_TERMS = frozenset({
    "haemoglobin", "hemoglobin", "platelet count", "random blood sugar",
    "serum creatinine", "serum sodium", "total wbc count",
})
_LAB_TEST_KEYS = {"test", "labtest", "testname"}
_JSON_LAB_TEST_PREFIX = re.compile(
    r'"(?:test|lab[ _]?test|test[ _]?name)"[ \t]*:[ \t]*"$', re.IGNORECASE
)
_LAB_UNITS = r"(?:mg/dL|g/dL|mmol/L|mIU/L|/uL|/µL|%)"
_LAB_MEASUREMENT_SUFFIX = re.compile(
    rf"(?:[ \t]+[0-9]+(?:\.[0-9]+)?[ \t]*{_LAB_UNITS}(?=[ \t|,;\r\n]|$)"
    rf"|[,\t](?:[0-9]+(?:\.[0-9]+)?|[0-9]{{1,7}}-[0-9])[,\t]{_LAB_UNITS}(?=[,\t\r\n]|$))",
    re.IGNORECASE,
)
_MEDICATION_PHRASE = re.compile(
    r"(?:continue[ \t]+)?(?:amlodipine|levothyroxine)"
    r"|(?:inh[ \t]+)?salbutamol(?:[ \t]+inhaler)?",
    re.IGNORECASE,
)
_MEDICATION_DOSE_SUFFIX = re.compile(
    r"(?:[ \t]+inhaler)?[ \t]+[0-9]{1,4}(?:\.[0-9]+)?[ \t]*(?:mg|mcg|µg)\b",
    re.IGNORECASE,
)
_NAME_LABELS = (
    "patient full name",
    "patient name",
    "full name",
    "name",
    "patient ka naam",
    "mareez ka naam",
    "naam",
    "रोगी का नाम",
    "मरीज का नाम",
    "नाम",
)
_NAME_VALUE_TOKEN = r"[A-Za-z\u0900-\u097f]+(?:['’\-][A-Za-z\u0900-\u097f]+)*"
_KEY_NAME_VALUE = re.compile(
    r"(?i)(?<![\w])(?:patient(?:[_\s-]+name|name)?|full[_\s-]+name|naam)"
    r"[_:=\s-]+(?P<value>" + _NAME_VALUE_TOKEN
    + r"(?:[_\s-]+" + _NAME_VALUE_TOKEN + r"){0,2})(?![A-Za-z\u0900-\u097f])"
)
_EXTRA_LABELS = (
    ("date of birth", DetectionEntityType.DATE_OF_BIRTH),
    ("birth date", DetectionEntityType.DATE_OF_BIRTH),
    ("janm tithi", DetectionEntityType.DATE_OF_BIRTH),
    ("janam tithi", DetectionEntityType.DATE_OF_BIRTH),
    ("janm tarikh", DetectionEntityType.DATE_OF_BIRTH),
    ("janam tarikh", DetectionEntityType.DATE_OF_BIRTH),
    ("phone number", DetectionEntityType.PHONE),
    ("phone no", DetectionEntityType.PHONE),
    ("mobile number", DetectionEntityType.PHONE),
    ("mobile no", DetectionEntityType.PHONE),
    ("contact number", DetectionEntityType.PHONE),
    ("email address", DetectionEntityType.EMAIL),
    ("insurance id", DetectionEntityType.INSURANCE_ID),
    ("insurance number", DetectionEntityType.INSURANCE_ID),
    ("policy id", DetectionEntityType.INSURANCE_ID),
    ("policy number", DetectionEntityType.INSURANCE_ID),
    ("member id", DetectionEntityType.INSURANCE_ID),
    ("subscriber id", DetectionEntityType.INSURANCE_ID),
    ("aadhaar number", DetectionEntityType.AADHAAR),
    ("aadhar number", DetectionEntityType.AADHAAR),
    ("aadhaar no", DetectionEntityType.AADHAAR),
    ("aadhar no", DetectionEntityType.AADHAAR),
    ("abha number", DetectionEntityType.ABHA),
    ("abha id", DetectionEntityType.ABHA),
    ("abha address", DetectionEntityType.ABHA),
    ("patient id", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("patient identifier", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("hospital id", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("ipd no", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("ipd number", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("opd no", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("opd number", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("case number", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("medical record number", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("registration number", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("registration no", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("reg no", DetectionEntityType.MEDICAL_RECORD_NUMBER),
    ("pin code", DetectionEntityType.PIN_CODE),
    ("postal code", DetectionEntityType.PIN_CODE),
    ("zip code", DetectionEntityType.PIN_CODE),
)
_FIELD_LABELS: tuple[tuple[str, DetectionEntityType], ...] = tuple(
    sorted(
        tuple(
            (label, entity_type)
            for entity_type, labels in _KEY_TYPES.items()
            for label in labels
        )
        + tuple((label, DetectionEntityType.PATIENT_NAME) for label in _NAME_LABELS)
        + _EXTRA_LABELS,
        key=lambda item: len(item[0]),
        reverse=True,
    )
)
_LABEL_ALTERNATIVES = "|".join(
    r"[ \t]+".join(re.escape(part) for part in label.split())
    for label, _ in _FIELD_LABELS
)
_LABEL_PATTERN = re.compile(
    rf"(?im)(?<!\w)(?P<label>{_LABEL_ALTERNATIVES})[ \t]*[:：=][ \t]*"
    rf"(?P<value>[^\r\n,;|]+?)(?=[\r\n,;|]|$|[ \t]+(?:{_LABEL_ALTERNATIVES})[ \t]*[:：=])"
)
_PIN_LABEL = re.compile(
    r"(?i)(?<!\w)(?:pin(?:\s*code)?|postal(?:\s*code)?|zip(?:\s*code)?)"
    r"\s*[:：=#-]?\s*(?P<value>[\d\u0966-\u096f]{6})(?!\d)"
)
_NOTE_ADDRESS_LINE = re.compile(
    r"(?im)^[ \t]*(?:पता|address(?:[ \t]*\([a-z -]{1,30}\))?)"
    r"[ \t]*[:：=][ \t]*(?P<value>[^\r\n]+)"
)
_NOTE_HINDI_RECORD_NUMBERS = re.compile(
    r"(?im)^[ \t]*पंजीकरण[ \t]+सं\.[ \t]*[:：=][ \t]*(?P<registration>[a-z0-9/-]+)"
    r"[ \t]+आईपीडी[ \t]+सं\.[ \t]*[:：=][ \t]*(?P<encounter>[a-z0-9/-]+)[ \t]*(?=\r?$)"
)
_COMPLAINT_OR_CLINICAL_TERMS = {
    "admission",
    "capsule",
    "cap",
    "breathlessness",
    "chest",
    "cold",
    "complaint",
    "cough",
    "diabetes",
    "dizziness",
    "fever",
    "headache",
    "hypertension",
    "hospital",
    "clinic",
    "laboratory",
    "inj",
    "injection",
    "pain",
    "parkinson",
    "rash",
    "syrup",
    "tab",
    "tablet",
    "disease",
    "vomiting",
    "ज्वर",
    "खाँसी",
    "दर्द",
    "बुखार",
}
_RELATIVE_KEYS = frozenset(
    {
        "relative",
        "relativename",
        "fathername",
        "mothername",
        "spousename",
        "guardianname",
    }
)
_NORMALIZED_NAME_KEYS = {_compact_key(key) for key in _NAME_KEYS}
_NORMALIZED_NAME_PART_KEYS = {_compact_key(key) for key in _NAME_PART_KEYS}
_NORMALIZED_RELATIVE_KEYS = {_compact_key(key) for key in _RELATIVE_KEYS}
_KEY_TYPE_LOOKUP = {
    _compact_key(alias): entity_type
    for entity_type, aliases in _KEY_TYPES.items()
    for alias in aliases
}
_LABEL_TYPE_LOOKUP = {
    _compact_key(alias): entity_type for alias, entity_type in _FIELD_LABELS
}


class MultilingualPIIDetector:
    """Find explicit PII patterns and context-labelled patient attributes offline."""

    def detect(
        self,
        record: NormalizedRecord,
        *,
        known_names: Sequence[str] = (),
    ) -> DetectionResult:
        findings: list[DetectionFinding] = []
        seen: set[tuple[object, ...]] = set()
        name_values = [
            value.original
            for identity in record.identities
            for value in identity.name
        ]
        names = tuple(
            dict.fromkeys(
                candidate
                for value in name_values
                if isinstance(value, str)
                and (candidate := _clean_name_candidate(value)) is not None
            )
        )
        file_names = tuple(
            dict.fromkeys(
                names
                + tuple(
                    candidate
                    for value in known_names
                    if isinstance(value, str)
                    and (candidate := _clean_name_candidate(value)) is not None
                )
            )
        )

        self._scan_text(
            record.source.relative_path,
            "@filename",
            DetectionChannel.FILENAME,
            file_names,
            findings,
            seen,
        )
        headers = record.structure.get("headers")
        if isinstance(headers, (tuple, list)):
            for index, header in enumerate(headers):
                if isinstance(header, str):
                    self._scan_text(
                        header,
                        f"@header/{index}",
                        DetectionChannel.HEADER,
                        file_names,
                        findings,
                        seen,
                    )

        stack: list[tuple[object, tuple[str, ...], int]] = [(record.fields, (), 0)]
        visited_nodes = 0
        while stack:
            value, path, depth = stack.pop()
            visited_nodes += 1
            if depth > _MAX_DEPTH:
                raise ProcessingError("detection_structure_depth_exceeded")
            if visited_nodes > _MAX_NODES:
                raise ProcessingError("detection_structure_too_large")

            if isinstance(value, Mapping):
                resource_type = value.get("resourceType")
                context_path = path
                if isinstance(resource_type, str):
                    context_path = path + (resource_type.casefold(),)
                if "identifier" in {_compact_key(part) for part in path}:
                    identifier = value.get("value")
                    if isinstance(identifier, (str, int)) and not isinstance(
                        identifier, bool
                    ):
                        identifier_type = _fhir_identifier_entity_type(value)
                        self._add_typed_value(
                            str(identifier),
                            identifier_type,
                            _source_key(path + ("value",)),
                            DetectionChannel.VALUE,
                            findings,
                            seen,
                        )
                for key, child in value.items():
                    if not isinstance(key, str):
                        continue
                    child_path = context_path + (key,)
                    self._scan_text(
                        key,
                        _source_key(child_path),
                        DetectionChannel.KEY,
                        file_names,
                        findings,
                        seen,
                        context=path,
                    )
                    if visited_nodes + len(stack) >= _MAX_NODES:
                        raise ProcessingError("detection_structure_too_large")
                    stack.append((child, child_path, depth + 1))
                continue

            if isinstance(value, (list, tuple)):
                for index, child in enumerate(value):
                    if visited_nodes + len(stack) >= _MAX_NODES:
                        raise ProcessingError("detection_structure_too_large")
                    stack.append((child, path + (str(index),), depth + 1))
                continue

            if isinstance(value, (str, int, float, Decimal)) and not isinstance(value, bool):
                text = str(value)
                if isinstance(value, str):
                    _reject_printable_base64_payload(value)
                source_key = _source_key(path)
                entity_type = _classify_key(path[-1] if path else "", path[:-1])
                if entity_type is not None:
                    self._add_typed_value(
                        text,
                        entity_type,
                        source_key,
                        DetectionChannel.VALUE,
                        findings,
                        seen,
                        allow_short_identifier=_is_explicit_identifier_source(
                            source_key
                        ),
                    )
                self._scan_text(
                    text,
                    source_key,
                    DetectionChannel.VALUE,
                    names,
                    findings,
                    seen,
                    context=path,
                    key_entity_type=entity_type,
                )

        findings.sort(
            key=lambda finding: (
                finding.channel.value,
                finding.source_key,
                finding.start if finding.start is not None else -1,
                finding.end if finding.end is not None else -1,
                finding.entity_type.value,
            )
        )
        counts: dict[str, int] = {}
        for finding in findings:
            entity_type = finding.entity_type.value
            counts[entity_type] = counts.get(entity_type, 0) + 1
        return DetectionResult(
            identifier_count=len(findings),
            entity_counts=counts,
            findings=tuple(findings),
        )

    def _scan_text(
        self,
        text: str,
        source_key: str,
        channel: DetectionChannel,
        names: tuple[str, ...],
        findings: list[DetectionFinding],
        seen: set[tuple[object, ...]],
        context: tuple[str, ...] = (),
        key_entity_type: DetectionEntityType | None = None,
    ) -> None:
        if _is_non_patient_context(context):
            return
        for match in _EMAIL.finditer(text):
            self._add_match(
                DetectionEntityType.EMAIL, text, match.start(), match.end(),
                source_key, channel, findings, seen,
            )
        for match in _PHONE.finditer(text):
            candidate = match.group()
            if normalize_phone(candidate) is None:
                continue
            if _is_clinician_context(text, match.start()):
                continue
            self._add_match(
                DetectionEntityType.PHONE, text, match.start(), match.end(),
                source_key, channel, findings, seen,
            )
        for match in _MASKED_AADHAAR.finditer(text):
            self._add_match(
                DetectionEntityType.AADHAAR, text, match.start(), match.end(),
                source_key, channel, findings, seen,
            )
        for match in _AADHAAR.finditer(text):
            candidate = match.group()
            if len(_digits_only(candidate)) != 12 or normalize_phone(
                candidate
            ) is not None:
                continue
            self._add_match(
                DetectionEntityType.AADHAAR, text, match.start(), match.end(),
                source_key, channel, findings, seen,
            )
        for match in _ABHA.finditer(text):
            self._add_match(
                DetectionEntityType.ABHA, text, match.start(), match.end(),
                source_key, channel, findings, seen,
            )
        for match in _PAN.finditer(text):
            self._add_match(
                DetectionEntityType.PAN, text, match.start(), match.end(),
                source_key, channel, findings, seen,
            )
        for match in _PREFIXED_RECORD_NUMBER.finditer(text):
            self._add_match(
                DetectionEntityType.MEDICAL_RECORD_NUMBER,
                text, match.start(), match.end(), source_key, channel, findings, seen,
            )
        if channel is DetectionChannel.VALUE:
            for match in _NOTE_ADDRESS_LINE.finditer(text):
                if any(ch.isalnum() for ch in match.group("value")):
                    self._add_match(
                        DetectionEntityType.ADDRESS, text, *match.span("value"),
                        source_key, channel, findings, seen,
                    )
            for match in _NOTE_HINDI_RECORD_NUMBERS.finditer(text):
                for group in ("registration", "encounter"):
                    self._add_match(
                        DetectionEntityType.MEDICAL_RECORD_NUMBER, text, *match.span(group),
                        source_key, channel, findings, seen,
                    )
        for match in _PIN_LABEL.finditer(text):
            self._add_match(
                DetectionEntityType.PIN_CODE,
                text,
                match.start("value"),
                match.end("value"),
                source_key,
                channel,
                findings,
                seen,
            )

        for match in _LABEL_PATTERN.finditer(text):
            label = match.group("label")
            entity_type = _label_type(label)
            if entity_type is None or _is_clinician_context(text, match.start("label")):
                continue
            if entity_type is DetectionEntityType.PATIENT_NAME:
                name_span = _name_prefix_span(match.group("value"))
                if name_span is None:
                    continue
                start = match.start("value") + name_span[0]
                end = match.start("value") + name_span[1]
                candidate = text[start:end]
                if _is_clinical_name(candidate) or (
                    _is_generic_name(candidate)
                    and not _is_explicit_name_label(label)
                ):
                    continue
                self._add_match(
                    entity_type,
                    text,
                    start,
                    end,
                    source_key,
                    channel,
                    findings,
                    seen,
                )
                continue
            self._add_typed_value(
                match.group("value").strip(),
                entity_type,
                source_key,
                channel,
                findings,
                seen,
                offset=match.start("value"),
                allow_short_identifier=_is_explicit_identifier_label(label),
            )

        if not _is_non_patient_context(context):
            for match in _RELATIVE_NAME.finditer(text):
                candidate = match.group("name").strip()
                if (
                    _is_clinical_history(text, match.start())
                    or (
                        match.group(0).lstrip().casefold().startswith("k")
                        and re.search(
                            r"(?i)(?:\bno|\bhistory\s*:)[ \t]+$",
                            text[: match.start()],
                        )
                        is not None
                    )
                    or _is_clinical_name(candidate)
                    or _is_generic_name(candidate)
                ):
                    continue
                self._add_match(
                    DetectionEntityType.RELATIVE_NAME,
                    text,
                    match.start("name"),
                    match.end("name"),
                    source_key,
                    channel,
                    findings,
                    seen,
                )
            for match in _NAME_BEFORE_RELATIVE.finditer(text):
                candidate = match.group("name").strip()
                if (
                    _is_clinician_context(text, match.start("name"))
                    or _is_clinical_name(candidate)
                    or _is_generic_name(candidate)
                    or _is_missing(candidate)
                    or _compact_key(candidate) in {"no", "known", "history"}
                ):
                    continue
                self._add_match(
                    DetectionEntityType.PATIENT_NAME,
                    text,
                    match.start("name"),
                    match.end("name"),
                    source_key,
                    channel,
                    findings,
                    seen,
                )
            for match in _HONORIFIC_NAME.finditer(text):
                if _is_clinician_context(text, match.start("name")):
                    continue
                if _is_generic_name(match.group("name")):
                    continue
                self._add_match(
                    DetectionEntityType.PATIENT_NAME,
                    text,
                    match.start(),
                    match.end() if match.group("title").casefold() in {"bhai", "babu", "amma"} else match.end("name"),
                    source_key,
                    channel,
                    findings,
                    seen,
                )
            if (
                channel is DetectionChannel.VALUE
                and key_entity_type is not DetectionEntityType.LOCATION
            ):
                for match in _PROPER_NAME_SEQUENCE.finditer(text):
                    candidate = match.group("name")
                    if (
                        _is_clinician_context(text, match.start("name"))
                        or _is_clinical_name(candidate)
                        or _is_generic_name(candidate)
                        or _is_clinical_phrase(
                            text, match.start("name"), match.end("name"), context
                        )
                        or _compact_key(candidate)
                        in {"patientname", "patientfullname", "fullname"}
                    ):
                        continue
                    self._add_match(
                        DetectionEntityType.PATIENT_NAME,
                        text,
                        match.start("name"),
                        match.end("name"),
                        source_key,
                        channel,
                        findings,
                        seen,
                    )
            self._find_known_names(
                text, source_key, channel, names, findings, seen
            )
        if channel is DetectionChannel.FILENAME or (
            channel in {DetectionChannel.KEY, DetectionChannel.HEADER}
            and _compact_key(text) != "patientref"
        ):
            for match in _KEY_NAME_VALUE.finditer(text):
                candidate = text[match.start("value") : match.end("value")]
                if _is_clinical_name(candidate) or _is_generic_name(candidate):
                    continue
                self._add_match(
                    DetectionEntityType.PATIENT_NAME,
                    text,
                    match.start("value"),
                    match.end("value"),
                    source_key,
                    channel,
                    findings,
                    seen,
                )

    def _find_known_names(
        self,
        text: str,
        source_key: str,
        channel: DetectionChannel,
        names: tuple[str, ...],
        findings: list[DetectionFinding],
        seen: set[tuple[object, ...]],
    ) -> None:
        if not names:
            return
        tokens = _token_spans(text)
        names_by_width: dict[int, set[str]] = {}
        for name in names:
            name_tokens = _token_spans(name)
            if not name_tokens or (
                len(name_tokens) < 2
                and channel not in {
                    DetectionChannel.HEADER,
                    DetectionChannel.FILENAME,
                    DetectionChannel.KEY,
                }
            ):
                continue
            names_by_width.setdefault(len(name_tokens), set()).add(normalize_name(name))
        for width, normalized_names in names_by_width.items():
            for index in range(len(tokens) - width + 1):
                start = tokens[index][0]
                end = tokens[index + width - 1][1]
                candidate = normalize_name(text[start:end])
                if candidate and candidate in normalized_names and not _is_clinician_context(text, start):
                    self._add_match(
                        DetectionEntityType.PATIENT_NAME,
                        text,
                        start,
                        end,
                        source_key,
                        channel,
                        findings,
                        seen,
                    )

    def _add_typed_value(
        self,
        value: str,
        entity_type: DetectionEntityType,
        source_key: str,
        channel: DetectionChannel,
        findings: list[DetectionFinding],
        seen: set[tuple[object, ...]],
        offset: int = 0,
        allow_short_identifier: bool = False,
    ) -> None:
        cleaned = value.strip()
        if _is_missing(cleaned):
            return
        valid = True
        name_span: tuple[int, int] | None = None
        if entity_type is DetectionEntityType.PATIENT_NAME:
            name_span = _name_prefix_span(cleaned)
            valid = name_span is not None
            if valid and name_span is not None:
                candidate = cleaned[name_span[0] : name_span[1]]
                valid = not _is_clinical_name(candidate) and (
                    not _is_generic_name(candidate)
                    or _is_explicit_name_source(source_key)
                )
                cleaned = candidate
        elif entity_type is DetectionEntityType.DATE_OF_BIRTH:
            valid = normalize_date(cleaned) is not None
        elif entity_type is DetectionEntityType.AGE:
            valid = normalize_age(cleaned) is not None
        elif entity_type is DetectionEntityType.GENDER:
            valid = normalize_gender(cleaned) is not None
        elif entity_type is DetectionEntityType.PHONE:
            valid = normalize_phone(cleaned) is not None
        elif entity_type is DetectionEntityType.EMAIL:
            valid = _EMAIL.search(cleaned) is not None
        elif entity_type is DetectionEntityType.PIN_CODE:
            valid = len(_digits_only(cleaned)) == 6
        elif entity_type is DetectionEntityType.AADHAAR:
            valid = len(_digits_only(cleaned)) == 12 or (
                _MASKED_AADHAAR.fullmatch(cleaned) is not None
            )
        elif entity_type is DetectionEntityType.ABHA:
            valid = _ABHA.fullmatch(cleaned) is not None or (
                "@" in cleaned and "abdm" in cleaned.casefold()
            )
        elif entity_type is DetectionEntityType.PAN:
            valid = _PAN.fullmatch(cleaned) is not None
        elif entity_type in {
            DetectionEntityType.MEDICAL_RECORD_NUMBER,
            DetectionEntityType.INSURANCE_ID,
            DetectionEntityType.OTHER_IDENTIFIER,
        }:
            valid = (allow_short_identifier or len(cleaned) >= 4) and any(
                character.isalnum() for character in cleaned
            )
        if not valid:
            return
        start = offset + len(value) - len(value.lstrip())
        if name_span is not None:
            start += name_span[0]
        end = start + len(cleaned)
        self._add(
            entity_type,
            cleaned,
            source_key,
            channel,
            start,
            end,
            findings,
            seen,
        )

    def _add_match(
        self,
        entity_type: DetectionEntityType,
        text: str,
        start: int,
        end: int,
        source_key: str,
        channel: DetectionChannel,
        findings: list[DetectionFinding],
        seen: set[tuple[object, ...]],
    ) -> None:
        self._add(
            entity_type,
            text[start:end],
            source_key,
            channel,
            start,
            end,
            findings,
            seen,
        )

    def _add(
        self,
        entity_type: DetectionEntityType,
        value: str,
        source_key: str,
        channel: DetectionChannel,
        start: int,
        end: int,
        findings: list[DetectionFinding],
        seen: set[tuple[object, ...]],
    ) -> None:
        key = (entity_type, value, source_key, channel, start, end)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            DetectionFinding(
                entity_type=entity_type,
                value=value,
                source_key=source_key,
                channel=channel,
                start=start,
                end=end,
            )
        )


def _classify_key(key: str, context: tuple[str, ...]) -> DetectionEntityType | None:
    normalized_key = _compact_key(key)
    normalized_context = {_compact_key(part) for part in context}
    if normalized_key in _NORMALIZED_NAME_KEYS and normalized_context & {
        "contact",
        "guardian",
        "relative",
        "nextofkin",
    }:
        return DetectionEntityType.RELATIVE_NAME
    if _is_non_patient_context(context):
        return None
    if normalized_key in _NORMALIZED_RELATIVE_KEYS:
        return DetectionEntityType.RELATIVE_NAME
    if normalized_key == "id" and normalized_context & {
        "patient",
        "person",
        "beneficiary",
        "subject",
    }:
        return DetectionEntityType.MEDICAL_RECORD_NUMBER
    if normalized_key in _NORMALIZED_NAME_KEYS:
        return DetectionEntityType.PATIENT_NAME
    if normalized_key in _NORMALIZED_NAME_PART_KEYS and (
        not context
        or {"name", "patient", "person", "beneficiary", "subject"}
        & normalized_context
    ):
        return DetectionEntityType.PATIENT_NAME
    return _KEY_TYPE_LOOKUP.get(normalized_key)


def _label_type(label: str) -> DetectionEntityType | None:
    return _LABEL_TYPE_LOOKUP.get(_compact_key(label))


def _is_explicit_name_label(label: str) -> bool:
    return _compact_key(label) in {
        "patientname",
        "patientfullname",
        "fullname",
        "personname",
        "patientnaam",
        "patientkanam",
        "mareezkanam",
        "रोगीकानाम",
        "मरीजकानाम",
    }


def _is_explicit_name_source(source_key: str) -> bool:
    return any(
        _is_explicit_name_label(part)
        for part in re.split(r"[./]", source_key)
    )


def _is_explicit_identifier_label(label: str) -> bool:
    return _compact_key(label) in {
        "patientid",
        "patientidentifier",
        "patientref",
        "hospitalid",
        "hospitalpatientid",
        "uhid",
        "mrn",
        "medicalrecordnumber",
        "registrationnumber",
        "registrationno",
        "regno",
        "registrationid",
        "ipdno",
        "ipdnumber",
        "opdno",
        "opdnumber",
        "caseid",
        "casenumber",
        "mareezid",
        "रोगीआईडी",
    }


def _is_explicit_identifier_source(source_key: str) -> bool:
    return any(
        _is_explicit_identifier_label(part)
        for part in re.split(r"[./]", source_key)
    )


def _is_non_patient_context(context: tuple[str, ...]) -> bool:
    return any(_compact_key(part) in _NON_PATIENT_CONTEXTS for part in context)


def _is_clinician_context(text: str, position: int) -> bool:
    line_start = max(text.rfind("\n", 0, position), text.rfind("\r", 0, position)) + 1
    prefix = text[line_start:position].casefold()
    pattern = r"(?:\bdr\.?|\bdoctor|\bphysician|\bpractitioner)\s*$"
    return re.search(pattern, prefix) is not None


def _is_clinical_name(value: str) -> bool:
    return any(
        _compact_key(value[start:end]) in _COMPLAINT_OR_CLINICAL_TERMS
        for start, end in _token_spans(value)
    )


def _is_clinical_phrase(
    text: str, start: int, end: int, context: tuple[str, ...]
) -> bool:
    candidate = text[start:end]
    if candidate.casefold() in _LAB_TEST_TERMS:
        if context and _compact_key(context[-1]) in _LAB_TEST_KEYS:
            return text.strip() == candidate
        if text.startswith('"', end) and _JSON_LAB_TEST_PREFIX.search(
            text, max(0, start - 64), start
        ):
            return True
        if _LAB_MEASUREMENT_SUFFIX.match(text, end):
            return start == 0 or text[start - 1] in " \t,|\n"
    return bool(
        _MEDICATION_PHRASE.fullmatch(candidate)
        and _MEDICATION_DOSE_SUFFIX.match(text, end)
    )


def _is_clinical_history(text: str, start: int) -> bool:
    match = _CLINICAL_HISTORY.match(text, start)
    if match is None:
        return False
    if text.startswith('"', match.end()):
        return bool(_JSON_HISTORY_PREFIX.search(text, max(0, start - 64), start))
    return start == 0 or text[start - 1] == "\n"


def _is_generic_name(value: str) -> bool:
    tokens = _token_spans(value)
    return len(tokens) == 1 and _compact_key(value[tokens[0][0] : tokens[0][1]]) in {
        "address",
        "devi",
        "dob",
        "email",
        "gender",
        "id",
        "ji",
        "kumar",
        "md",
        "mobile",
        "name",
        "phone",
        "patient",
        "uhid",
    }


def _is_missing(value: str) -> bool:
    return _compact_key(value) in _MISSING_KEYS


def _source_key(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else "record"


def _ascii_digits(value: str) -> str:
    return "".join(
        str(unicodedata.digit(character)) if character.isdecimal() else character
        for character in value
    )


def _digits_only(value: str) -> str:
    return "".join(
        character
        for character in _ascii_digits(value)
        if character.isdecimal()
    )


def _name_prefix_span(value: str) -> tuple[int, int] | None:
    tokens = _token_spans(value)
    if not tokens:
        return None
    words = [value[start:end] for start, end in tokens]
    if _compact_key(words[0]) in {"dr", "doctor", "physician", "practitioner"}:
        return None
    stop_words = {
        "admitted",
        "aadhaar",
        "aadhar",
        "abha",
        "and",
        "address",
        "bp",
        "complaint",
        "diagnosis",
        "dob",
        "disease",
        "email",
        "fever",
        "for",
        "gender",
        "age",
        "birth",
        "is",
        "ka",
        "ke",
        "ki",
        "mobile",
        "mrn",
        "pain",
        "parkinson",
        "phone",
        "presents",
        "reviewed",
        "uhid",
        "village",
        "was",
        "with",
    }
    end_index = len(tokens)
    for index, word in enumerate(words):
        normalized = _compact_key(word)
        if normalized in stop_words or normalized in {
            "ji",
            "sahab",
            "sahib",
            "didi",
            "behenji",
        }:
            end_index = index
            break
        if any(character.isdigit() for character in word):
            end_index = index
            break
        if index == 4:
            end_index = index
            break
    if end_index == 0:
        return None
    return tokens[0][0], tokens[end_index - 1][1]


def _clean_name_candidate(value: str) -> str | None:
    candidate = re.split(r"[,;|\r\n]", value, maxsplit=1)[0].strip()
    span = _name_prefix_span(candidate)
    if span is None:
        return None
    return candidate[span[0] : span[1]]


def _fhir_identifier_entity_type(
    identifier: Mapping[str, object],
) -> DetectionEntityType:
    context: list[str] = []
    system = identifier.get("system")
    if isinstance(system, str):
        context.append(system.casefold())
    identifier_type = identifier.get("type")
    if isinstance(identifier_type, Mapping):
        text = identifier_type.get("text")
        if isinstance(text, str):
            context.append(text.casefold())
        coding = identifier_type.get("coding")
        if isinstance(coding, list):
            for item in coding:
                if isinstance(item, Mapping):
                    context.extend(
                        value.casefold()
                        for value in (
                            item.get("code"),
                            item.get("display"),
                            item.get("system"),
                        )
                        if isinstance(value, str)
                    )
    combined = " ".join(context)
    if any(term in combined for term in ("aadhaar", "aadhar")):
        return DetectionEntityType.AADHAAR
    if "abha" in combined:
        return DetectionEntityType.ABHA
    if "pan" in combined:
        return DetectionEntityType.PAN
    if any(term in combined for term in ("insurance", "policy", "coverage")):
        return DetectionEntityType.INSURANCE_ID
    if any(term in combined for term in ("mrn", "uhid", "hospital", "patient")):
        return DetectionEntityType.MEDICAL_RECORD_NUMBER
    return DetectionEntityType.OTHER_IDENTIFIER


def _token_spans(value: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start: int | None = None
    for index, character in enumerate(value):
        category = unicodedata.category(character)
        is_word_character = character.isalnum() or category.startswith("M")
        if is_word_character:
            if start is None:
                start = index
        elif start is not None:
            spans.append((start, index))
            start = None
    if start is not None:
        spans.append((start, len(value)))
    return spans


__all__ = ["MultilingualPIIDetector"]
