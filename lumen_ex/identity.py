"""Identity attribute extraction from already-parsed records and labeled notes.

This module deliberately does not read files, infer unlabeled free-text names, or
decide whether two identity projections belong to the same person.
"""

from collections.abc import Mapping
from datetime import date, datetime
import re
import unicodedata
from typing import TypeAlias

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat

from lumen_ex.contracts.identity import IdentityValue, PatientIdentity
from lumen_ex.contracts.models import (
    InputFormat,
    NormalizedRecord,
    ParsedRecord,
)
from lumen_ex.detection.indic_names import normalize_name, transliterate_to_latin
from lumen_ex.errors import ProcessingError
from lumen_ex.value_normalization import normalize_age, normalize_date


_FIELD_NAMES = (
    "name",
    "relative_name",
    "date_of_birth",
    "age",
    "gender",
    "phone",
    "email",
    "address",
    "location",
    "hospital_identifier",
    "insurance_identifier",
    "government_identifier",
)
_SOURCE_SYSTEM_KEYS = frozenset(
    {
        "facilitycode",
        "facilityid",
        "facilityissuer",
        "facilityname",
        "facilitynamespace",
        "healthcarefacilityid",
        "healthcareproviderid",
        "hospitalcode",
        "hospitalissuer",
        "hospitalname",
        "hospitalnamespace",
        "identifiernamespace",
        "identifiersystem",
        "issuer",
        "issuingsystem",
        "issuingauthority",
        "organizationid",
        "organizationname",
        "organisationid",
        "organisationname",
        "providerid",
        "providersystem",
        "sourcefacility",
        "sourcefacilityid",
        "sourcehospital",
        "sourcehospitalid",
        "sourceissuer",
        "sourcenamespace",
        "sourcesystem",
    }
)
_SOURCE_CONTEXTS = frozenset(
    {
        "facility",
        "identifier",
        "issuer",
        "organization",
        "organisation",
        "provider",
        "source",
    }
)
_NON_SOURCE_CONTEXTS = frozenset({"coverage", "insurance", "payer", "policy"})
_MAX_DEPTH = 24
_MISSING_WORDS = {"", "n/a", "na", "nil", "none", "null", "unknown", "-", "--"}
_WORD_SEPARATORS = re.compile(r"[^\w]+", re.UNICODE)
_RELATIVE_NAME = re.compile(
    r"(?i)\b(?P<marker>s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|c\s*/\s*o)"
    r"\s*[:=\-]?\s*(?P<name>[^,;\r\n]+)"
)
_RELATIVE_CLINICAL_TERMS = frozenset(
    {
        "abdominal",
        "bleeding",
        "bp",
        "chest",
        "complaint",
        "cough",
        "diagnosis",
        "disease",
        "fever",
        "fracture",
        "headache",
        "hypertension",
        "injury",
        "pain",
        "symptom",
        "vomiting",
        "weakness",
        "wound",
    }
)
_EMAIL = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$",
    re.IGNORECASE,
)
_PHONE_PUNCTUATION = frozenset(" +-()./")
_ID_PUNCTUATION = re.compile(r"[\s./-]+")
_ALIASES: dict[str, frozenset[str]] = {
    "name": frozenset(
        {
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
        }
    ),
    "relative_name": frozenset(
        {
            "relativename",
            "fathername",
            "mothername",
            "husbandname",
            "wifename",
            "spousename",
        }
    ),
    "date_of_birth": frozenset(
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
    "age": frozenset({"age", "patientage", "umar", "umr", "उम्र", "आयु"}),
    "gender": frozenset({"gender", "sex", "patientgender", "ling", "लिंग"}),
    "phone": frozenset(
        {
            "phone",
            "phonenumber",
            "mobile",
            "mobilenumber",
            "contactnumber",
            "telephone",
            "telephonenumber",
            "phoneno",
            "mobileno",
            "samparknumber",
            "फोन",
            "मोबाइल",
        }
    ),
    "email": frozenset({"email", "emailaddress", "patientemail", "mailaddress"}),
    "address": frozenset(
        {"address", "patientaddress", "pata", "gharkapata", "पता"}
    ),
    "location": frozenset(
        {
            "city",
            "village",
            "tehsil",
            "district",
            "state",
            "location",
            "postalcode",
            "zipcode",
            "pin",
            "pincode",
            "gaon",
            "jila",
            "zilla",
            "shehar",
            "गाँव",
            "जिला",
        }
    ),
    "hospital_identifier": frozenset(
        {
            "patientid",
            "patientidentifier",
            "hospitalid",
            "hospitalpatientid",
            "uhid",
            "mrn",
            "medicalrecordnumber",
            "registrationnumber",
            "mareezid",
            "रोगीआईडी",
        }
    ),
    "insurance_identifier": frozenset(
        {
            "insuranceid",
            "insuranceidentifier",
            "insurancenumber",
            "insurancepolicynumber",
            "policyid",
            "policynumber",
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
    "government_identifier": frozenset(
        {
            "aadhaar",
            "aadhar",
            "aadhaarno",
            "aadharno",
            "aadhaarnumber",
            "aadharnumber",
            "abha",
            "abhanumber",
            "abhaaddress",
            "pan",
            "governmentid",
            "nationalid",
            "healthid",
            "आधार",
        }
    ),
}
_NAME_PARTS = {
    "firstname",
    "given",
    "givenname",
    "lastname",
    "family",
    "familyname",
    "surname",
}
_EXCLUDED_NAME_CONTEXTS = {
    "author",
    "contact",
    "doctor",
    "facility",
    "guardian",
    "practitioner",
    "relative",
    "staff",
}
_NON_PATIENT_CONTEXTS = {
    "author",
    "doctor",
    "facility",
    "guardian",
    "practitioner",
    "staff",
}
_NOTE_LABELS: dict[str, tuple[str, ...]] = {
    "name": (
        "patient name",
        "full name",
        r"name",
        "naam",
        "patient ka naam",
        "mareez ka naam",
        "रोगी का नाम",
        "मरीज का नाम",
        "नाम",
    ),
    "relative_name": (
        "relative name",
        "father name",
        "mother name",
        "husband name",
        "wife name",
        "spouse name",
        "s/o",
        "d/o",
        "w/o",
        "c/o",
    ),
    "date_of_birth": (
        "date of birth",
        "birth date",
        "dob",
        "janm tithi",
        "janam tithi",
        "janm tarikh",
        "janam tarikh",
        "जन्म तिथि",
    ),
    "age": ("age", "umar", "umr", "उम्र", "आयु"),
    "gender": ("gender", "sex", "ling", "लिंग"),
    "phone": (
        "phone number",
        "phone no",
        "phone",
        "mobile number",
        "mobile no",
        "mobile",
        "contact number",
        "sampark number",
        "फोन",
        "मोबाइल",
    ),
    "email": ("email", "email address", "e-mail"),
    "address": ("address", "pata", "ghar ka pata", "पता"),
    "location": (
        "village",
        "gaon",
        "district",
        "jila",
        "zilla",
        "tehsil",
        "city",
        "shehar",
        "location",
        "गाँव",
        "जिला",
    ),
    "hospital_identifier": (
        "patient id",
        "mareez id",
        "uhid",
        "mrn",
        "hospital id",
        "registration number",
    ),
    "insurance_identifier": (
        "insurance id",
        "insurance number",
        "policy id",
        "policy number",
        "bima id",
        "bima number",
    ),
    "government_identifier": (
        "aadhaar",
        "aadhar",
        "abha number",
        "abha",
        "pan",
        "आधार",
    ),
}
_NOTE_LABEL_ALTERNATIVES = sorted(
    (
        (label, field_name)
        for field_name, labels in _NOTE_LABELS.items()
        for label in labels
    ),
    key=lambda item: len(item[0]),
    reverse=True,
)
_NOTE_PATTERN = re.compile(
    r"(?im)^\s*(?P<label>"
    + "|".join(
        r"\s+".join(re.escape(part) for part in label.split())
        for label, _ in _NOTE_LABEL_ALTERNATIVES
    )
    + r")\s*[:：=\-]\s*(?P<value>[^\r\n]+)"
)
_NOTE_LABEL_LOOKUP = {
    re.sub(r"[^\w]+", "", label.casefold()): field_name
    for label, field_name in _NOTE_LABEL_ALTERNATIVES
}

IdentityInput: TypeAlias = Mapping[str, object] | str


def normalize_phone(value: str) -> str | None:
    """Return valid Indian phone numbers as +91 E.164, or None when invalid."""
    normalized = unicodedata.normalize("NFKC", value).strip()
    ascii_number = _ascii_digits(normalized)
    if not ascii_number or any(
        not character.isdecimal() and character not in _PHONE_PUNCTUATION
        for character in ascii_number
    ):
        return None
    try:
        parsed = phonenumbers.parse(ascii_number, "IN")
    except NumberParseException:
        return None
    if parsed.country_code != 91 or not phonenumbers.is_valid_number(parsed):
        return None
    return phonenumbers.format_number(parsed, PhoneNumberFormat.E164)


def normalize_gender(value: str) -> str | None:
    """Map common sex/gender values to a small, explicit vocabulary."""
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    values = {
        "m": "male",
        "male": "male",
        "man": "male",
        "पुरुष": "male",
        "purush": "male",
        "mard": "male",
        "f": "female",
        "female": "female",
        "woman": "female",
        "महिला": "female",
        "mahila": "female",
        "स्त्री": "female",
        "stri": "female",
        "stree": "female",
        "other": "other",
        "non-binary": "other",
        "non binary": "other",
        "nonbinary": "other",
        "o": "other",
        "unknown": "unknown",
        "u": "unknown",
        "undifferentiated": "unknown",
    }
    return values.get(normalized)


def normalize_identifier(value: str) -> str | None:
    """Normalize identifier case and separators without changing its digits."""
    normalized = unicodedata.normalize("NFKC", value).strip().upper()
    if not normalized:
        return None
    ascii_digits = _ascii_digits(normalized)
    return _ID_PUNCTUATION.sub("", ascii_digits)


def normalize_email(value: str) -> str | None:
    """Return a validated, case-folded email address or None."""
    normalized = unicodedata.normalize("NFKC", value).strip()
    if len(normalized) > 254 or _EMAIL.fullmatch(normalized) is None:
        return None
    return normalized.casefold()


def normalize_location(value: str) -> str:
    """Normalize a location's script, case, whitespace, and punctuation."""
    text = transliterate_to_latin(unicodedata.normalize("NFKC", value)).casefold()
    return " ".join(part for part in _WORD_SEPARATORS.split(text) if part)


def extract_identity(
    record: IdentityInput,
    source_file: str,
    record_locator: str = "doc",
) -> PatientIdentity:
    """Project one parsed row/object or labeled note into identity-only values."""
    source_system: str | None = None
    if isinstance(record, str):
        candidates = _extract_note_values(record)
    elif isinstance(record, Mapping):
        if record.get("resourceType") == "Patient":
            candidates = _extract_fhir_patient(record)
            source_system = _single_identifier_namespace(candidates)
        else:
            candidates = _extract_mapping_values(record)
            source_system = _extract_source_system(record)
    else:
        raise TypeError("identity_record_type_invalid")

    return _build_identity(
        candidates, source_file, record_locator, source_system
    )


class PatientIdentityNormalizer:
    """Attach identity projections while preserving parsed clinical source values."""

    def normalize(self, record: ParsedRecord) -> NormalizedRecord:
        values = record.values
        fields = dict(values) if isinstance(values, Mapping) else {"value": values}
        if record.source.detected_format is InputFormat.FHIR and isinstance(values, Mapping):
            identities = extract_fhir_identities(
                values,
                record.source.relative_path,
                record.locator,
            )
        elif record.source.detected_format is InputFormat.TEXT and isinstance(
            values, Mapping
        ) and isinstance(values.get("text"), str):
            identities = (
                extract_identity(
                    values["text"],
                    record.source.relative_path,
                    record.locator,
                ),
            )
        elif isinstance(values, Mapping):
            identities = (
                extract_identity(
                    values,
                    record.source.relative_path,
                    record.locator,
                ),
            )
        elif isinstance(values, str):
            identities = (
                extract_identity(
                    values,
                    record.source.relative_path,
                    record.locator,
                ),
            )
        else:
            identities = ()

        return NormalizedRecord(
            source=record.source,
            locator=record.locator,
            fields=fields,
            identities=identities,
            structure=dict(record.structure),
        )


def extract_fhir_identities(
    resource: Mapping[str, object],
    source_file: str,
    record_locator: str = "doc",
) -> tuple[PatientIdentity, ...]:
    """Extract one identity per Patient resource in a FHIR R4 resource or Bundle."""
    if resource.get("resourceType") == "Patient":
        return (extract_identity(resource, source_file, record_locator),)
    if resource.get("resourceType") != "Bundle":
        return ()

    identities: list[PatientIdentity] = []
    entries = resource.get("entry")
    if not isinstance(entries, list):
        return ()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        nested_resource = entry.get("resource")
        if not isinstance(nested_resource, Mapping) or nested_resource.get("resourceType") != "Patient":
            continue
        identities.append(
            extract_identity(
                nested_resource,
                source_file,
                f"{record_locator.rstrip('/')}/entry/{index}/resource"
                if record_locator != "doc"
                else f"/entry/{index}/resource",
            )
        )
    return tuple(identities)


def _build_identity(
    candidates: Mapping[str, list[tuple[object, str, str | None]]],
    source_file: str,
    record_locator: str,
    source_system: str | None = None,
) -> PatientIdentity:
    normalizers = {
        "name": _normalize_name,
        "relative_name": _normalize_name,
        "date_of_birth": _normalize_date_value,
        "age": _normalize_age_value,
        "gender": _normalize_gender_value,
        "phone": _normalize_phone_value,
        "email": _normalize_email_value,
        "address": _normalize_address_value,
        "location": _normalize_location_value,
        "hospital_identifier": _normalize_identifier_value,
        "insurance_identifier": _normalize_identifier_value,
        "government_identifier": _normalize_identifier_value,
    }
    values: dict[str, tuple[IdentityValue, ...]] = {}
    invalid: set[str] = set()
    for field_name in _FIELD_NAMES:
        field_values: list[IdentityValue] = []
        seen: set[tuple[str, str, str | None]] = set()
        for raw, source_key, value_namespace in candidates.get(field_name, []):
            original = _scalar_text(raw)
            if original is None or original.strip().casefold() in _MISSING_WORDS:
                continue
            normalized = normalizers[field_name](raw)
            if normalized is None:
                invalid.add(field_name)
            namespace = (
                value_namespace or source_system
                if field_name == "hospital_identifier"
                else None
            )
            unique_key = (original, source_key, namespace)
            if unique_key not in seen:
                seen.add(unique_key)
                field_values.append(
                    IdentityValue(
                        original,
                        normalized,
                        source_key,
                        namespace=namespace,
                    )
                )
        values[field_name] = tuple(field_values)

    metadata = (
        ("schema", "patient-identity/1"),
        ("name_normalization", "indic-transliteration ITRANS; order and initials retained"),
        ("date_policy", "ISO output; ambiguous numeric dates are invalid unless source-specific parsing is added"),
    )
    return PatientIdentity(
        source_file=source_file,
        record_locator=record_locator,
        **values,
        missing_fields=frozenset(
            field_name for field_name, field_values in values.items() if not field_values
        ),
        invalid_fields=frozenset(invalid),
        normalization_metadata=metadata,
        source_system=source_system,
    )


def _extract_mapping_values(
    record: Mapping[str, object],
) -> dict[str, list[tuple[object, str, str | None]]]:
    candidates = _empty_candidates()
    stack: list[tuple[object, tuple[str, ...], int]] = [(record, (), 0)]
    while stack:
        value, path, depth = stack.pop()
        if depth > _MAX_DEPTH:
            raise ProcessingError("identity_structure_depth_exceeded")
        if isinstance(value, Mapping):
            for key, child in value.items():
                if not isinstance(key, str):
                    continue
                child_path = path + (key,)
                stack.append((child, child_path, depth + 1))
            continue
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                stack.append((child, path + (str(index),), depth + 1))
            continue
        if _scalar_text(value) is None:
            continue
        _collect_mapping_scalar(candidates, path, value)
    _append_combined_name_parts(candidates)
    return candidates


def _append_combined_name_parts(
    candidates: dict[str, list[tuple[object, str, str | None]]],
) -> None:
    grouped: dict[str, dict[str, list[tuple[str, str]]]] = {}
    given_parts = {"firstname", "given", "givenname"}
    family_parts = {"lastname", "family", "familyname", "surname"}
    for raw, source_key, _ in candidates["name"]:
        parts = source_key.split(".")
        key = _key_name(parts[-1])
        role = "given" if key in given_parts else "family" if key in family_parts else None
        group_parts = parts[:-1]
        if key.isdecimal() and len(parts) > 1 and _key_name(parts[-2]) == "given":
            role = "given"
            group_parts = parts[:-2]
        if role is None:
            continue
        grouped.setdefault(".".join(group_parts), {"given": [], "family": []})[role].append(
            (source_key, str(raw).strip())
        )

    for group, parts in grouped.items():
        if not parts["given"] or not parts["family"]:
            continue
        given = " ".join(value for _, value in sorted(parts["given"]))
        family = " ".join(value for _, value in sorted(parts["family"]))
        _append(candidates, "name", f"{given} {family}", group or "name_parts")


def _collect_mapping_scalar(
    candidates: dict[str, list[tuple[object, str, str | None]]],
    path: tuple[str, ...],
    value: object,
) -> None:
    key = _key_name(path[-1])
    contexts = {_key_name(part) for part in path[:-1]}
    field_name = next(
        (name for name, aliases in _ALIASES.items() if key in aliases),
        None,
    )
    relative_contexts = {
        "relative",
        "nextofkin",
        "father",
        "mother",
        "husband",
        "wife",
        "spouse",
    }
    if contexts & relative_contexts:
        if field_name in {"name", "relative_name"} or key in _NAME_PARTS:
            _append(candidates, "relative_name", value, ".".join(path))
        return
    if contexts & _NON_PATIENT_CONTEXTS:
        return

    if field_name == "name":
        if contexts & _EXCLUDED_NAME_CONTEXTS:
            return
        _append(candidates, "name", value, ".".join(path))
    elif key in _NAME_PARTS and not contexts & _EXCLUDED_NAME_CONTEXTS and (
        "name" in contexts or not contexts or contexts & {"patient", "person", "beneficiary", "subject"}
    ):
        _append(candidates, "name", value, ".".join(path))
    elif "name" in contexts and key.isdecimal() and not contexts & _EXCLUDED_NAME_CONTEXTS:
        _append(candidates, "name", value, ".".join(path))
    elif field_name in {
        "date_of_birth",
        "age",
        "gender",
        "phone",
        "email",
        "address",
        "location",
        "hospital_identifier",
        "insurance_identifier",
        "government_identifier",
        "relative_name",
    }:
        if field_name == "address" and contexts & {"contact", "telecom"}:
            return
        _append(candidates, field_name, value, ".".join(path))
    elif key in {"line", "street", "streetaddress", "house"} and "address" in contexts:
        _append(candidates, "address", value, ".".join(path))
    elif key.isdecimal() and "address" in contexts:
        _append(candidates, "address", value, ".".join(path))


def _extract_fhir_patient(
    patient: Mapping[str, object],
) -> dict[str, list[tuple[object, str, str | None]]]:
    candidates = _empty_candidates()
    for index, name in enumerate(_as_mappings(patient.get("name"))):
        path = f"name/{index}"
        _append_if_scalar(candidates, "name", name.get("text"), path + "/text")
        given = name.get("given")
        given_values = [value for value in given if _scalar_text(value) is not None] if isinstance(given, list) else []
        family = name.get("family")
        parts = given_values + ([family] if _scalar_text(family) is not None else [])
        if parts:
            combined = " ".join(str(part).strip() for part in parts)
            _append(candidates, "name", combined, path)
        for part_index, part in enumerate(parts):
            _append(candidates, "name", part, f"{path}/part/{part_index}")

    for key, field_name in (("gender", "gender"), ("birthDate", "date_of_birth")):
        _append_if_scalar(candidates, field_name, patient.get(key), key)

    for identifier_index, identifier in enumerate(_as_mappings(patient.get("identifier"))):
        value = identifier.get("value")
        if _scalar_text(value) is None:
            continue
        raw_system = identifier.get("system")
        system = str(raw_system or "").casefold()
        type_text = _fhir_identifier_type(identifier.get("type"))
        identifier_context = f"{system} {type_text}"
        if any(word in identifier_context for word in ("insurance", "policy", "coverage")):
            target = "insurance_identifier"
        elif any(
            word in identifier_context
            for word in ("aadhaar", "aadhar", "abha", "pan", "national", "government")
        ):
            target = "government_identifier"
        else:
            target = "hospital_identifier"
        namespace = (
            _normalize_source_system(raw_system)
            if target == "hospital_identifier"
            and isinstance(raw_system, str)
            else None
        )
        _append(
            candidates,
            target,
            value,
            f"identifier/{identifier_index}/value",
            namespace=namespace,
        )

    for index, telecom in enumerate(_as_mappings(patient.get("telecom"))):
        system = str(telecom.get("system", "")).casefold()
        if system in {"phone", "email"}:
            _append_if_scalar(
                candidates,
                system,
                telecom.get("value"),
                f"telecom/{index}/value",
            )

    for index, address in enumerate(_as_mappings(patient.get("address"))):
        parts: list[str] = []
        for key in ("line", "city", "district", "state", "postalCode", "country"):
            part = address.get(key)
            part_values = part if isinstance(part, list) else [part]
            for item in part_values:
                if _scalar_text(item) is not None:
                    parts.append(str(item).strip())
                    if key != "line":
                        _append(candidates, "location", item, f"address/{index}/{key}")
        if parts:
            _append(candidates, "address", ", ".join(parts), f"address/{index}")
    return candidates


def _extract_note_values(
    note: str,
) -> dict[str, list[tuple[object, str, str | None]]]:
    candidates = _empty_candidates()
    for match in _NOTE_PATTERN.finditer(note):
        label = _key_name(match.group("label"))
        field_name = _NOTE_LABEL_LOOKUP.get(label)
        if field_name is not None:
            _append(candidates, field_name, match.group("value").strip(), label)
    return candidates


def _normalize_name(value: object) -> str | None:
    text = _scalar_text(value)
    normalized = normalize_name(text or "")
    return normalized or None


def _normalize_date_value(value: object) -> str | None:
    if isinstance(value, (date, datetime)):
        return normalize_date(value)
    text = _scalar_text(value)
    return normalize_date(text) if text is not None else None


def _normalize_age_value(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    return normalize_age(value) if isinstance(value, (str, int, float)) else None


def _normalize_gender_value(value: object) -> str | None:
    text = _scalar_text(value)
    return normalize_gender(text) if text is not None else None


def _normalize_phone_value(value: object) -> str | None:
    text = _scalar_text(value)
    return normalize_phone(text) if text is not None else None


def _normalize_email_value(value: object) -> str | None:
    text = _scalar_text(value)
    return normalize_email(text) if text is not None else None


def _normalize_address_value(value: object) -> str | None:
    text = _scalar_text(value)
    normalized = normalize_location(text or "")
    return normalized or None


def _normalize_location_value(value: object) -> str | None:
    return _normalize_address_value(value)


def _normalize_identifier_value(value: object) -> str | None:
    text = _scalar_text(value)
    return normalize_identifier(text) if text is not None else None


def _append_if_scalar(
    candidates: dict[str, list[tuple[object, str, str | None]]],
    field_name: str,
    value: object,
    source_key: str,
) -> None:
    if _scalar_text(value) is not None:
        _append(candidates, field_name, value, source_key)


def _fhir_identifier_type(value: object) -> str:
    if not isinstance(value, Mapping):
        return ""
    parts: list[str] = []
    text = value.get("text")
    if isinstance(text, str):
        parts.append(text)
    coding = value.get("coding")
    if isinstance(coding, list):
        for item in coding:
            if not isinstance(item, Mapping):
                continue
            for key in ("code", "display", "system"):
                item_value = item.get(key)
                if isinstance(item_value, str):
                    parts.append(item_value)
    return " ".join(parts).casefold()


def _append(
    candidates: dict[str, list[tuple[object, str, str | None]]],
    field_name: str,
    value: object,
    source_key: str,
    *,
    namespace: str | None = None,
) -> None:
    candidates[field_name].append((value, source_key, namespace))
    if field_name == "name":
        text = _scalar_text(value)
        relative = _RELATIVE_NAME.search(text or "")
        if relative is not None and relative.group("name").strip():
            candidates[field_name].pop()
            patient_name = (text or "")[: relative.start()].strip(" ,;:-")
            if patient_name:
                candidates[field_name].append((patient_name, source_key, None))
            relative_name = relative.group("name").strip()
            if not _is_clinical_relative_candidate(relative_name):
                candidates["relative_name"].append((relative_name, source_key, None))


def _is_clinical_relative_candidate(value: str) -> bool:
    normalized = normalize_name(value)
    return bool(set(normalized.split()) & _RELATIVE_CLINICAL_TERMS)


def _empty_candidates() -> dict[str, list[tuple[object, str, str | None]]]:
    return {field_name: [] for field_name in _FIELD_NAMES}


def _extract_source_system(record: Mapping[str, object]) -> str | None:
    values: set[str] = set()
    stack: list[tuple[object, tuple[str, ...], int]] = [(record, (), 0)]
    while stack:
        value, path, depth = stack.pop()
        if depth > _MAX_DEPTH:
            raise ProcessingError("identity_structure_depth_exceeded")
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                stack.append((child, path + (str(index),), depth + 1))
            continue
        if not isinstance(value, Mapping):
            continue
        for key, child in value.items():
            if not isinstance(key, str):
                continue
            child_path = path + (key,)
            normalized_key = _key_name(key)
            contexts = {_key_name(part) for part in path}
            if contexts & _NON_SOURCE_CONTEXTS:
                continue
            has_source_context = bool(contexts & _SOURCE_CONTEXTS)
            is_source_key = normalized_key in _SOURCE_SYSTEM_KEYS or (
                has_source_context
                and normalized_key in {"id", "identifier", "name", "system"}
            )
            if is_source_key:
                candidate = _normalize_source_system(child)
                if candidate is not None:
                    values.add(candidate)
            if isinstance(child, (Mapping, list, tuple)):
                stack.append((child, child_path, depth + 1))
    return next(iter(values)) if len(values) == 1 else None


def _single_identifier_namespace(
    candidates: Mapping[str, list[tuple[object, str, str | None]]],
) -> str | None:
    namespaces = {
        namespace
        for _, _, namespace in candidates.get("hospital_identifier", [])
        if namespace is not None
    }
    return next(iter(namespaces)) if len(namespaces) == 1 else None


def _normalize_source_system(value: object) -> str | None:
    text = _scalar_text(value)
    if text is None:
        return None
    normalized = unicodedata.normalize("NFKC", text).strip()
    if (
        not normalized
        or len(normalized) > 2048
        or any(unicodedata.category(character) == "Cc" for character in normalized)
    ):
        return None
    return " ".join(normalized.split())


def _scalar_text(value: object) -> str | None:
    if isinstance(value, bool) or value is None or isinstance(value, (Mapping, list, tuple)):
        return None
    if not isinstance(value, (str, int, float, date, datetime)):
        return None
    text = value.isoformat() if isinstance(value, (date, datetime)) else str(value)
    return text if text.strip() else None


def _key_name(value: str) -> str:
    text = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in text if character.isalnum())


def _ascii_digits(value: str) -> str:
    return "".join(
        str(unicodedata.digit(character)) if character.isdecimal() else character
        for character in value
    )


def _as_mappings(value: object) -> list[Mapping[str, object]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


__all__ = [
    "PatientIdentityNormalizer",
    "extract_fhir_identities",
    "extract_identity",
    "normalize_age",
    "normalize_date",
    "normalize_gender",
    "normalize_identifier",
    "normalize_email",
    "normalize_location",
    "normalize_phone",
]
