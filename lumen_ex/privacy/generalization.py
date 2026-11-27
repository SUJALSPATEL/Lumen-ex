"""Age and location generalization that leaves clinical fields untouched."""

from collections.abc import Mapping
from decimal import Decimal
import re

from lumen_ex.value_normalization import normalize_age


_AGE_BAND = re.compile(r"^(\d+)-(\d+)$")
_AGE_OPEN_BAND = re.compile(r"^(\d+)\+$")
_KEY_NORMALIZER = re.compile(r"[^a-z0-9]+")

_VILLAGE_KEYS = {"village", "villagemohalla", "gaon", "gram", "mohalla", "locality", "town", "city"}
_DISTRICT_KEYS = {"district", "jila", "zilla"}
_TEHSIL_KEYS = {"tehsil", "taluk", "taluka", "subdistrict"}
_STATE_KEYS = {"state", "province"}
_PIN_KEYS = {"pin", "pincode", "postalcode", "zipcode", "postal"}
_ADDRESS_LINE_KEYS = {
    "line",
    "line1",
    "line2",
    "line3",
    "addressline",
    "addressline1",
    "addressline2",
    "house",
    "houseno",
    "street",
    "streetaddress",
    "landmark",
}


class AgeGeneralizer:
    def __init__(self, band_years: int = 5, elderly_threshold: int = 85) -> None:
        if (
            isinstance(band_years, bool)
            or not isinstance(band_years, int)
            or band_years < 1
            or elderly_threshold < band_years
        ):
            raise ValueError("age_generalization_policy_invalid")
        self.band_years = band_years
        self.elderly_threshold = elderly_threshold

    def generalize(self, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            band = _AGE_BAND.fullmatch(value.strip())
            if band:
                lower, upper = int(band.group(1)), int(band.group(2))
                if 0 <= lower <= upper < self.elderly_threshold and (
                    upper - lower < self.band_years
                ):
                    return value.strip()
            open_band = _AGE_OPEN_BAND.fullmatch(value.strip())
            if open_band and int(open_band.group(1)) == self.elderly_threshold:
                return value.strip()
        if isinstance(value, bool) or not isinstance(
            value, (str, int, float, Decimal)
        ):
            return None
        normalized = normalize_age(value)
        if normalized is None:
            return None
        age = int(normalized)
        if age >= self.elderly_threshold:
            return f"{self.elderly_threshold}+"
        distance_from_elderly_band = self.elderly_threshold - 1 - age
        upper = (
            self.elderly_threshold
            - 1
            - (distance_from_elderly_band // self.band_years) * self.band_years
        )
        lower = max(0, upper - self.band_years + 1)
        return f"{lower}-{upper}"


class LocationGeneralizer:
    def __init__(
        self,
        hierarchy: tuple[str, ...] = ("village", "tehsil", "district", "state"),
    ) -> None:
        allowed = {"village", "tehsil", "district", "state"}
        if not hierarchy or any(level not in allowed for level in hierarchy):
            raise ValueError("location_generalization_policy_invalid")
        if len(set(hierarchy)) != len(hierarchy):
            raise ValueError("location_generalization_policy_invalid")
        order = ("village", "tehsil", "district", "state")
        if tuple(order.index(level) for level in hierarchy) != tuple(
            sorted(order.index(level) for level in hierarchy)
        ):
            raise ValueError("location_generalization_policy_invalid")
        self.hierarchy = hierarchy

    def generalize(self, fields: Mapping[object, object]) -> dict[str, object]:
        return self._transform_mapping(fields, in_address=False, in_hospital=False)

    def _transform_mapping(
        self,
        values: Mapping[object, object],
        *,
        in_address: bool,
        in_hospital: bool,
    ) -> dict[str, object]:
        string_values = {
            _normalize_key(str(key)): value for key, value in values.items()
        }
        result: dict[str, object] = {}
        for original_key, value in values.items():
            if not isinstance(original_key, str):
                result[str(original_key)] = value
                continue
            key = _normalize_key(original_key)
            hospital_context = in_hospital or key in {
                "hospital",
                "hospitaladdress",
                "facility",
                "facilityaddress",
                "facilitylocation",
                "clinic",
                "provider",
                "organization",
                "organisation",
            }
            address_context = in_address or key in {
                "address",
                "patientaddress",
                "pata",
                "residence",
                "homeaddress",
            }
            if not in_hospital and (
                (address_context and _is_address_line(key))
                or key in {"street", "streetaddress", "house", "houseno", "landmark"}
            ):
                result[original_key] = None
                continue
            if (
                not in_hospital
                and key in {
                    "address",
                    "patientaddress",
                    "pata",
                    "residence",
                    "homeaddress",
                }
                and not isinstance(value, Mapping)
            ):
                result[original_key] = None
                continue
            if not in_hospital and key in _PIN_KEYS:
                result[original_key] = _generalize_pin(value)
                continue
            if not in_hospital and key in _VILLAGE_KEYS:
                result[original_key] = self._broader_location(
                    "village", string_values
                )
                continue
            if not in_hospital and key in _TEHSIL_KEYS:
                result[original_key] = self._broader_location("tehsil", string_values)
                continue
            if not in_hospital and key in _DISTRICT_KEYS:
                result[original_key] = self._broader_location("district", string_values)
                continue
            if not in_hospital and key in {"location", "localaddress"} and not isinstance(
                value, Mapping
            ):
                result[original_key] = self._broader_location("village", string_values)
                continue
            if isinstance(value, Mapping):
                result[original_key] = self._transform_mapping(
                    value,
                    in_address=address_context,
                    in_hospital=hospital_context,
                )
            elif isinstance(value, list):
                result[original_key] = [
                    self._transform_mapping(item, in_address=address_context, in_hospital=hospital_context)
                    if isinstance(item, Mapping)
                    else item
                    for item in value
                ]
            else:
                result[original_key] = value
        return result

    def _broader_location(
        self, level: str, values: Mapping[str, object]
    ) -> object:
        mapped = _location_level_values(values)
        level_index = self.hierarchy.index(level) if level in self.hierarchy else 0
        for candidate in self.hierarchy[level_index + 1 :]:
            value = mapped.get(candidate)
            if value not in (None, ""):
                return value
        if level == "district":
            value = mapped.get("district")
            return value if value not in (None, "") else None
        return None


def _normalize_key(key: str) -> str:
    return _KEY_NORMALIZER.sub("", key.casefold())


def _location_level_values(values: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values.items():
        if key in _VILLAGE_KEYS:
            result["village"] = value
        elif key in _TEHSIL_KEYS:
            result["tehsil"] = value
        elif key in _DISTRICT_KEYS:
            result["district"] = value
        elif key in _STATE_KEYS:
            result["state"] = value
    return result


def _generalize_pin(value: object) -> str | None:
    digits = "".join(character for character in str(value) if character.isdecimal())
    if len(digits) != 6:
        return None
    return digits[:3] + "***"


def _is_address_line(key: str) -> bool:
    return key in _ADDRESS_LINE_KEYS or key.startswith("addressline")
