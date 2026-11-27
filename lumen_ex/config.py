"""Validated loading for the starter's small YAML-like policy file."""

from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
import re
import unicodedata

from lumen_ex.errors import ConfigurationError
from lumen_ex.value_normalization import AmbiguousDateAction, DateOrder

CANONICAL_ISSUER_PREFIX = "issuer-alias\x00"


@dataclass(frozen=True)
class PipelineConfig:
    age_band_years: int = 5
    date_shift_max_days: int = 180
    min_group_size: int = 5
    location_hierarchy: tuple[str, ...] = ("village", "tehsil", "district", "state")
    date_order_overrides: tuple[tuple[str, DateOrder], ...] = (
        ("registration/sanjeevani_registration", "dmy"),
        ("registration/jeevanjyoti_patients", "dmy"),
        ("registration/arogya_legacy_export", "mdy"),
    )
    ambiguous_date_action: AmbiguousDateAction = "redact"
    issuer_aliases: tuple[tuple[str, str, str], ...] = ()

    def __post_init__(self) -> None:
        numeric = (
            self.age_band_years,
            self.date_shift_max_days,
            self.min_group_size,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in numeric):
            raise ConfigurationError("configuration_value_invalid")
        if (
            self.age_band_years < 1
            or self.date_shift_max_days < 1
            or self.min_group_size < 2
        ):
            raise ConfigurationError("configuration_value_out_of_range")
        allowed = {"village", "tehsil", "district", "state"}
        if (
            not isinstance(self.location_hierarchy, tuple)
            or not self.location_hierarchy
            or any(not isinstance(level, str) for level in self.location_hierarchy)
            or any(level not in allowed for level in self.location_hierarchy)
            or len(set(self.location_hierarchy)) != len(self.location_hierarchy)
            or tuple(
                ("village", "tehsil", "district", "state").index(level)
                for level in self.location_hierarchy
            )
            != tuple(
                sorted(
                    ("village", "tehsil", "district", "state").index(level)
                    for level in self.location_hierarchy
                )
            )
        ):
            raise ConfigurationError("configuration_value_invalid")
        if (
            not isinstance(self.date_order_overrides, tuple)
            or any(
                not isinstance(override, tuple)
                or len(override) != 2
                or not isinstance(override[0], str)
                or not isinstance(override[1], str)
                for override in self.date_order_overrides
            )
        ):
            raise ConfigurationError("configuration_value_invalid")
        if (
            not isinstance(self.ambiguous_date_action, str)
            or self.ambiguous_date_action not in {"redact", "quarantine"}
        ):
            raise ConfigurationError("configuration_value_invalid")
        seen_prefixes: set[str] = set()
        for prefix, order in self.date_order_overrides:
            path = PurePosixPath(prefix)
            normalized_prefix = prefix.casefold()
            if (
                not prefix
                or prefix != str(path)
                or "\\" in prefix
                or ":" in prefix
                or path.is_absolute()
                or not path.parts
                or any(part in {".", ".."} for part in path.parts)
                or order not in {"dmy", "mdy"}
                or normalized_prefix in seen_prefixes
            ):
                raise ConfigurationError("configuration_value_invalid")
            seen_prefixes.add(normalized_prefix)

        aliases: set[tuple[str, str]] = set()
        if not isinstance(self.issuer_aliases, tuple):
            raise ConfigurationError("configuration_value_invalid")
        for entry in self.issuer_aliases:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 3
                or any(not isinstance(part, str) for part in entry)
            ):
                raise ConfigurationError("configuration_value_invalid")
            kind, alias, issuer = entry
            if (
                kind not in {"metadata", "fhir"}
                or not alias
                or alias.casefold() in {"na", "n/a", "nil", "none", "null", "unknown", "-", "--"}
                or len(alias) > 2048
                or alias != " ".join(unicodedata.normalize("NFKC", alias).split())
                or any(unicodedata.category(character) == "Cc" for character in alias)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", issuer)
                or (kind, alias) in aliases
            ):
                raise ConfigurationError("configuration_value_invalid")
            aliases.add((kind, alias))

    def issuer_namespace(self, kind: str, issuer: str) -> str:
        for alias_kind, alias, canonical in self.issuer_aliases:
            if (alias_kind, alias) == (kind, issuer):
                # Source issuer normalization rejects control characters.
                return CANONICAL_ISSUER_PREFIX + canonical
        return issuer

    def date_order_for_source(self, relative_path: str) -> DateOrder | None:
        """Return the most-specific configured date order for a source path."""
        normalized_path = relative_path.replace("\\", "/").casefold()
        matching = [
            (prefix, order)
            for prefix, order in self.date_order_overrides
            if _source_path_matches_prefix(normalized_path, prefix.casefold())
        ]
        if not matching:
            return None
        return max(matching, key=lambda override: len(override[0]))[1]


_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"
_EXPECTED_KEYS = {
    "age_band_years",
    "date_shift_max_days",
    "min_group_size",
    "location_hierarchy",
    "date_order_overrides",
    "ambiguous_date_action",
    "issuer_aliases",
}


def load_config(path: Path | str | None = None) -> PipelineConfig:
    """Load validated policy settings without requiring a YAML dependency."""
    config_path = Path(path) if path is not None else _DEFAULT_CONFIG_PATH
    values: dict[
        str,
        int
        | tuple[str, ...]
        | tuple[tuple[str, DateOrder], ...]
        | tuple[tuple[str, str, str], ...]
        | AmbiguousDateAction,
    ] = {}
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        raise ConfigurationError("configuration_unavailable") from None
    except UnicodeError:
        raise ConfigurationError("configuration_encoding_invalid") from None

    for line in lines:
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        if ":" not in content:
            raise ConfigurationError("configuration_syntax_invalid")
        key, value = (part.strip() for part in content.split(":", 1))
        if key not in _EXPECTED_KEYS or key in values:
            raise ConfigurationError("configuration_key_invalid")
        if key == "location_hierarchy":
            levels = tuple(part.strip().casefold() for part in value.split(","))
            allowed = {"village", "tehsil", "district", "state"}
            if (
                not levels
                or any(not level or level not in allowed for level in levels)
                or len(set(levels)) != len(levels)
                or tuple(
                    ("village", "tehsil", "district", "state").index(level)
                    for level in levels
                )
                != tuple(
                    sorted(
                        ("village", "tehsil", "district", "state").index(level)
                        for level in levels
                    )
                )
            ):
                raise ConfigurationError("configuration_value_invalid")
            values[key] = levels
            continue
        if key == "date_order_overrides":
            overrides: list[tuple[str, str]] = []
            for item in value.split(","):
                prefix, separator, order = item.partition("=")
                prefix = prefix.strip()
                order = order.strip().casefold()
                if not separator or not prefix:
                    raise ConfigurationError("configuration_value_invalid")
                overrides.append((prefix, _parse_date_order(order)))
            values[key] = tuple(overrides)
            continue
        if key == "ambiguous_date_action":
            action = value.casefold()
            if action == "redact":
                values[key] = "redact"
            elif action == "quarantine":
                values[key] = "quarantine"
            else:
                raise ConfigurationError("configuration_value_invalid")
            continue
        if key == "issuer_aliases":
            issuer_aliases = []
            for item in value.split(",") if value else ():
                kind, type_separator, assignment = item.partition("|")
                alias, separator, issuer = assignment.rpartition("=")
                if not type_separator or not separator:
                    raise ConfigurationError("configuration_value_invalid")
                issuer_aliases.append((kind.strip(), alias.strip(), issuer.strip()))
            values[key] = tuple(issuer_aliases)
            continue
        try:
            values[key] = int(value)
        except ValueError:
            raise ConfigurationError("configuration_value_invalid") from None

    defaults = PipelineConfig()
    age_band_years = values.get("age_band_years", defaults.age_band_years)
    date_shift_max_days = values.get("date_shift_max_days", defaults.date_shift_max_days)
    min_group_size = values.get("min_group_size", defaults.min_group_size)
    location_hierarchy = values.get(
        "location_hierarchy", defaults.location_hierarchy
    )
    date_order_overrides = values.get(
        "date_order_overrides", defaults.date_order_overrides
    )
    ambiguous_date_action = values.get(
        "ambiguous_date_action", defaults.ambiguous_date_action
    )
    issuer_aliases = values.get("issuer_aliases", defaults.issuer_aliases)
    if not isinstance(location_hierarchy, tuple):
        raise ConfigurationError("configuration_value_invalid")
    if not isinstance(date_order_overrides, tuple):
        raise ConfigurationError("configuration_value_invalid")
    if ambiguous_date_action not in {"redact", "quarantine"}:
        raise ConfigurationError("configuration_value_invalid")
    if any(
        not isinstance(value, int)
        for value in (age_band_years, date_shift_max_days, min_group_size)
    ):
        raise ConfigurationError("configuration_value_invalid")
    return PipelineConfig(
        age_band_years=age_band_years,
        date_shift_max_days=date_shift_max_days,
        min_group_size=min_group_size,
        location_hierarchy=location_hierarchy,
        date_order_overrides=date_order_overrides,
        ambiguous_date_action=ambiguous_date_action,
        issuer_aliases=issuer_aliases,
    )


def _source_path_matches_prefix(relative_path: str, prefix: str) -> bool:
    if relative_path == prefix or relative_path.startswith(prefix + "/"):
        return True
    return relative_path.startswith((prefix + ".", prefix + " ("))


def _parse_date_order(value: str) -> DateOrder:
    if value == "dmy":
        return "dmy"
    if value == "mdy":
        return "mdy"
    raise ConfigurationError("configuration_value_invalid")
