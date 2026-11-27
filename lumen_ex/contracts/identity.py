"""Compact identity data contracts for future candidate-retrieval stages."""

from dataclasses import dataclass, field
from enum import Enum


class IdentityDecision(str, Enum):
    LINK = "LINK"
    CREATE = "CREATE"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class RegistryRecordMapping:
    patient_id: str | None
    decision: IdentityDecision
    confidence: float


@dataclass(frozen=True)
class IdentityValue:
    """One extracted source value and its conservative normalized form."""

    original: str = field(repr=False)
    normalized: str | None = field(repr=False)
    source_key: str = field(default="", repr=False)
    namespace: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class PatientIdentity:
    """Identity-only projection of a record; never retains the complete record."""

    source_file: str = field(repr=False)
    record_locator: str = field(repr=False)
    name: tuple[IdentityValue, ...] = ()
    relative_name: tuple[IdentityValue, ...] = ()
    date_of_birth: tuple[IdentityValue, ...] = ()
    age: tuple[IdentityValue, ...] = ()
    gender: tuple[IdentityValue, ...] = ()
    phone: tuple[IdentityValue, ...] = ()
    email: tuple[IdentityValue, ...] = ()
    address: tuple[IdentityValue, ...] = ()
    location: tuple[IdentityValue, ...] = ()
    hospital_identifier: tuple[IdentityValue, ...] = ()
    insurance_identifier: tuple[IdentityValue, ...] = ()
    government_identifier: tuple[IdentityValue, ...] = ()
    missing_fields: frozenset[str] = frozenset()
    invalid_fields: frozenset[str] = frozenset()
    normalization_metadata: tuple[tuple[str, str], ...] = ()
    source_system: str | None = field(default=None, repr=False)
    context_conflict: bool = False
    inherited_fields: frozenset[str] = frozenset()
    reference_source_system: str | None = field(default=None, repr=False)


__all__ = [
    "IdentityDecision",
    "IdentityValue",
    "PatientIdentity",
    "RegistryRecordMapping",
]
