"""Conservative indexed candidate scoring; this module never merges patients."""

from dataclasses import dataclass, field
from difflib import SequenceMatcher
import math

from lumen_ex.contracts.identity import IdentityDecision, IdentityValue, PatientIdentity
from lumen_ex.contracts.models import LinkageAction, LinkageDecision, NormalizedRecord
from lumen_ex.detection.indic_names import normalize_name
from lumen_ex.registry import EncryptedIdentityRegistry


_BLOCK_FIELDS = (
    "government_identifier",
    "insurance_identifier",
    "hospital_identifier",
    "phone",
    "email",
    "date_of_birth",
    "relative_name",
    "name",
)
_STRONG_IDENTIFIERS = frozenset(
    {
        "government_identifier",
        "hospital_identifier",
        "insurance_identifier",
        "phone",
        "email",
    }
)
_MIN_NAME_CORROBORATION = 0.75
_MIN_NAME_CONFLICT = 0.55
_DEFAULT_LINK_THRESHOLD = 0.85
_SUPPORTED_EVIDENCE_CONFIDENCE = 0.90
_DEFAULT_AMBIGUITY_MARGIN = 0.05
_DEFAULT_CANDIDATE_LIMIT = 500


@dataclass(frozen=True)
class CandidateScore:
    patient_id: str = field(repr=False)
    confidence: float
    evidence: tuple[str, ...]
    hard_conflict: bool = False


@dataclass(frozen=True)
class IdentityMatchResult:
    decision: IdentityDecision
    patient_id: str | None = field(repr=False)
    confidence: float
    reason: str
    candidates: tuple[CandidateScore, ...] = ()


class IdentityMatcher:
    """Retrieve bounded candidates and decide LINK, CREATE, or UNRESOLVED.

    Confidence is a deterministic evidence score, not a calibrated probability.
    A strong identifier or a unique name-plus-independent-clue combination can link.
    Names alone can never link records.
    """

    def __init__(
        self,
        registry: EncryptedIdentityRegistry,
        hospital_namespace: str = "",
        link_threshold: float = _DEFAULT_LINK_THRESHOLD,
        ambiguity_margin: float = _DEFAULT_AMBIGUITY_MARGIN,
        candidate_limit: int = _DEFAULT_CANDIDATE_LIMIT,
    ) -> None:
        if (
            isinstance(link_threshold, bool)
            or not isinstance(link_threshold, (int, float))
            or not math.isfinite(link_threshold)
            or not 0.0 < link_threshold <= 1.0
        ):
            raise ValueError("link_threshold_invalid")
        if (
            isinstance(ambiguity_margin, bool)
            or not isinstance(ambiguity_margin, (int, float))
            or not math.isfinite(ambiguity_margin)
            or not 0.0 <= ambiguity_margin < 1.0
        ):
            raise ValueError("ambiguity_margin_invalid")
        if (
            isinstance(candidate_limit, bool)
            or not isinstance(candidate_limit, int)
            or candidate_limit < 1
        ):
            raise ValueError("candidate_limit_invalid")
        if not isinstance(hospital_namespace, str):
            raise ValueError("hospital_namespace_invalid")

        self.registry = registry
        self.hospital_namespace = hospital_namespace
        self.link_threshold = float(link_threshold)
        self.ambiguity_margin = float(ambiguity_margin)
        self.candidate_limit = candidate_limit

    def evaluate(self, identity: PatientIdentity) -> IdentityMatchResult:
        """Score only indexed candidates; do not persist a decision or merge."""
        values = _normalized_values(identity)
        candidates: dict[str, set[str]] = {}
        for field_name in _BLOCK_FIELDS:
            if field_name == "hospital_identifier":
                for value in identity.hospital_identifier:
                    normalized = value.normalized
                    namespace = _identifier_namespace(
                        value, identity.source_system, self.hospital_namespace
                    )
                    if not normalized or not namespace:
                        continue
                    for patient_id in self.registry.iter_resolved_candidate_ids(
                        field_name, normalized, namespace
                    ):
                        candidates.setdefault(patient_id, set()).add(field_name)
                        if len(candidates) > self.candidate_limit:
                            return IdentityMatchResult(
                                IdentityDecision.UNRESOLVED,
                                None,
                                0.0,
                                "candidate_limit_exceeded",
                            )
                continue
            for value in values[field_name]:
                for patient_id in self.registry.iter_resolved_candidate_ids(
                    field_name, value, ""
                ):
                    candidates.setdefault(patient_id, set()).add(field_name)
                    if len(candidates) > self.candidate_limit:
                        return IdentityMatchResult(
                            IdentityDecision.UNRESOLVED,
                            None,
                            0.0,
                            "candidate_limit_exceeded",
                        )

        if not candidates:
            has_hospital_namespace = bool(
                identity.source_system
                or self.hospital_namespace
                or any(value.namespace for value in identity.hospital_identifier)
            )
            if _sufficient_for_create(values, has_hospital_namespace):
                return IdentityMatchResult(
                    IdentityDecision.CREATE, None, 0.9, "no_existing_candidate"
                )
            return IdentityMatchResult(
                IdentityDecision.UNRESOLVED,
                None,
                0.0,
                "insufficient_identity_evidence",
            )

        scores = tuple(
            sorted(
                (
                    self._score_candidate(
                        patient_id, block_matches, values, identity
                    )
                    for patient_id, block_matches in candidates.items()
                ),
                key=lambda candidate: (-candidate.confidence, candidate.patient_id),
            )
        )
        eligible = tuple(
            candidate
            for candidate in scores
            if not candidate.hard_conflict
            and "name_conflict" not in candidate.evidence
            and candidate.confidence >= self.link_threshold
            and _has_independent_support(candidate.evidence)
        )
        if not eligible:
            reason = (
                "hard_identifier_conflict"
                if all(candidate.hard_conflict for candidate in scores)
                else "weak_candidate_evidence"
            )
            return IdentityMatchResult(
                IdentityDecision.UNRESOLVED, None, scores[0].confidence, reason, scores
            )
        if (
            len(eligible) > 1
            and eligible[0].confidence - eligible[1].confidence
            < self.ambiguity_margin
        ):
            return IdentityMatchResult(
                IdentityDecision.UNRESOLVED,
                None,
                eligible[0].confidence,
                "ambiguous_candidates",
                scores,
            )
        best = eligible[0]
        return IdentityMatchResult(
            IdentityDecision.LINK,
            best.patient_id,
            best.confidence,
            "unique_best_candidate",
            scores,
        )

    def _score_candidate(
        self,
        patient_id: str,
        block_matches: set[str],
        values: dict[str, set[str]],
        identity: PatientIdentity,
    ) -> CandidateScore:
        exact_fields = set(block_matches)
        evidence: set[str] = set()
        best_name_similarity = 0.0
        best_relative_similarity = 0.0
        has_stored_name = False
        for field_name, stored_value in self.registry.iter_identity_values(patient_id):
            normalized = stored_value.normalized
            if normalized is None:
                continue
            if field_name == "name":
                stored_name = normalize_name(normalized)
                has_stored_name = has_stored_name or bool(stored_name)
                for current_name in values["name"]:
                    best_name_similarity = max(
                        best_name_similarity,
                        _name_similarity(current_name, stored_name),
                    )
            elif field_name == "relative_name":
                stored_name = normalize_name(normalized)
                for current_name in values["relative_name"]:
                    best_relative_similarity = max(
                        best_relative_similarity,
                        _name_similarity(current_name, stored_name),
                    )
            elif (
                field_name == "location"
                and _is_village_source(stored_value.source_key)
                and normalized in values["village"]
            ):
                evidence.add("village_exact")
            elif field_name == "age" and _age_matches_within_one(
                normalized, values["age"]
            ):
                if normalized in values["age"]:
                    exact_fields.add("age")
                else:
                    evidence.add("age_near")
            elif field_name == "hospital_identifier":
                if normalized in values.get(field_name, set()) and any(
                    current.normalized == normalized
                    and _identifier_namespace(
                        current,
                        identity.source_system,
                        self.hospital_namespace,
                    )
                    == stored_value.namespace
                    for current in identity.hospital_identifier
                ):
                    exact_fields.add(field_name)
            elif normalized in values.get(field_name, set()):
                exact_fields.add(field_name)

        evidence.update(f"{field_name}_exact" for field_name in exact_fields)
        if best_name_similarity >= _MIN_NAME_CORROBORATION:
            evidence.add("name_similar")
        elif (
            values["name"]
            and has_stored_name
            and best_name_similarity < _MIN_NAME_CONFLICT
        ):
            evidence.add("name_conflict")
        if best_relative_similarity >= _MIN_NAME_CORROBORATION:
            evidence.add("relative_name_similar")

        hard_conflict = False
        for identifier in identity.hospital_identifier:
            identifier_namespace = _identifier_namespace(
                identifier, identity.source_system, self.hospital_namespace
            )
            if identifier.normalized and identifier_namespace:
                if self.registry.has_conflicting_block(
                    patient_id,
                    "hospital_identifier",
                    identifier.normalized,
                    identifier_namespace,
                ):
                    hard_conflict = True
                    evidence.add("hospital_identifier_conflict")
                    break

        if _has_independent_support(tuple(evidence)):
            evidence.add("independent_support")

        confidence = _evidence_confidence(
            exact_fields,
            best_name_similarity,
            best_relative_similarity,
        )
        if "independent_support" in evidence:
            confidence = max(confidence, _SUPPORTED_EVIDENCE_CONFIDENCE)
        if hard_conflict:
            confidence = 0.0
        return CandidateScore(
            patient_id=patient_id,
            confidence=confidence,
            evidence=tuple(sorted(evidence)),
            hard_conflict=hard_conflict,
        )


def _normalized_values(identity: PatientIdentity) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for field_name in _BLOCK_FIELDS:
        values: tuple[IdentityValue, ...] = getattr(identity, field_name)
        normalized_values = {
            value.normalized
            for value in values
            if isinstance(value.normalized, str) and value.normalized
        }
        if field_name in {"name", "relative_name"}:
            normalized_values = {
                normalized
                for value in values
                if isinstance(value.normalized, str)
                and (normalized := normalize_name(value.normalized))
            }
        result[field_name] = normalized_values

    for field_name in ("gender", "age", "address", "location"):
        result[field_name] = {
            value.normalized
            for value in getattr(identity, field_name)
            if isinstance(value.normalized, str) and value.normalized
        }
    result["village"] = {
        value.normalized
        for value in identity.location
        if isinstance(value.normalized, str)
        and value.normalized
        and _is_village_source(value.source_key)
    }
    return result


def _identifier_namespace(
    value: IdentityValue,
    source_system: str | None,
    fallback: str,
) -> str:
    return value.namespace or source_system or fallback


def _evidence_confidence(
    exact_fields: set[str],
    name_similarity: float,
    relative_name_similarity: float,
) -> float:
    confidence = 1.0
    weights = {
        "government_identifier": 0.92,
        "hospital_identifier": 0.92,
        "insurance_identifier": 0.92,
        "email": 0.92,
        "phone": 0.60,
        "date_of_birth": 0.60,
        "gender": 0.10,
        "age": 0.05,
        "address": 0.05,
        "location": 0.05,
    }
    for field_name, weight in weights.items():
        if field_name in exact_fields:
            confidence *= 1.0 - weight
    confidence *= 1.0 - (0.40 * name_similarity)
    confidence *= 1.0 - (0.20 * relative_name_similarity)
    return min(1.0, max(0.0, 1.0 - confidence))


def _name_similarity(first: str, second: str) -> float:
    if first == second:
        return 1.0
    if len(first) > 512 or len(second) > 512:
        return 0.0
    return SequenceMatcher(None, first.split(), second.split(), autojunk=False).ratio()


def _has_independent_support(evidence: tuple[str, ...]) -> bool:
    evidence_set = set(evidence)
    strong_identifier = bool(
        evidence_set & {
            f"{field}_exact" for field in _STRONG_IDENTIFIERS - {"hospital_identifier"}
        }
    )
    name_support = "name_similar" in evidence_set
    if strong_identifier:
        return True
    if "hospital_identifier_exact" in evidence_set and name_support:
        return True
    has_second_clue = bool(
        evidence_set
        & {
            "date_of_birth_exact",
            "relative_name_exact",
            "relative_name_similar",
        }
    )
    village_age = (
        "village_exact" in evidence_set
        and bool(evidence_set & {"age_exact", "age_near"})
    )
    return name_support and (has_second_clue or village_age)


def _sufficient_for_create(
    values: dict[str, set[str]], has_hospital_namespace: bool
) -> bool:
    has_identifier = any(
        values[field_name]
        for field_name in _STRONG_IDENTIFIERS - {"hospital_identifier"}
    ) or (
        has_hospital_namespace and bool(values["hospital_identifier"])
    )
    return has_identifier or bool(
        values["phone"] and values["date_of_birth"] and values["name"]
    )


def _age_matches_within_one(candidate: str, values: set[str]) -> bool:
    if not candidate.isdecimal():
        return False
    candidate_age = int(candidate)
    return any(
        value.isdecimal() and abs(candidate_age - int(value)) <= 1
        for value in values
    )


def _is_village_source(source_key: str) -> bool:
    normalized = source_key.casefold()
    return any(marker in normalized for marker in ("village", "gaon", "गाँव", "गांव"))


class IdentityLinker:
    """Adapt identity-match outcomes to the pipeline's LINK/DO_NOT_LINK/ABSTAIN contract."""

    def __init__(self, matcher: IdentityMatcher) -> None:
        self.matcher = matcher

    def decide(self, record: NormalizedRecord) -> LinkageDecision:
        if len(record.identities) != 1:
            return LinkageDecision(LinkageAction.ABSTAIN)

        result = self.matcher.evaluate(record.identities[0])
        if result.decision is IdentityDecision.LINK:
            return LinkageDecision(
                LinkageAction.LINK,
                patient_reference=result.patient_id,
            )
        if result.decision is IdentityDecision.CREATE:
            return LinkageDecision(LinkageAction.DO_NOT_LINK)
        return LinkageDecision(LinkageAction.ABSTAIN)


__all__ = [
    "CandidateScore",
    "IdentityLinker",
    "IdentityMatchResult",
    "IdentityMatcher",
]
