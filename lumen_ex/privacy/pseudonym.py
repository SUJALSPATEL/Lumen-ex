"""Stable, purpose-separated patient pseudonyms."""

import hashlib
import hmac

from lumen_ex.contracts.models import LinkageAction, LinkageDecision
from lumen_ex.errors import ProcessingError
from lumen_ex.key_derivation import derive_key


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PSEUDONYM_BYTES = 10
_PSEUDONYM_LENGTH = 16


class Pseudonymizer:
    def __init__(self, secret: str | bytes) -> None:
        if not isinstance(secret, (str, bytes)) or not secret:
            raise ProcessingError("secret_missing")
        self._key = derive_key(secret, b"patient-pseudonym")

    def pseudonym_for(self, patient_reference: str) -> str:
        if not isinstance(patient_reference, str) or not patient_reference:
            raise ProcessingError("privacy_patient_reference_invalid")
        digest = hmac.new(
            self._key,
            b"lumen-ex/patient-reference/v1\0" + patient_reference.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        number = int.from_bytes(digest[:_PSEUDONYM_BYTES], "big")
        encoded = "".join(
            _CROCKFORD[(number >> (index * 5)) & 31]
            for index in range(_PSEUDONYM_LENGTH - 1, -1, -1)
        )
        return "PSN-" + encoded

    def for_decision(self, decision: LinkageDecision) -> str | None:
        if decision.action is not LinkageAction.LINK:
            return None
        if decision.patient_reference is None:
            raise ProcessingError("privacy_patient_reference_invalid")
        return self.pseudonym_for(decision.patient_reference)

    def __repr__(self) -> str:
        return "Pseudonymizer()"
