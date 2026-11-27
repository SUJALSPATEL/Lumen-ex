"""Encrypted, per-run SQLite storage for provisional patient identities."""

from contextlib import contextmanager
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Iterator, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lumen_ex.contracts.identity import (
    IdentityDecision,
    IdentityValue,
    PatientIdentity,
    RegistryRecordMapping,
)
from lumen_ex.errors import ProcessingError
from lumen_ex.key_derivation import derive_key


_FIELDS = (
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
_SHA256 = hashlib.sha256
_NONCE_LENGTH = 12


class EncryptedIdentityRegistry:
    """One encrypted registry shared by every batch in a processing run."""

    def __init__(
        self,
        database_path: Path,
        encryption_key: bytes,
        index_key: bytes,
        temporary_directory: tempfile.TemporaryDirectory,
    ) -> None:
        self.database_path = database_path
        self._encryption_key = encryption_key
        self._index_key = index_key
        self._temporary_directory = temporary_directory
        self._closed = False
        self._connection = self._connect(database_path)

    @classmethod
    def temporary(
        cls, secret: str | bytes, parent_dir: Path | None = None
    ) -> "EncryptedIdentityRegistry":
        """Create an encrypted registry in a private directory removed on close."""
        if not isinstance(secret, (str, bytes)):
            raise ProcessingError("registry_secret_missing")
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not secret_bytes:
            raise ProcessingError("registry_secret_missing")
        encryption_key = derive_key(secret_bytes, b"database-encryption")
        index_key = derive_key(secret_bytes, b"blind-index")
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="lumen-ex-registry-",
            dir=str(parent_dir) if parent_dir is not None else None,
        )
        database_path = Path(temporary_directory.name) / "identity-registry.sqlite3"
        try:
            return cls(
                database_path,
                encryption_key,
                index_key,
                temporary_directory,
            )
        except ProcessingError:
            temporary_directory.cleanup()
            raise
        except sqlite3.Error:
            temporary_directory.cleanup()
            raise ProcessingError("registry_storage_invalid") from None
        except OSError:
            temporary_directory.cleanup()
            raise ProcessingError("registry_storage_invalid") from None

    def __enter__(self) -> "EncryptedIdentityRegistry":
        self._ensure_open()
        return self

    def __exit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(closed={self._closed})"

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Group multiple registry writes into one SQLite transaction."""
        self._ensure_open()
        if self._connection.in_transaction:
            yield
            return
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            yield
            self._connection.commit()
        except sqlite3.Error:
            self._rollback()
            raise ProcessingError("registry_storage_error") from None
        except BaseException:
            self._rollback()
            raise

    def create_patient(self, source_sha256: str, record_locator: str) -> str:
        """Create or retrieve a deterministic provisional ID for a source record."""
        record_key = self._record_key(source_sha256, record_locator)
        patient_digest = hmac.new(
            self._index_key, b"patient\x00" + record_key, _SHA256
        ).hexdigest()
        patient_id = f"patient-{patient_digest[:32]}"
        with self.transaction():
            self._execute(
                "INSERT OR IGNORE INTO patients "
                "(patient_id, status, origin_key, canonical_id) "
                "VALUES (?, 'provisional', ?, NULL)",
                (patient_id, record_key),
            )
        return patient_id

    def add_record_mapping(
        self,
        source_sha256: str,
        record_locator: str,
        patient_id: str | None,
        decision: IdentityDecision | str,
        confidence: float,
        evidence: Mapping[str, object] | None = None,
    ) -> None:
        """Persist a record decision and encrypt its source reference and evidence."""
        record_key = self._record_key(source_sha256, record_locator)
        resolved_decision = self._coerce_decision(decision)
        self._validate_decision(patient_id, resolved_decision, confidence)
        if patient_id is not None and not self._patient_exists(patient_id):
            raise ProcessingError("registry_reference_invalid")

        source_ciphertext = self._encrypt(
            _json_bytes({"sha256": source_sha256.lower(), "locator": record_locator}),
            b"record-source\x00" + record_key,
        )
        try:
            evidence_bytes = _json_bytes(dict(evidence or {}))
        except (TypeError, ValueError):
            raise ProcessingError("registry_evidence_invalid") from None
        evidence_ciphertext = self._encrypt(
            evidence_bytes, b"record-evidence\x00" + record_key
        )
        with self.transaction():
            self._execute(
                "INSERT INTO record_mappings "
                "(record_key, source_ciphertext, patient_id, decision, confidence, "
                "evidence_ciphertext) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(record_key) DO UPDATE SET "
                "source_ciphertext=excluded.source_ciphertext, "
                "patient_id=excluded.patient_id, decision=excluded.decision, "
                "confidence=excluded.confidence, "
                "evidence_ciphertext=excluded.evidence_ciphertext",
                (
                    record_key,
                    source_ciphertext,
                    patient_id,
                    resolved_decision.value,
                    float(confidence),
                    evidence_ciphertext,
                ),
            )

    def add_identity(
        self,
        patient_id: str,
        source_sha256: str,
        identity: PatientIdentity,
        namespace: str = "",
        record_locator: str | None = None,
    ) -> None:
        """Encrypt extracted identity values and add keyed exact-value blocks."""
        locator = record_locator if record_locator is not None else identity.record_locator
        record_key = self._record_key(source_sha256, locator)
        if not self._patient_exists(patient_id):
            raise ProcessingError("registry_reference_invalid")
        mapping = self._execute(
            "SELECT patient_id, decision FROM record_mappings WHERE record_key = ?",
            (record_key,),
        ).fetchone()
        if mapping is None or (
            mapping[1] != IdentityDecision.UNRESOLVED.value
            and mapping[0] != patient_id
        ):
            raise ProcessingError("registry_reference_invalid")

        with self.transaction():
            for field_name in _FIELDS:
                field_values: tuple[IdentityValue, ...] = getattr(identity, field_name)
                for position, field_value in enumerate(field_values):
                    block_namespace = (
                        field_value.namespace or identity.source_system or namespace
                        if field_name == "hospital_identifier"
                        else field_value.namespace
                        if field_name == "insurance_identifier"
                        else None
                    )
                    payload = _json_bytes(
                        {
                            "original": field_value.original,
                            "normalized": field_value.normalized,
                            "source_key": field_value.source_key,
                            "namespace": block_namespace,
                        }
                    )
                    ciphertext = self._encrypt(
                        payload,
                        _identity_aad(record_key, field_name, position),
                    )
                    self._execute(
                        "INSERT INTO identity_values "
                        "(record_key, patient_id, field, position, ciphertext) "
                        "VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(record_key, field, position) DO UPDATE SET "
                        "patient_id=excluded.patient_id, ciphertext=excluded.ciphertext",
                        (record_key, patient_id, field_name, position, ciphertext),
                    )
                    if field_value.normalized is not None and (
                        field_name != "insurance_identifier" or block_namespace
                    ):
                        self.add_block(
                            patient_id,
                            field_name,
                            field_value.normalized,
                            block_namespace or "",
                        )

    def add_block(
        self,
        patient_id: str,
        kind: str,
        value: str,
        namespace: str = "",
    ) -> None:
        """Index a keyed feature token without storing its plaintext."""
        if not kind or not value or (kind == "insurance_identifier" and not namespace):
            return
        if not self._patient_exists(patient_id):
            raise ProcessingError("registry_reference_invalid")
        namespace_token = _hmac_digest(
            self._index_key, b"namespace\x00" + namespace.encode("utf-8")
        )
        value_token = _hmac_digest(
            self._index_key,
            b"block\x00" + kind.encode("utf-8") + b"\x00" + value.encode("utf-8"),
        )
        with self.transaction():
            self._execute(
                "INSERT OR IGNORE INTO block_index "
                "(kind, namespace_token, value_token, patient_id) VALUES (?, ?, ?, ?)",
                (kind, namespace_token, value_token, patient_id),
            )

    def find_candidates(
        self, kind: str, value: str, namespace: str = ""
    ) -> tuple[str, ...]:
        """Return deduplicated candidate IDs for small blocking result sets."""
        self._ensure_open()
        if not kind or not value:
            return ()
        return tuple(
            sorted(
                {
                    self._resolve_patient(patient_id)
                    for patient_id in self.iter_candidate_ids(kind, value, namespace)
                }
            )
        )

    def iter_candidate_ids(
        self, kind: str, value: str, namespace: str = ""
    ) -> Iterator[str]:
        """Stream raw matching IDs for blocks that may contain many candidates."""
        self._ensure_open()
        if not kind or not value or (kind == "insurance_identifier" and not namespace):
            return
        namespace_token = _hmac_digest(
            self._index_key, b"namespace\x00" + namespace.encode("utf-8")
        )
        value_token = _hmac_digest(
            self._index_key,
            b"block\x00" + kind.encode("utf-8") + b"\x00" + value.encode("utf-8"),
        )
        rows = self._execute(
            "SELECT patient_id FROM block_index "
            "WHERE kind = ? AND namespace_token = ? AND value_token = ? "
            "ORDER BY patient_id",
            (kind, namespace_token, value_token),
        )
        for row in rows:
            yield row[0]

    def iter_resolved_candidate_ids(
        self, kind: str, value: str, namespace: str = ""
    ) -> Iterator[str]:
        """Stream candidate IDs after following any existing canonical aliases."""
        for patient_id in self.iter_candidate_ids(kind, value, namespace):
            yield self._resolve_patient(patient_id)

    def has_conflicting_block(
        self, patient_id: str, kind: str, value: str, namespace: str = ""
    ) -> bool:
        """Check for a different indexed value in the same patient namespace."""
        self._ensure_open()
        if not kind or not value or (kind == "insurance_identifier" and not namespace):
            return False
        if not self._patient_exists(patient_id):
            raise ProcessingError("registry_reference_invalid")
        namespace_token = _hmac_digest(
            self._index_key, b"namespace\x00" + namespace.encode("utf-8")
        )
        value_token = _hmac_digest(
            self._index_key,
            b"block\x00" + kind.encode("utf-8") + b"\x00" + value.encode("utf-8"),
        )
        row = self._execute(
            "WITH RECURSIVE patient_family(patient_id) AS ("
            "SELECT ? UNION ALL "
            "SELECT patients.patient_id FROM patients "
            "JOIN patient_family ON patients.canonical_id = patient_family.patient_id"
            ") "
            "SELECT 1 FROM block_index "
            "WHERE patient_id IN (SELECT patient_id FROM patient_family) "
            "AND kind = ? AND namespace_token = ? AND value_token != ? LIMIT 1",
            (patient_id, kind, namespace_token, value_token),
        ).fetchone()
        return row is not None

    def get_record_mapping(
        self, source_sha256: str, record_locator: str
    ) -> RegistryRecordMapping | None:
        """Return the mapping for a reread source record, if one was registered."""
        self._ensure_open()
        record_key = self._record_key(source_sha256, record_locator)
        row = self._execute(
            "SELECT source_ciphertext, patient_id, decision, confidence "
            "FROM record_mappings WHERE record_key = ?",
            (record_key,),
        ).fetchone()
        if row is None:
            return None
        source = self._decrypt_json(
            row[0], b"record-source\x00" + record_key
        )
        if source != {
            "sha256": source_sha256.lower(),
            "locator": record_locator,
        }:
            raise ProcessingError("registry_data_invalid")
        patient_id = self._resolve_patient(row[1]) if row[1] is not None else None
        try:
            decision = IdentityDecision(row[2])
        except ValueError:
            raise ProcessingError("registry_data_invalid") from None
        return RegistryRecordMapping(patient_id, decision, float(row[3]))

    def get_identity_values(
        self, patient_id: str
    ) -> dict[str, tuple[IdentityValue, ...]]:
        """Decrypt one patient's stored evidence for confidence evaluation."""
        result: dict[str, list[IdentityValue]] = {field: [] for field in _FIELDS}
        for field_name, identity_value in self.iter_identity_values(patient_id):
            result[field_name].append(identity_value)
        return {field: tuple(values) for field, values in result.items()}

    def iter_identity_values(
        self, patient_id: str
    ) -> Iterator[tuple[str, IdentityValue]]:
        """Stream one patient's encrypted evidence in deterministic order."""
        self._ensure_open()
        if not self._patient_exists(patient_id):
            raise ProcessingError("registry_reference_invalid")
        rows = self._execute(
            "SELECT record_key, field, position, ciphertext FROM identity_values "
            "WHERE patient_id = ? ORDER BY record_key, field, position",
            (patient_id,),
        )
        for record_key, field_name, position, ciphertext in rows:
            payload = self._decrypt_json(
                ciphertext, _identity_aad(record_key, field_name, position)
            )
            yield field_name, (
                IdentityValue(
                    original=payload["original"],
                    normalized=payload["normalized"],
                    source_key=payload["source_key"],
                    namespace=payload.get("namespace"),
                )
            )

    def set_canonical_patient(self, source_id: str, canonical_id: str) -> None:
        """Merge two identity clusters unless a hospital-ID conflict is transitive."""
        if source_id == canonical_id:
            raise ProcessingError("registry_reference_invalid")
        if not self._patient_exists(source_id) or not self._patient_exists(canonical_id):
            raise ProcessingError("registry_reference_invalid")
        with self.transaction():
            source_root = self._resolve_patient(source_id)
            canonical_root = self._resolve_patient(canonical_id)
            if source_root == canonical_root:
                raise ProcessingError("registry_reference_invalid")
            if self._clusters_have_hospital_id_conflict(source_root, canonical_root):
                raise ProcessingError("registry_cluster_conflict")
            self._execute(
                "UPDATE patients SET status = 'merged', canonical_id = ? "
                "WHERE patient_id = ?",
                (canonical_root, source_root),
            )

    def finalize_patient(self, patient_id: str) -> None:
        """Mark a canonical provisional patient finalized after reconciliation."""
        if not self._patient_exists(patient_id):
            raise ProcessingError("registry_reference_invalid")
        with self.transaction():
            self._execute(
                "UPDATE patients SET status = 'finalized' "
                "WHERE patient_id = ? AND canonical_id IS NULL",
                (patient_id,),
            )

    def iter_patient_ids(self) -> Iterator[str]:
        """Iterate IDs in a stable order without loading the registry into memory."""
        self._ensure_open()
        cursor = self._execute(
            "SELECT patient_id FROM patients ORDER BY patient_id"
        )
        for row in cursor:
            yield row[0]

    @property
    def patient_count(self) -> int:
        self._ensure_open()
        return int(self._execute("SELECT COUNT(*) FROM patients").fetchone()[0])

    @property
    def record_count(self) -> int:
        self._ensure_open()
        return int(self._execute("SELECT COUNT(*) FROM record_mappings").fetchone()[0])

    def close(self) -> None:
        if self._closed:
            return
        try:
            try:
                self._connection.close()
            except sqlite3.Error:
                raise ProcessingError("registry_storage_error") from None
        finally:
            self._encryption_key = b""
            self._index_key = b""
            try:
                self._temporary_directory.cleanup()
            except OSError:
                raise ProcessingError("registry_storage_error") from None
            finally:
                self._closed = True

    def _connect(self, database_path: Path) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(database_path, isolation_level=None)
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            self._connection = connection
            self._initialize_schema()
            return connection
        except ProcessingError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error:
            if connection is not None:
                connection.close()
            raise ProcessingError("registry_storage_invalid") from None

    def _initialize_schema(self) -> None:
        self._execute(
            "CREATE TABLE patients ("
            "patient_id TEXT PRIMARY KEY, "
            "status TEXT NOT NULL CHECK(status IN ('provisional','finalized','merged')), "
            "origin_key BLOB NOT NULL UNIQUE, "
            "canonical_id TEXT NULL REFERENCES patients(patient_id))"
        )
        self._execute(
            "CREATE TABLE record_mappings ("
            "record_key BLOB PRIMARY KEY, "
            "source_ciphertext BLOB NOT NULL, "
            "patient_id TEXT NULL REFERENCES patients(patient_id), "
            "decision TEXT NOT NULL CHECK(decision IN ('LINK','CREATE','UNRESOLVED')), "
            "confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0), "
            "evidence_ciphertext BLOB NOT NULL)"
        )
        self._execute(
            "CREATE TABLE identity_values ("
            "record_key BLOB NOT NULL REFERENCES record_mappings(record_key) ON DELETE CASCADE, "
            "patient_id TEXT NOT NULL REFERENCES patients(patient_id), "
            "field TEXT NOT NULL, "
            "position INTEGER NOT NULL, "
            "ciphertext BLOB NOT NULL, "
            "PRIMARY KEY(record_key, field, position))"
        )
        self._execute(
            "CREATE TABLE block_index ("
            "kind TEXT NOT NULL, "
            "namespace_token BLOB NOT NULL, "
            "value_token BLOB NOT NULL, "
            "patient_id TEXT NOT NULL REFERENCES patients(patient_id), "
            "PRIMARY KEY(kind, namespace_token, value_token, patient_id))"
        )
        self._execute(
            "CREATE INDEX block_index_lookup "
            "ON block_index(kind, namespace_token, value_token)"
        )
        self._execute(
            "CREATE INDEX identity_values_patient "
            "ON identity_values(patient_id, field)"
        )
        self._execute(
            "CREATE INDEX record_mappings_patient "
            "ON record_mappings(patient_id)"
        )

    def _execute(
        self, statement: str, parameters: tuple[object, ...] = ()
    ) -> sqlite3.Cursor:
        self._ensure_open()
        try:
            return self._connection.execute(statement, parameters)
        except sqlite3.Error:
            raise ProcessingError("registry_storage_error") from None

    def _rollback(self) -> None:
        try:
            self._connection.rollback()
        except sqlite3.Error:
            raise ProcessingError("registry_storage_error") from None

    def _record_key(self, source_sha256: str, record_locator: str) -> bytes:
        if (
            len(source_sha256) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in source_sha256)
            or not record_locator
        ):
            raise ProcessingError("registry_reference_invalid")
        message = (
            b"record\x00"
            + source_sha256.lower().encode("ascii")
            + b"\x00"
            + record_locator.encode("utf-8")
        )
        return _hmac_digest(self._index_key, message)

    def _encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(_NONCE_LENGTH)
        return nonce + AESGCM(self._encryption_key).encrypt(
            nonce, plaintext, associated_data
        )

    def _decrypt_json(self, ciphertext: bytes, associated_data: bytes) -> object:
        if len(ciphertext) < _NONCE_LENGTH + 16:
            raise ProcessingError("registry_data_invalid")
        nonce, encrypted = ciphertext[:_NONCE_LENGTH], ciphertext[_NONCE_LENGTH:]
        try:
            plaintext = AESGCM(self._encryption_key).decrypt(
                nonce, encrypted, associated_data
            )
            return json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, UnicodeError, ValueError):
            raise ProcessingError("registry_data_invalid") from None

    def _patient_exists(self, patient_id: str) -> bool:
        self._ensure_open()
        row = self._execute(
            "SELECT 1 FROM patients WHERE patient_id = ?", (patient_id,)
        ).fetchone()
        return row is not None

    def _resolve_patient(self, patient_id: str) -> str:
        current = patient_id
        visited: set[str] = set()
        while True:
            if current in visited:
                raise ProcessingError("registry_data_invalid")
            visited.add(current)
            row = self._execute(
                "SELECT canonical_id FROM patients WHERE patient_id = ?",
                (current,),
            ).fetchone()
            if row is None:
                raise ProcessingError("registry_reference_invalid")
            canonical_id = row[0]
            if canonical_id is None:
                return current
            current = canonical_id

    def _clusters_have_hospital_id_conflict(
        self, first_root: str, second_root: str
    ) -> bool:
        row = self._execute(
            "WITH RECURSIVE first_family(patient_id) AS ("
            "SELECT ? UNION ALL "
            "SELECT patients.patient_id FROM patients "
            "JOIN first_family ON patients.canonical_id = first_family.patient_id"
            "), second_family(patient_id) AS ("
            "SELECT ? UNION ALL "
            "SELECT patients.patient_id FROM patients "
            "JOIN second_family ON patients.canonical_id = second_family.patient_id"
            ") "
            "SELECT 1 FROM block_index first_block "
            "JOIN block_index second_block "
            "ON first_block.kind = second_block.kind "
            "AND first_block.namespace_token = second_block.namespace_token "
            "AND first_block.value_token != second_block.value_token "
            "WHERE first_block.kind = 'hospital_identifier' "
            "AND first_block.patient_id IN (SELECT patient_id FROM first_family) "
            "AND second_block.patient_id IN (SELECT patient_id FROM second_family) "
            "LIMIT 1",
            (first_root, second_root),
        ).fetchone()
        return row is not None

    @staticmethod
    def _coerce_decision(value: IdentityDecision | str) -> IdentityDecision:
        try:
            return value if isinstance(value, IdentityDecision) else IdentityDecision(value)
        except ValueError:
            raise ProcessingError("registry_decision_invalid") from None

    @staticmethod
    def _validate_decision(
        patient_id: str | None,
        decision: IdentityDecision,
        confidence: float,
    ) -> None:
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or confidence < 0
            or confidence > 1
        ):
            raise ProcessingError("registry_confidence_invalid")
        if (decision is IdentityDecision.UNRESOLVED) != (patient_id is None):
            raise ProcessingError("registry_decision_invalid")

    def _ensure_open(self) -> None:
        if self._closed:
            raise ProcessingError("registry_storage_error")


def _hmac_digest(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, _SHA256).digest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _identity_aad(record_key: bytes, field_name: str, position: int) -> bytes:
    return (
        b"identity\x00"
        + record_key
        + b"\x00"
        + field_name.encode("ascii")
        + b"\x00"
        + str(position).encode("ascii")
    )


__all__ = ["EncryptedIdentityRegistry"]
