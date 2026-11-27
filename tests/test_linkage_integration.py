from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from lumen_ex.config import PipelineConfig
from lumen_ex.contracts.identity import IdentityDecision
from lumen_ex.errors import ProcessingError
from lumen_ex.identity import extract_identity
from lumen_ex.ingestion import StreamingIngestor
from lumen_ex.registry import EncryptedIdentityRegistry
from lumen_ex.release import ReleasePipeline
from lumen_ex.security import SensitiveDataLeakScanner


_SECRET = "synthetic-integration-secret"
_ALIASES = PipelineConfig(issuer_aliases=(
    ("metadata", "East", "east"),
    ("metadata", "EastExport", "east"),
    ("metadata", "West", "west"),
    ("fhir", "urn:test:east", "east"),
))
_NAME = "Asha Sharma"
_BASE = {"patient_name": _NAME, "hospital_code": "East", "MRN": "SYN-101"}


class ReleaseLinkageIntegrationTests(unittest.TestCase):
    def _prepare(self, files, config=_ALIASES):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            source = workspace / "input"
            source.mkdir()
            for filename, data in files:
                (source / filename).write_text(
                    data if isinstance(data, str) else json.dumps(data, ensure_ascii=False),
                    encoding="utf-8",
                )
            pipeline = ReleasePipeline(
                source, workspace / "output", config, _SECRET, SensitiveDataLeakScanner()
            )
            records = tuple(StreamingIngestor().ingest(source).records)
            with EncryptedIdentityRegistry.temporary(_SECRET, workspace) as registry:
                prepared = pipeline._prepare_records(records, registry, {})
                decisions = [
                    registry.get_record_mapping(item.parsed.source.sha256, item.parsed.locator)
                    for item in prepared
                ]
            self.assertFalse(registry.database_path.exists())
            return decisions, prepared

    def test_production_routes_csv_tsv_json_fhir_and_note_to_one_patient(self):
        files = [
            ("a.csv", "Patient Name,MRN,Hospital Code,DOB\nAsha Sharma,SYN-101,East,1982-04-13\n"),
            ("b.tsv", "Patient Name\tMRN\tHospital Code\tDOB\nआशा शर्मा\tSYN-101\tEastExport\t1982-04-13\n"),
            ("c.json", {"patient": _BASE, "panels": [{"results": [{"value": 13}]}]}),
            ("d.json", {"resourceType": "Patient", "name": [{"text": _NAME}],
                        "identifier": [{"system": "urn:test:east", "value": "SYN-101"}]}),
            ("e.txt", "Patient ka naam: Aasha Sharma\nDOB: 13/04/1982\nHb: 13\n"),
            ("f.txt", "Patient Name: Asha Sharma\nDOB: 15/09/1990\nHb: 14\n"),
        ]
        decisions, prepared = self._prepare(files)
        self.assertEqual([entry.decision for entry in decisions],
                         [IdentityDecision.CREATE] + [IdentityDecision.LINK] * 4
                         + [IdentityDecision.UNRESOLVED])
        self.assertEqual(len({entry.patient_id for entry in decisions[:5]}), 1)
        self.assertIsNone(decisions[-1].patient_id)
        self.assertEqual(prepared[2].normalized.fields, {"value": 13})

    def test_composite_and_collision_cases_use_sequential_resolution(self):
        cases = (
            ("name only", {}, {"patient_name": _NAME}, IdentityDecision.UNRESOLVED),
            ("DOB", {"DOB": "1982-04-13"}, {"patient_name": _NAME, "DOB": "1982-04-13"}, IdentityDecision.LINK),
            ("relative", {"Father Name": "Mohan Sharma"}, {"patient_name": _NAME, "Father Name": "मोहन शर्मा"}, IdentityDecision.LINK),
            ("different relative", {"Father Name": "Mohan Sharma"},
             {"patient_name": _NAME, "Father Name": "Ramesh Kumar"}, IdentityDecision.UNRESOLVED),
            ("DOB and relative", {"DOB": "1982-04-13", "Father Name": "Mohan Sharma"},
             {"patient_name": _NAME, "DOB": "1982-04-13", "Father Name": "Mohan Sharma"}, IdentityDecision.LINK),
            ("village and age", {"village": "Rampur", "age": 42},
             {"patient_name": _NAME, "village": "Rampur", "age": 43}, IdentityDecision.LINK),
            ("village but conflicting age", {"village": "Rampur", "age": 42},
             {"patient_name": _NAME, "village": "Rampur", "age": 60}, IdentityDecision.UNRESOLVED),
            ("village but conflicting DOB", {"village": "Rampur", "age": 42, "DOB": "1982-04-13"},
             {"patient_name": _NAME, "village": "Rampur", "age": 42, "DOB": "1982-05-13"}, IdentityDecision.UNRESOLVED),
            ("same MRN different hospital", {}, {**_BASE, "hospital_code": "West"}, IdentityDecision.UNRESOLVED),
            ("conflicting issuer", {}, {**_BASE, "hospital_name": "West"}, IdentityDecision.UNRESOLVED),
            ("cross-hospital independent evidence", {"DOB": "1982-04-13"},
             {**_BASE, "hospital_code": "West", "DOB": "1982-04-13"}, IdentityDecision.LINK),
            ("reordered cross-script name", {}, {**_BASE, "patient_name": "शर्मा आशा"}, IdentityDecision.LINK),
            ("partial name and DOB", {"DOB": "1982-04-13"},
             {**_BASE, "patient_name": "Asha", "DOB": "1982-04-13"}, IdentityDecision.LINK),
            ("similar name conflicting DOB", {"DOB": "1982-04-13"},
             {**_BASE, "patient_name": "Usha Sharma", "DOB": "1982-05-13"}, IdentityDecision.UNRESOLVED),
            ("same issuer insurance", {"insurance_id": "POL-123", "insurer": "PlanOne"},
             {"patient_name": _NAME, "insurance_id": "POL-123", "insurer": "PlanOne"}, IdentityDecision.LINK),
            ("different issuer insurance", {"insurance_id": "POL-123", "insurer": "PlanOne"},
             {"patient_name": _NAME, "insurance_id": "POL-123", "insurer": "PlanTwo"}, IdentityDecision.UNRESOLVED),
            ("unscoped insurance", {"insurance_id": "POL-123", "insurer": "PlanOne"},
             {"patient_name": _NAME, "insurance_id": "POL-123"}, IdentityDecision.UNRESOLVED),
            ("conflicting scoped insurance despite name and DOB",
             {"insurance_id": "POL-123", "insurer": "PlanOne", "DOB": "1982-04-13"},
             {"patient_name": _NAME, "insurance_id": "POL-456", "insurer": "PlanOne",
              "DOB": "1982-04-13"}, IdentityDecision.UNRESOLVED),
            ("shared family phone and homonym", {"phone": "9876543210"},
             {"patient_name": _NAME, "phone": "9876543210"}, IdentityDecision.UNRESOLVED),
            ("phone with independent DOB and name", {"phone": "9876543210", "DOB": "1982-04-13"},
             {"patient_name": _NAME, "phone": "9876543210", "DOB": "1982-04-13"}, IdentityDecision.LINK),
        )
        for label, anchor, incoming, expected in cases:
            with self.subTest(label=label):
                decisions, _ = self._prepare([("a.json", {**_BASE, **anchor}), ("b.json", incoming)])
                first, second = decisions
                self.assertEqual(first.decision, IdentityDecision.CREATE)
                self.assertEqual(second.decision, expected)
                self.assertEqual(second.patient_id, first.patient_id if expected is IdentityDecision.LINK else None)

    def test_unresolved_and_competing_records_are_not_backfilled(self):
        anchor = {**_BASE, "DOB": "1982-04-13"}
        decisions, _ = self._prepare([
            ("a.json", {"patient_name": _NAME, "DOB": "1982-04-13"}),
            ("b.json", anchor),
            ("c.json", {"patient_name": _NAME, "DOB": "1982-04-13", "value": 3}),
            ("d.json", {**_BASE, "hospital_code": "West", "MRN": "SYN-202"}),
            ("e.json", {**_BASE, "hospital_code": "West", "MRN": "SYN-202", "DOB": "1982-04-13"}),
            ("f.json", {"patient_name": _NAME, "DOB": "1982-04-13", "value": 4}),
        ])
        self.assertEqual([entry.decision for entry in decisions], [
            IdentityDecision.UNRESOLVED, IdentityDecision.CREATE, IdentityDecision.LINK,
            IdentityDecision.CREATE, IdentityDecision.LINK, IdentityDecision.UNRESOLVED,
        ])
        self.assertNotEqual(decisions[1].patient_id, decisions[3].patient_id)
        self.assertIsNone(decisions[0].patient_id)
        self.assertIsNone(decisions[-1].patient_id)

    def test_byte_identical_inputs_preserve_the_original_create_mapping(self):
        decisions, prepared = self._prepare([("a.json", _BASE), ("b.json", _BASE)])
        self.assertEqual([entry.decision for entry in decisions], [IdentityDecision.CREATE] * 2)
        self.assertEqual(decisions[0].patient_id, decisions[1].patient_id)
        self.assertEqual(prepared[0].linkage, prepared[1].linkage)
        different, _ = self._prepare([("a.json", _BASE), ("b.json", {**_BASE, "value": 12})])
        self.assertEqual(different[1].decision, IdentityDecision.LINK)

    def test_duplicate_with_conflicting_date_conventions_stays_unlinked(self):
        data = {**_BASE, "DOB": "04/05/1982"}
        config = PipelineConfig(date_order_overrides=(("a", "dmy"), ("b", "mdy")))
        _, prepared = self._prepare([("a.json", data), ("b.json", data)], config)
        first, second = prepared
        self.assertIsNotNone(first.linkage.patient_reference)
        self.assertIsNone(second.linkage.patient_reference)

    def test_blind_index_is_keyed_scoped_and_separate_from_ciphertext(self):
        identity = extract_identity({**_BASE, "phone": "9876543210"}, "synthetic.json", config=_ALIASES)
        source = "a" * 64
        with tempfile.TemporaryDirectory() as temp:
            def snapshot(secret):
                with EncryptedIdentityRegistry.temporary(secret, Path(temp)) as registry:
                    patient = registry.create_patient(source, identity.record_locator)
                    registry.add_record_mapping(source, identity.record_locator, patient, IdentityDecision.CREATE, 0.9)
                    registry.add_identity(patient, source, identity)
                    with closing(sqlite3.connect(registry.database_path)) as connection:
                        tokens = connection.execute(
                            "SELECT kind, namespace_token, value_token FROM block_index ORDER BY kind"
                        ).fetchall()
                    content = registry.database_path.read_bytes()
                    for value in (b"Asha Sharma", b"SYN-101", b"9876543210"):
                        self.assertNotIn(value, content)
                    namespace = identity.hospital_identifier[0].namespace
                    self.assertEqual(registry.find_candidates("hospital_identifier", "SYN101", namespace), (patient,))
                    self.assertFalse(registry.find_candidates("hospital_identifier", "SYN101", "West"))
                    path = registry.database_path
                self.assertFalse(path.exists())
                return tokens

            baseline = snapshot(_SECRET)
            self.assertEqual(baseline, snapshot(_SECRET))
            rotated = snapshot("rotated-integration-secret")
            for (kind, ns, token), (other_kind, other_ns, other_token) in zip(baseline, rotated, strict=True):
                self.assertEqual(kind, other_kind)
                self.assertNotEqual(ns, other_ns)
                self.assertNotEqual(token, other_token)

    def test_index_write_failure_rolls_back_assignment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "anchor.json").write_text(json.dumps(_BASE), encoding="utf-8")
            pipeline = ReleasePipeline(root, root / "output", _ALIASES, _SECRET, SensitiveDataLeakScanner())
            record, = StreamingIngestor().ingest(root).records
            with EncryptedIdentityRegistry.temporary(_SECRET, root) as registry:
                with patch.object(registry, "add_identity", side_effect=ProcessingError("registry_storage_error")):
                    prepared, = pipeline._prepare_records((record,), registry, {})
                self.assertEqual(prepared.result.error_code, "registry_storage_error")
                self.assertIsNone(registry.get_record_mapping(record.source.sha256, record.locator))
                self.assertEqual(registry.patient_count, 0)
