import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lumen_ex.errors import ProcessingError
import lumen_ex.ingestion as ingestion_module
from lumen_ex.ingestion import StreamingIngestor
from lumen_ex.identity import PatientIdentityNormalizer


class StreamingIngestorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "input"
        self.root.mkdir()
        self.ingestor = StreamingIngestor()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_json_lab_envelopes_inherit_only_from_the_owning_patient(self) -> None:
        groups = [
            {
                "patient": {"name": "Asha Sharma", "mrn": "MRN-A10"},
                "lab": {"panel": {"results": [
                    {"test": "Hb", "value": 12},
                    {"test": "WBC", "value": 5, "email": "asha@example.test"},
                    {"test": "Hb", "value": 13, "mrn": "MRN-B20"},
                ]}},
            },
            {"lab": {"panel": {"results": [{"test": "Hb", "value": 14}]}}},
        ]
        (self.root / "nested.json").write_text(
            json.dumps({"patient": {"name": "Other Person"}, "groups": groups}),
            encoding="utf-8",
        )
        source = next(self.ingestor.discover(self.root))
        normalizer = PatientIdentityNormalizer()
        records = [normalizer.normalize(record) for record in self.ingestor.read(source)]
        self.assertEqual([record.locator for record in records], [
            "/groups/0/lab/panel/results/0", "/groups/0/lab/panel/results/1",
            "/groups/0/lab/panel/results/2", "/groups/1/lab/panel/results/0",
        ])
        first, second, conflicting, empty = [record.identities[0] for record in records]
        self.assertEqual(first.hospital_identifier, second.hospital_identifier)
        self.assertEqual(first.name[0].original, "Asha Sharma")
        self.assertEqual(first.inherited_fields, {"name", "hospital_identifier"})
        self.assertEqual(second.email[0].original, "asha@example.test")
        self.assertTrue(conflicting.context_conflict)
        self.assertEqual(conflicting.hospital_identifier[0].original, "MRN-B20")
        self.assertFalse(conflicting.name)
        self.assertFalse(empty.name or empty.hospital_identifier)
        self.assertEqual(records[0].fields, {"test": "Hb", "value": 12})

    def test_json_lab_panels_share_the_root_patient(self) -> None:
        document = {
            "panels": [{"results": [{"value": 12}]}, {"results": [{"value": 13}]}],
            "patient": {"name": "Asha Sharma"},
        }
        (self.root / "panels.json").write_text(json.dumps(document), encoding="utf-8")
        source = next(self.ingestor.discover(self.root))
        for record in self.ingestor.read(source):
            identity, = PatientIdentityNormalizer().normalize(record).identities
            self.assertEqual(identity.name[0].original, "Asha Sharma")

    def test_discovery_is_sorted_and_hashes_files_incrementally(self) -> None:
        second = self.root / "z.json"
        first = self.root / "a.txt"
        second.write_text("{}", encoding="utf-8")
        first.write_text("note", encoding="utf-8")

        sources = list(self.ingestor.discover(self.root))

        self.assertEqual(
            [source.relative_path for source in sources],
            ["a.txt", "z.json"],
        )
        self.assertEqual(
            sources[0].sha256,
            hashlib.sha256(b"note").hexdigest(),
        )
        self.assertEqual(sources[0].media_type, "text/plain")

    def test_csv_tsv_and_batches_preserve_zero_based_row_locators(self) -> None:
        (self.root / "a.csv").write_text(
            "Patient Name,Age\nAsha,30\nBina,31\n", encoding="utf-8"
        )
        (self.root / "b.tsv").write_text(
            "Patient Name\tAge\nChandra\t32\n", encoding="utf-8"
        )

        batches = list(self.ingestor.iter_batches(self.root, batch_size=2))

        self.assertEqual([len(batch) for batch in batches], [2, 1])
        self.assertEqual(
            [(record.source.relative_path, record.locator) for batch in batches for record in batch],
            [("a.csv", "row:0"), ("a.csv", "row:1"), ("b.tsv", "row:0")],
        )
        self.assertEqual(batches[0][0].values["Patient Name"], "Asha")

    def test_csv_preserves_duplicate_headers_and_ragged_cells(self) -> None:
        path = self.root / "ragged.csv"
        path.write_text(
            "Name,Name,Age\nAsha,Alias\nBina,Other,32,overflow\n",
            encoding="utf-8",
        )
        source = next(self.ingestor.discover(self.root))

        records = list(self.ingestor.read(source))

        self.assertEqual(records[0].values, {"Name": "Alias", "Age": None})
        self.assertEqual(records[0].structure["headers"], ("Name", "Name", "Age"))
        self.assertEqual(records[0].structure["cells"], ("Asha", "Alias"))
        self.assertEqual(records[1].values[None], ["overflow"])
        self.assertEqual(records[1].structure["cells"], ("Bina", "Other", "32", "overflow"))

    def test_tsv_supports_quoted_delimiters_and_embedded_newlines(self) -> None:
        path = self.root / "quoted.tsv"
        path.write_text('Name\tNote\nAsha\t"first\tsecond"\nBina\t"line one\nline two"\n', encoding="utf-8")
        source = next(self.ingestor.discover(self.root))

        records = list(self.ingestor.read(source))

        self.assertEqual(records[0].values["Note"], "first\tsecond")
        self.assertEqual(records[1].values["Note"], "line one\r\nline two")

    def test_decodes_utf8_bom_utf16_and_cp1252(self) -> None:
        examples = (
            ("utf8.csv", "Name\nAsha\n".encode("utf-8-sig"), "Asha"),
            ("utf16.csv", "Name\nBina\n".encode("utf-16"), "Bina"),
            ("legacy.csv", "Name\nJosé\n".encode("cp1252"), "José"),
        )
        for filename, contents, expected in examples:
            with self.subTest(filename=filename):
                path = self.root / filename
                path.write_bytes(contents)
                source = next(
                    item
                    for item in self.ingestor.discover(self.root)
                    if item.relative_path == filename
                )
                record = next(self.ingestor.read(source))
                self.assertEqual(record.values["Name"], expected)

    def test_streams_nested_json_arrays_and_escapes_pointer_segments(self) -> None:
        path = self.root / "nested.json"
        path.write_text(
            json.dumps(
                {
                    "metadata": {"source": "synthetic"},
                    "records": [
                        {"patient": {"name": "Asha"}},
                        {"patient": {"name": "Bina"}},
                    ],
                }
            ),
            encoding="utf-8",
        )
        source = next(self.ingestor.discover(self.root))

        records = list(self.ingestor.read(source))

        self.assertEqual([record.locator for record in records], ["/records/0", "/records/1"])
        self.assertEqual(records[0].values["patient"]["name"], "Asha")

    def test_json_pointer_preserves_dots_and_escapes_slash_and_tilde(self) -> None:
        path = self.root / "special.json"
        path.write_text(
            json.dumps(
                {"a.b": {"folder/name~1": {"records": [{"value": "safe"}]}}}
            ),
            encoding="utf-8",
        )
        source = next(self.ingestor.discover(self.root))

        record = next(self.ingestor.read(source))

        self.assertEqual(record.locator, "/a.b/folder~1name~01/records/0")
        self.assertEqual(record.values, {"value": "safe"})

    def test_json_record_array_nested_inside_unselected_array(self) -> None:
        path = self.root / "groups.json"
        path.write_text(
            '{"groups":[{"records":[{"id":"a"},{"id":"b"}]}]}',
            encoding="utf-8",
        )
        source = next(self.ingestor.discover(self.root))

        records = list(self.ingestor.read(source))

        self.assertEqual(
            [record.locator for record in records],
            ["/groups/0/records/0", "/groups/0/records/1"],
        )

    def test_streams_root_arrays_and_single_json_documents(self) -> None:
        array_path = self.root / "array.json"
        array_path.write_text('[{"name":"Asha"},{"name":"Bina"}]', encoding="utf-8")
        array_source = next(self.ingestor.discover(self.root))
        array_records = list(self.ingestor.read(array_source))
        self.assertEqual([record.locator for record in array_records], ["/0", "/1"])

        document_path = self.root / "patient.json"
        document_path.write_text('{"resourceType":"Patient","name":[{"text":"Asha"}]}', encoding="utf-8")
        document_source = next(
            item
            for item in self.ingestor.discover(self.root)
            if item.relative_path == "patient.json"
        )
        document = next(self.ingestor.read(document_source))
        self.assertEqual(document.locator, "doc")
        self.assertEqual(document.values["resourceType"], "Patient")

    def test_bundle_is_preserved_as_one_document_record(self) -> None:
        path = self.root / "bundle.json"
        bundle = {
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                {"resource": {"resourceType": "Observation", "id": "obs"}},
                {"resource": {"resourceType": "Patient", "id": "patient"}},
            ],
        }
        path.write_text(json.dumps(bundle), encoding="utf-8")
        source = next(self.ingestor.discover(self.root))

        records = list(self.ingestor.read(source))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].locator, "doc")
        self.assertEqual(records[0].values, bundle)
        self.assertEqual(source.detected_format, ingestion_module.InputFormat.JSON)

    def test_fhir_format_is_recorded_after_content_validation(self) -> None:
        path = self.root / "patient.json"
        path.write_text('{"resourceType":"Patient","id":"p"}', encoding="utf-8")

        result = self.ingestor.ingest(self.root)

        source = result.files[0].source
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.detected_format, ingestion_module.InputFormat.FHIR)
        self.assertEqual(source.media_type, "application/fhir+json")
        self.assertEqual(next(result.records).locator, "doc")

    def test_text_note_is_one_document_record(self) -> None:
        path = self.root / "note.txt"
        path.write_text("Name: Asha\nAge: 30", encoding="utf-8")
        source = next(self.ingestor.discover(self.root))

        record = next(self.ingestor.read(source))

        self.assertEqual(record.locator, "doc")
        self.assertEqual(record.values["text"], "Name: Asha\r\nAge: 30")

    def test_empty_unsupported_and_malformed_inputs_fail_with_safe_codes(self) -> None:
        (self.root / "empty.csv").write_bytes(b"")
        (self.root / "unsupported.xml").write_text("<root/>", encoding="utf-8")
        (self.root / "broken.json").write_text('{"records":[', encoding="utf-8")
        sources = {item.relative_path: item for item in self.ingestor.discover(self.root)}

        with self.assertRaises(ProcessingError) as empty:
            next(self.ingestor.read(sources["empty.csv"]))
        self.assertEqual(empty.exception.code, "empty_file")

        with self.assertRaises(ProcessingError) as unsupported:
            next(self.ingestor.read(sources["unsupported.xml"]))
        self.assertEqual(unsupported.exception.code, "unsupported_format")

        with self.assertRaises(ProcessingError) as malformed:
            list(self.ingestor.read(sources["broken.json"]))
        self.assertEqual(malformed.exception.code, "JSONDecodeError")

    def test_ingest_quarantines_bad_files_without_aborting_valid_files(self) -> None:
        (self.root / "good.csv").write_text("Name\nAsha\n", encoding="utf-8")
        (self.root / "broken.json").write_text(
            '{"name":"RawSensitiveValue","records":[', encoding="utf-8"
        )
        (self.root / "unsupported.xml").write_text("<root/>", encoding="utf-8")
        (self.root / "wrong.csv").write_text('{"records":[]}', encoding="utf-8")
        (self.root / "binary.txt").write_bytes(b"\x00\x01\x02")
        (self.root / "empty.txt").write_bytes(b"")

        result = self.ingestor.ingest(self.root)
        statuses = {item.relative_path: item for item in result.files}
        records = list(result.records)

        self.assertEqual(result.statistics.files_discovered, 6)
        self.assertEqual(result.statistics.files_ingested, 1)
        self.assertEqual(result.statistics.files_quarantined, 5)
        self.assertEqual(result.statistics.records_parsed, 1)
        self.assertEqual([record.source.relative_path for record in records], ["good.csv"])
        self.assertEqual(statuses["broken.json"].error_code, "JSONDecodeError")
        self.assertEqual(statuses["unsupported.xml"].error_code, "unsupported_format")
        self.assertEqual(statuses["wrong.csv"].error_code, "format_mismatch")
        self.assertEqual(statuses["binary.txt"].error_code, "unsupported_format")
        self.assertEqual(statuses["empty.txt"].error_code, "empty_file")
        self.assertNotIn("RawSensitiveValue", repr(result))

    def test_json_depth_over_limit_is_quarantined_safely(self) -> None:
        path = self.root / "deep.json"
        path.write_text("[" * 513 + "0" + "]" * 513, encoding="utf-8")

        result = self.ingestor.ingest(self.root)

        self.assertEqual(result.files[0].error_code, "json_depth_exceeded")

    def test_source_is_unchanged_and_changed_sources_are_rejected(self) -> None:
        path = self.root / "source.txt"
        path.write_text("stable text", encoding="utf-8")
        original_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        source = next(self.ingestor.discover(self.root))
        record = next(self.ingestor.read(source))
        self.assertEqual(record.values["text"], "stable text")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), original_hash)

        path.write_text("changed text", encoding="utf-8")
        with self.assertRaises(ProcessingError) as changed:
            next(self.ingestor.read(source))
        self.assertEqual(changed.exception.code, "source_changed")

    def test_unreadable_file_is_reported_without_blocking_readable_files(self) -> None:
        (self.root / "good.txt").write_text("safe", encoding="utf-8")
        (self.root / "unreadable.txt").write_text("unavailable", encoding="utf-8")
        hash_file = ingestion_module._sha256_file

        def fail_for_one_file(path: Path) -> str:
            if path.name == "unreadable.txt":
                raise PermissionError
            return hash_file(path)

        with patch("lumen_ex.ingestion._sha256_file", side_effect=fail_for_one_file):
            result = self.ingestor.ingest(self.root)

        outcomes = {item.relative_path: item for item in result.files}
        self.assertEqual(outcomes["unreadable.txt"].error_code, "filesystem_error")
        self.assertEqual(
            [record.source.relative_path for record in result.records], ["good.txt"]
        )

    def test_ingestion_is_deterministic_for_identical_files(self) -> None:
        (self.root / "records.json").write_text(
            '{"records":[{"id":1},{"id":2}]}', encoding="utf-8"
        )

        first = self.ingestor.ingest(self.root)
        first_records = list(first.records)
        second = self.ingestor.ingest(self.root)
        second_records = list(second.records)

        self.assertEqual(first.statistics, second.statistics)
        self.assertEqual(
            [record.record_id for record in first_records],
            [record.record_id for record in second_records],
        )

    def test_symlink_is_quarantined_without_following_target(self) -> None:
        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("must not be read", encoding="utf-8")
        link = self.root / "linked.txt"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not permitted")

        result = self.ingestor.ingest(self.root)

        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].error_code, "unsafe_symlink")
        self.assertEqual(list(result.records), [])

        root_link = Path(self.temporary.name) / "input-link"
        try:
            os.symlink(self.root, root_link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation is not permitted")
        with self.assertRaises(ProcessingError) as linked_root:
            self.ingestor.ingest(root_link)
        self.assertEqual(linked_root.exception.code, "unsafe_symlink")

    def test_read_requires_a_discovered_input_root_and_batch_size_is_positive(self) -> None:
        (self.root / "example.txt").write_text("note", encoding="utf-8")
        with self.assertRaises(ProcessingError) as not_discovered:
            self.ingestor.read(
                # The record is irrelevant; source resolution must fail safely first.
                next(StreamingIngestor().discover(self.root))
            )
        self.assertEqual(not_discovered.exception.code, "invalid_record")
        with self.assertRaises(ValueError):
            list(self.ingestor.iter_batches(self.root, batch_size=0))


if __name__ == "__main__":
    unittest.main()
