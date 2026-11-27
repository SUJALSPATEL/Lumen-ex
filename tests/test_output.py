import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from lumen_ex.config import PipelineConfig, load_config
from lumen_ex.errors import ConfigurationError, ProcessingError
from lumen_ex.contracts.models import (
    InputFileMetadata,
    InputFormat,
    ParsedRecord,
    ProcessingStatus,
    SanitizationResult,
)
from lumen_ex.output import (
    OutputContractValidator,
    ReleaseRecord,
    SanitizedOutputWriter,
)
from lumen_ex.release import ReleasePipeline
from lumen_ex.security import SensitiveDataLeakScanner
from lumen_ex.identity import PatientIdentityNormalizer


class SanitizedOutputWriterTests(unittest.TestCase):
    def test_verified_issuers_link_across_files_and_remain_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            source.mkdir()
            policy = root / "policy.yaml"
            policy.write_text(
                "issuer_aliases: metadata|LegacyEast=issuer-east, "
                "metadata|ExportEast=issuer-east, metadata|Other=issuer-west\n",
                encoding="utf-8",
            )
            config = load_config(policy)
            policy.write_text(
                "issuer_aliases: metadata|LegacyEast=issuer-east, metadata|LegacyEast=issuer-west\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_config(policy)

            files = (
                ("a.json", "LegacyEast"),
                ("b.json", "ExportEast"),
                ("c.json", "Other"),
                ("d.json", None),
                ("e.json", None),
                ("f.json", "LegacyEast"),
            )
            for index, (filename, issuer) in enumerate(files):
                record = {"patient_name": "Asha Sharma", "mrn": "H-102", "value": 12 + index}
                if issuer:
                    record["hospital_code"] = issuer
                (source / filename).write_text(json.dumps(record), encoding="utf-8")

            def released(label, secret):
                output = root / label
                report = ReleasePipeline(
                    source, output, config, secret, SensitiveDataLeakScanner()
                ).run()
                records = {
                    row["file"]: row["patient"]
                    for row in map(json.loads, (output / "records.jsonl").read_text().splitlines())
                }
                return {
                    entry.input_sha256: (entry.output, records[entry.output])
                    for entry in report.files if entry.output
                }

            first = released("first", "synthetic-secret")
            self.assertEqual(first, released("repeat", "synthetic-secret"))
            rotated = released("rotated", "rotated-secret")
            hashes = [hashlib.sha256((source / filename).read_bytes()).hexdigest() for filename, _ in files]
            self.assertEqual(set(first), set(hashes))
            self.assertEqual(set(first), set(rotated))
            for released_records in (first, rotated):
                a, b, c, d, e, f = [released_records[digest][1] for digest in hashes]
                self.assertTrue(all((a, b, d, e, f)))
                self.assertEqual(a, b)
                self.assertEqual(a, f)
                self.assertIsNone(c)
                self.assertEqual(len({a, d, e}), 3)
            for digest in hashes:
                self.assertNotEqual(first[digest][0], rotated[digest][0])
                if first[digest][1] is not None:
                    self.assertNotEqual(first[digest][1], rotated[digest][1])

    def test_sibling_lab_outputs_share_a_patient_and_exclude_parent_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "input", root / "output"
            source.mkdir()
            parent = {"name": "Asha Sharma", "mrn": "SYN-H-5432", "phone": "9876543210"}
            children = [{"test": "Hemoglobin", "value": value} for value in range(12, 17)]
            (source / "results.json").write_text(
                json.dumps({"lab": {"results": children}, "patient": parent}),
                encoding="utf-8",
            )
            report = ReleasePipeline(
                source, output, PipelineConfig(), "test-secret", SensitiveDataLeakScanner()
            ).run()
            self.assertEqual(report.files[0].status, ProcessingStatus.SANITIZED)
            payload = (output / report.files[0].output).read_text(encoding="utf-8")
            for value in parent.values():
                self.assertNotIn(value, payload)
            exported = json.loads(payload)["lab"]["results"]
            rows = [json.loads(row) for row in (output / "records.jsonl").read_text().splitlines()]
            self.assertEqual([row["loc"] for row in rows], [f"/lab/results/{i}" for i in range(5)])
            self.assertTrue(rows[0]["patient"])
            for row, child, result in zip(rows, children, exported, strict=True):
                self.assertEqual(row["patient"], rows[0]["patient"])
                self.assertEqual(result, {**child, "patient_ref": row["patient"]})

    def test_release_preserves_lab_columns_and_clinical_note_phrases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "input", root / "output"
            source.mkdir()
            labs = "test,result,unit\n" + "Random Blood Sugar,142,mg/dL\n" * 5
            (source / "results.csv").write_text(labs, encoding="utf-8")
            observations = [
                {
                    "test": "Serum Sodium", "value": 135, "unit": "mmol/L",
                    "history": history,
                }
                for history in ("K/C/O HTN on treatment", "K/C/O DM2 x 6 yrs")
                for _ in range(3)
            ]
            (source / "results.json").write_text(
                json.dumps({"results": observations}), encoding="utf-8"
            )
            note_lines = (
                "K/C/O: J45.9\n"
                "Continue Amlodipine 5 mg 0-0-1 orally.\n"
                "Inh Salbutamol inhaler 100 mcg 2 puffs.\n"
                "Serum Creatinine 1.4 mg/dL | Platelet Count 200000 /uL\n"
                "BP 120/80\n"
            )
            for index in range(5):
                (source / f"note_{index}.txt").write_text(
                    note_lines + "Phone: 9876543210\n", encoding="utf-8"
                )
            report = ReleasePipeline(
                source, output, PipelineConfig(), "test-secret", SensitiveDataLeakScanner()
            ).run()
            self.assertEqual(report.records_processed, 16)
            for entry in report.files:
                self.assertIsNotNone(entry.output)
                payload = (output / entry.output).read_text(encoding="utf-8")
                if entry.output.endswith(".csv"):
                    self.assertEqual(payload, labs)
                elif entry.output.endswith(".json"):
                    self.assertEqual(json.loads(payload)["results"], observations)
                else:
                    self.assertIn(note_lines, payload)
                    self.assertNotIn("9876543210", payload)

    def test_path_tokens_preserve_prefixes_and_distinguish_identical_files(self) -> None:
        left = _metadata("private/ward/a.csv", b"same")
        right = _metadata("private/ward/b.csv", b"same")
        sibling = _metadata("private/other/a.csv", b"same")
        writer = SanitizedOutputWriter(
            Path("."), Path("."), SensitiveDataLeakScanner(), secret="test-secret"
        )
        paths = [writer._output_path(source).split("/") for source in (left, right, sibling)]
        self.assertEqual(paths[0][:-1], paths[1][:-1])
        self.assertEqual(paths[0][:2], paths[2][:2])
        self.assertNotEqual(paths[0][2], paths[2][2])
        self.assertEqual(len({tuple(path) for path in paths}), 3)
        with self.assertRaisesRegex(ProcessingError, "filesystem_error"):
            writer._output_path(left)

    def test_only_detected_format_controls_the_extension(self) -> None:
        writer = SanitizedOutputWriter(
            Path("."), Path("."), SensitiveDataLeakScanner(), secret="test-secret"
        )
        raw_hash = hashlib.sha256(b"").hexdigest()
        source = InputFileMetadata(
            "private.patient-id", raw_hash, 0, detected_format=InputFormat.JSON
        )
        self.assertRegex(writer._output_path(source), r"^sanitized/f_[a-z]{32}\.json$")
        unsupported = InputFileMetadata(
            "private.patient-id", raw_hash, 0, detected_format=InputFormat.UNSUPPORTED
        )
        with self.assertRaisesRegex(ProcessingError, "unsupported_format"):
            writer._output_path(unsupported)

    def test_csv_keeps_header_and_places_pseudonym_in_existing_identifier_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            raw = b"name,phone,diagnosis\nMina Rao,9876543210,hypertension\n"
            (input_root / "records.csv").write_bytes(raw)
            source = _metadata("records.csv", raw)
            parsed = ParsedRecord(
                source,
                "row:0",
                {
                    "name": "Mina Rao",
                    "phone": "9876543210",
                    "diagnosis": "hypertension",
                },
                {
                    "headers": ("name", "phone", "diagnosis"),
                    "cells": ("Mina Rao", "9876543210", "hypertension"),
                },
            )
            normalized = PatientIdentityNormalizer().normalize(parsed)
            result = SanitizationResult(
                ProcessingStatus.SANITIZED,
                "row:0",
                {
                    "name": "[REDACTED]",
                    "phone": "[REDACTED]",
                    "diagnosis": "hypertension",
                },
                output_structure={"headers": ["name", "phone", "diagnosis"]},
                output_relative_path="sanitized/records.csv",
                patient_pseudonym="PSN-0123456789ABCDEF",
            )
            writer = SanitizedOutputWriter(
                input_root, output_root, SensitiveDataLeakScanner(), secret="test-secret"
            )

            written = writer.write_file(
                source, [ReleaseRecord(parsed, normalized, result)]
            )

            self.assertEqual(
                written.manifest.status,
                ProcessingStatus.SANITIZED,
                written.manifest.reason,
            )
            self.assertEqual(written.records[0]["patient"], "PSN-0123456789ABCDEF")
            with (output_root / written.manifest.output).open(
                encoding="utf-8", newline=""
            ) as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[0], ["name", "phone", "diagnosis"])
            self.assertEqual(rows[1][1], "PSN-0123456789ABCDEF")
            self.assertEqual(rows[1][2], "hypertension")

    def test_json_omissions_remap_output_locator_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            raw = (
                b'{"_export_meta":{"source_path":"inbound/synthetic_marker_854.json"},'
                b'"visits":[{"diagnosis":"discarded"},{"diagnosis":"withheld"},'
                b'{"diagnosis":"stable"}]}'
            )
            (input_root / "visits.json").write_bytes(raw)
            source = _metadata("visits.json", raw)
            first = ParsedRecord(
                source, "/visits/0", {"diagnosis": "discarded"}
            )
            second = ParsedRecord(
                source, "/visits/1", {"diagnosis": "withheld"}
            )
            third = ParsedRecord(
                source, "/visits/2", {"diagnosis": "stable"}
            )
            first_normalized = PatientIdentityNormalizer().normalize(first)
            second_normalized = PatientIdentityNormalizer().normalize(second)
            third_normalized = PatientIdentityNormalizer().normalize(third)
            suppressed = SanitizationResult(
                ProcessingStatus.SUPPRESSED, "/visits/0", suppressed=True
            )
            quarantined = SanitizationResult(
                ProcessingStatus.QUARANTINED,
                "/visits/1",
                error_code="invalid_record",
            )
            sanitized = SanitizationResult(
                ProcessingStatus.SANITIZED,
                "/visits/2",
                {"diagnosis": "stable"},
                output_relative_path="sanitized/visits.json",
                generalized=True,
            )
            writer = SanitizedOutputWriter(
                input_root, output_root, SensitiveDataLeakScanner(), secret="test-secret"
            )

            written = writer.write_file(
                source,
                [
                    ReleaseRecord(first, first_normalized, suppressed),
                    ReleaseRecord(second, second_normalized, quarantined),
                    ReleaseRecord(third, third_normalized, sanitized),
                ],
            )

            self.assertEqual(written.manifest.status, ProcessingStatus.SANITIZED)
            self.assertEqual(written.records_quarantined, 1)
            self.assertEqual(written.records[0]["loc"], "/visits/2")
            self.assertEqual(written.records[0]["out"], "/visits/0")
            self.assertEqual(
                json.loads((output_root / written.manifest.output).read_text())[
                    "visits"
                ],
                [{"diagnosis": "stable"}],
            )
            self.assertEqual((input_root / "visits.json").read_bytes(), raw)
            sanitized = (output_root / written.manifest.output).read_text(encoding="utf-8")
            self.assertEqual(json.loads(sanitized)["_export_meta"]["source_path"], "[REDACTED]")
            self.assertNotIn("synthetic_marker_854", sanitized)

    def test_fhir_patient_pseudonym_preserves_bundle_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            document = {
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [
                    {
                        "fullUrl": "urn:uuid:p1",
                        "resource": {
                            "resourceType": "Patient",
                            "id": "p1",
                            "identifier": [
                                {"system": "urn:mrn", "value": "[REDACTED]"}
                            ],
                        },
                    },
                    {
                        "fullUrl": "urn:uuid:o1",
                        "resource": {
                            "resourceType": "Observation",
                            "id": "o1",
                            "subject": {"reference": "urn:uuid:p1"},
                        },
                    },
                ],
            }
            raw = (json.dumps(document) + "\n").encode("utf-8")
            (input_root / "bundle.json").write_bytes(raw)
            source = InputFileMetadata(
                "bundle.json",
                hashlib.sha256(raw).hexdigest(),
                len(raw),
                detected_format=InputFormat.FHIR,
                encoding="utf-8",
            )
            parsed = ParsedRecord(source, "doc", document)
            normalized = PatientIdentityNormalizer().normalize(parsed)
            result = SanitizationResult(
                ProcessingStatus.SANITIZED,
                "doc",
                document,
                output_relative_path="sanitized/bundle.json",
                patient_pseudonym="PSN-0123456789ABCDEF",
            )
            writer = SanitizedOutputWriter(
                input_root, output_root, SensitiveDataLeakScanner(), secret="test-secret"
            )

            written = writer.write_file(
                source, [ReleaseRecord(parsed, normalized, result)]
            )

            self.assertEqual(
                written.manifest.status,
                ProcessingStatus.SANITIZED,
                written.manifest.reason,
            )
            self.assertEqual(written.records[0]["patient"], "PSN-0123456789ABCDEF")
            output_document = json.loads(
                (output_root / written.manifest.output).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                output_document["entry"][0]["resource"]["identifier"][0]["value"],
                "PSN-0123456789ABCDEF",
            )
            self.assertEqual(
                output_document["entry"][1]["resource"]["subject"]["reference"],
                "urn:uuid:p1",
            )

    def test_quarantines_duplicate_csv_headers_without_losing_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            raw = b"name,name\nMina Rao,second value\n"
            (input_root / "duplicate.csv").write_bytes(raw)
            source = _metadata("duplicate.csv", raw)
            parsed = ParsedRecord(
                source,
                "row:0",
                {"name": "second value"},
                {
                    "headers": ("name", "name"),
                    "cells": ("Mina Rao", "second value"),
                },
            )
            normalized = PatientIdentityNormalizer().normalize(parsed)
            result = SanitizationResult(
                ProcessingStatus.SANITIZED,
                "row:0",
                {"name": "[REDACTED]"},
                output_structure={"headers": ["name", "name"]},
                output_relative_path="sanitized/duplicate.csv",
            )

            written = SanitizedOutputWriter(
                input_root, output_root, SensitiveDataLeakScanner(), secret="test-secret"
            ).write_file(source, [ReleaseRecord(parsed, normalized, result)])

            self.assertEqual(written.manifest.status, ProcessingStatus.QUARANTINED)
            self.assertEqual(written.manifest.reason, "format_mismatch")
            self.assertEqual(list((output_root / "sanitized").iterdir()), [])

    def test_quarantined_csv_row_is_omitted_without_discarding_safe_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            raw = (
                b"diagnosis,age\n"
                b"withheld diagnosis,30-34\n"
                b"hypertension,35-39\n"
            )
            (input_root / "records.csv").write_bytes(raw)
            source = _metadata("records.csv", raw)
            rejected = ParsedRecord(
                source,
                "row:0",
                {"diagnosis": "withheld diagnosis", "age": "30-34"},
            )
            retained = ParsedRecord(
                source,
                "row:1",
                {"diagnosis": "hypertension", "age": "35-39"},
            )
            normalized_rejected = PatientIdentityNormalizer().normalize(rejected)
            normalized_retained = PatientIdentityNormalizer().normalize(retained)
            rejected_result = SanitizationResult(
                ProcessingStatus.QUARANTINED,
                "row:0",
                error_code="invalid_record",
            )
            retained_result = SanitizationResult(
                ProcessingStatus.SANITIZED,
                "row:1",
                {"diagnosis": "hypertension", "age": "35-39"},
                output_structure={"headers": ["diagnosis", "age"]},
                output_relative_path="sanitized/records.csv",
            )

            written = SanitizedOutputWriter(
                input_root, output_root, SensitiveDataLeakScanner(), secret="test-secret"
            ).write_file(
                source,
                (
                    ReleaseRecord(rejected, normalized_rejected, rejected_result),
                    ReleaseRecord(retained, normalized_retained, retained_result),
                ),
            )

            self.assertEqual(written.manifest.status, ProcessingStatus.SANITIZED)
            self.assertEqual(written.records_quarantined, 1)
            self.assertEqual(len(written.records), 1)
            self.assertEqual(written.records[0]["loc"], "row:1")
            with (output_root / written.manifest.output).open(
                encoding="utf-8", newline=""
            ) as stream:
                self.assertEqual(
                    list(csv.reader(stream)),
                    [["diagnosis", "age"], ["hypertension", "35-39"]],
                )

    def test_merges_header_redactions_across_records_and_preserves_column_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            raw = b"Mina Rao,diagnosis\nrecord_1,hypertension\nrecord_2,diabetes\n"
            (input_root / "headers.csv").write_bytes(raw)
            source = _metadata("headers.csv", raw)
            headers = ("Mina Rao", "diagnosis")
            records = []
            for index, (name, diagnosis, output_headers) in enumerate(
                (
                    ("record_1", "hypertension", ["Mina Rao", "diagnosis"]),
                    ("record_2", "diabetes", ["[REDACTED]", "diagnosis"]),
                )
            ):
                parsed = ParsedRecord(
                    source,
                    f"row:{index}",
                    {"Mina Rao": name, "diagnosis": diagnosis},
                    {
                        "headers": headers,
                        "cells": (name, diagnosis),
                    },
                )
                normalized = PatientIdentityNormalizer().normalize(parsed)
                result = SanitizationResult(
                    ProcessingStatus.SANITIZED,
                    f"row:{index}",
                    {"Mina Rao": name, "diagnosis": diagnosis},
                    output_structure={"headers": output_headers},
                    output_relative_path="sanitized/headers.csv",
                )
                records.append(ReleaseRecord(parsed, normalized, result))
            scanner = SensitiveDataLeakScanner(canaries=("Mina Rao",))

            written = SanitizedOutputWriter(
                input_root, output_root, scanner, secret="test-secret"
            ).write_file(source, records)

            self.assertEqual(written.manifest.status, ProcessingStatus.SANITIZED)
            output = (output_root / written.manifest.output).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("Mina Rao", output)
            self.assertIn("field_1,diagnosis", output)
            self.assertIn("record_1,hypertension", output)
            self.assertIn("record_2,diabetes", output)

    def test_anonymizes_header_containing_unlabeled_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (output_root / "sanitized").mkdir(parents=True)
            raw = (
                b"Asha ZXCV12345678,diagnosis\n"
                b"stable,hypertension\n"
            )
            (input_root / "header.csv").write_bytes(raw)
            source = _metadata("header.csv", raw)
            parsed = ParsedRecord(
                source,
                "row:0",
                {"Asha ZXCV12345678": "stable", "diagnosis": "hypertension"},
                {
                    "headers": ("Asha ZXCV12345678", "diagnosis"),
                    "cells": ("stable", "hypertension"),
                },
            )
            normalized = PatientIdentityNormalizer().normalize(parsed)
            result = SanitizationResult(
                ProcessingStatus.SANITIZED,
                "row:0",
                {"Asha ZXCV12345678": "stable", "diagnosis": "hypertension"},
                output_structure={
                    "headers": ["Asha ZXCV12345678", "diagnosis"]
                },
                output_relative_path="sanitized/header.csv",
            )

            written = SanitizedOutputWriter(
                input_root, output_root, SensitiveDataLeakScanner(), secret="test-secret"
            ).write_file(
                source, [ReleaseRecord(parsed, normalized, result)]
            )

            self.assertEqual(written.manifest.status, ProcessingStatus.SANITIZED)
            with (output_root / written.manifest.output).open(
                encoding="utf-8", newline=""
            ) as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[0], ["field_1", "diagnosis"])
            self.assertEqual(rows[1], ["stable", "hypertension"])

    def test_release_pipeline_writes_scanned_cohort_and_valid_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            rows = ["name,phone,age,diagnosis"]
            for index in range(5):
                rows.append(
                    f"Patient {index},987654321{index},40,hypertension"
                )
            source_path = "\u0930\u094b\u0917\u0940-9876543210/ward-private/\u0938\u0940\u092e\u093e-MRN-41882.CSV"
            source_file = input_root / source_path
            source_file.parent.mkdir(parents=True)
            source_file.write_text(
                "\n".join(rows) + "\n", encoding="utf-8"
            )
            scanner = SensitiveDataLeakScanner(canaries=("test-secret",))

            with self.assertLogs("lumen_ex", level="INFO") as logs:
                report = ReleasePipeline(
                    input_root, output_root, PipelineConfig(), "test-secret", scanner
                ).run()

            report_data = json.loads(
                (output_root / "report.json").read_text(encoding="utf-8")
            )
            record_lines = (
                output_root / "records.jsonl"
            ).read_text(encoding="utf-8").splitlines()
            self.assertEqual(report.records_processed, 5)
            self.assertEqual(report_data["counts"]["records_processed"], 5)
            self.assertEqual(len(record_lines), 5)
            self.assertTrue(scanner.scan_tree(output_root / "sanitized"))
            records = [json.loads(line) for line in record_lines]
            self.assertTrue(all(record["patient"] for record in records))
            output_name = records[0]["file"]
            self.assertRegex(
                output_name,
                r"^sanitized/(?:d_[a-z]{32}/){2}f_[a-z]{32}\.csv$",
            )
            self.assertEqual(report_data["files"][0]["output"], output_name)
            self.assertTrue((output_root / output_name).is_file())
            for component in source_path.split("/"):
                self.assertNotIn(component, json.dumps(report_data, ensure_ascii=False))
                self.assertNotIn(component, "\n".join(record_lines + logs.output))
            self.assertEqual(source_file.read_text(encoding="utf-8"), "\n".join(rows) + "\n")
            self.assertTrue(all(record["file"] == output_name for record in records))
            OutputContractValidator().validate(
                output_root, report.files, records, report_data
            )
            second_output = root / "output-repeat"
            ReleasePipeline(
                input_root,
                second_output,
                PipelineConfig(),
                "test-secret",
                SensitiveDataLeakScanner(canaries=("test-secret",)),
            ).run()
            self.assertEqual(
                (output_root / output_name).read_bytes(),
                (second_output / output_name).read_bytes(),
            )
            self.assertEqual(
                (output_root / "records.jsonl").read_bytes(),
                (second_output / "records.jsonl").read_bytes(),
            )
            third_output = root / "output-different-secret"
            ReleasePipeline(
                input_root,
                third_output,
                PipelineConfig(),
                "different-secret",
                SensitiveDataLeakScanner(canaries=("different-secret",)),
            ).run()
            third_records = [
                json.loads(line)
                for line in (third_output / "records.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertNotEqual(third_records[0]["file"], output_name)
            self.assertRegex(
                third_records[0]["file"],
                r"^sanitized/(?:d_[a-z]{32}/){2}f_[a-z]{32}\.csv$",
            )

    def test_release_pipeline_preserves_high_precision_json_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            records = []
            for index in range(5):
                records.append(
                    {
                        "patient_name": f"Synthetic Patient {index}",
                        "phone": f"987654321{index}",
                        "age": 40,
                        "diagnosis": "hypertension",
                        "lab_result": "__EXACT_DECIMAL__",
                    }
                )
            raw = json.dumps({"records": records}).replace(
                '"__EXACT_DECIMAL__"', "123.456789012345678901"
            )
            (input_root / "cohort.json").write_text(raw, encoding="utf-8")

            report = ReleasePipeline(
                input_root,
                output_root,
                PipelineConfig(),
                "test-secret",
                SensitiveDataLeakScanner(canaries=("test-secret",)),
            ).run()

            self.assertEqual(report.records_processed, 5)
            sanitized = json.loads(
                (
                    output_root
                    / json.loads(
                        (output_root / "records.jsonl")
                        .read_text(encoding="utf-8")
                        .splitlines()[0]
                    )["file"]
                ).read_text(
                    encoding="utf-8"
                ),
                parse_float=Decimal,
            )
            self.assertEqual(
                [item["lab_result"] for item in sanitized["records"]],
                [Decimal("123.456789012345678901")] * 5,
            )

    def test_release_pipeline_anonymizes_unknown_single_word_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            rows = ["Orchid,diagnosis"] + [
                f"value_{index},hypertension" for index in range(5)
            ]
            (input_root / "cohort.csv").write_text(
                "\n".join(rows) + "\n", encoding="utf-8"
            )

            report = ReleasePipeline(
                input_root,
                output_root,
                PipelineConfig(),
                "test-secret",
                SensitiveDataLeakScanner(canaries=("test-secret",)),
            ).run()

            self.assertEqual(report.records_processed, 5)
            output_path = json.loads(
                (output_root / "records.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )["file"]
            with (output_root / output_path).open(
                encoding="utf-8", newline=""
            ) as stream:
                written_rows = list(csv.reader(stream))
            self.assertEqual(written_rows[0], ["field_1", "diagnosis"])
            self.assertEqual(
                [row[0] for row in written_rows[1:]],
                [f"value_{index}" for index in range(5)],
            )


def _metadata(relative_path: str, raw: bytes) -> InputFileMetadata:
    return InputFileMetadata(
        relative_path=relative_path,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        detected_format=InputFormat.JSON if relative_path.endswith(".json") else InputFormat.CSV,
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
