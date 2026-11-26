import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lumen_ex.config import PipelineConfig, load_config
from lumen_ex.baseline import run_starter
from lumen_ex.contracts.models import (
    DetectionResult,
    InputFileMetadata,
    LinkageAction,
    LinkageDecision,
    OutputManifestEntry,
    ParsedRecord,
    PipelineReport,
    ProcessingStatus,
    SanitizationResult,
)
from lumen_ex.errors import ConfigurationError, ProcessingError
from lumen_ex.pipeline import Pipeline, PipelineStages
from lumen_ex.security import SensitiveDataLeakScanner


ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def test_loads_starter_policy_and_defaults_missing_values(self) -> None:
        config = load_config()
        self.assertEqual(config, PipelineConfig())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.yaml"
            path.write_text("age_band_years: 10\n", encoding="utf-8")
            self.assertEqual(load_config(path), PipelineConfig(age_band_years=10))

    def test_rejects_invalid_policy_values_and_keys(self) -> None:
        for content in (
            "age_band_years: 0\n",
            "unexpected: 2\n",
            "min_group_size: nope\n",
            "location_hierarchy: village,state,district\n",
            "date_order_overrides: registration/unknown=guess\n",
            "date_order_overrides: ../outside=dmy\n",
            "date_order_overrides: registration//bad=dmy\n",
            "ambiguous_date_action: guess\n",
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "policy.yaml"
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_config(path)

    def test_source_date_order_overrides_are_specific_and_unknowns_stay_unset(self) -> None:
        config = load_config()
        self.assertEqual(
            config.date_order_for_source(
                "registration/sanjeevani_registration (1).csv"
            ),
            "dmy",
        )
        self.assertEqual(
            config.date_order_for_source(
                "registration/arogya_legacy_export.csv"
            ),
            "mdy",
        )
        self.assertIsNone(
            config.date_order_for_source("misc/unknown_dates.txt")
        )


class ContractTests(unittest.TestCase):
    def test_validates_file_metadata_and_linkage_representation(self) -> None:
        metadata = InputFileMetadata(
            relative_path="records/example.json",
            sha256=hashlib.sha256(b"example").hexdigest(),
            size_bytes=7,
        )
        self.assertEqual(metadata.size_bytes, 7)
        with self.assertRaises(ValueError):
            InputFileMetadata("../outside", "0" * 64, 0)
        with self.assertRaises(ValueError):
            InputFileMetadata("C:\\outside.json", "0" * 64, 0)
        with self.assertRaises(ValueError):
            LinkageDecision(LinkageAction.LINK)
        self.assertEqual(LinkageDecision(LinkageAction.ABSTAIN).patient_reference, None)

    def test_manifest_serialization_keeps_official_file_entry_shape(self) -> None:
        manifest = OutputManifestEntry(
            input_sha256="a" * 64,
            output=None,
            status=ProcessingStatus.QUARANTINED,
            reason="unsupported_format",
        )
        self.assertEqual(
            manifest.to_official_dict(),
            {
                "input_sha256": "a" * 64,
                "output": None,
                "status": "quarantined",
                "reason": "unsupported_format",
            },
        )
        report = PipelineReport(files=(manifest,))
        self.assertEqual(report.to_official_dict()["schema"], "raksha-report/1")
        self.assertEqual(report.to_official_dict()["counts"]["files_quarantined"], 1)
        with self.assertRaises(ValueError):
            OutputManifestEntry(
                "b" * 64, "../../outside.json", ProcessingStatus.SANITIZED
            )
        with self.assertRaises(ValueError):
            OutputManifestEntry(
                "b" * 64,
                "sanitized/unsafe.json",
                ProcessingStatus.QUARANTINED,
                reason="unsupported_format",
            )

    def test_sanitization_requires_quarantine_reason(self) -> None:
        with self.assertRaises(ValueError):
            SanitizationResult(ProcessingStatus.QUARANTINED, "doc")


class PipelineTests(unittest.TestCase):
    def test_runs_placeholder_stages_and_quarantines_unsafe_result(self) -> None:
        class Normalizer:
            def normalize(self, record):
                return record

        class Detector:
            def detect(self, record):
                return DetectionResult(identifier_count=1)

        class Linker:
            def decide(self, record):
                return LinkageDecision(LinkageAction.ABSTAIN)

        class Privacy:
            def transform(self, record, detection, linkage):
                return SanitizationResult(
                    ProcessingStatus.SANITIZED,
                    record.locator,
                    identifiers_detected=detection.identifier_count,
                )

        class LeakScanner:
            def is_safe(self, result):
                if result.locator == "metadata":
                    return True
                return False

        quarantined = []

        class OutputGuard:
            def write(self, source, result):
                raise AssertionError

            def record(self, source, result):
                quarantined.append(result)
                return OutputManifestEntry(
                    source.sha256,
                    None,
                    ProcessingStatus.QUARANTINED,
                    result.error_code,
                )

            def finalize(self, report):
                self.report = report

        pipeline = Pipeline(
            PipelineStages(
                Normalizer(),
                Detector(),
                Linker(),
                Privacy(),
                LeakScanner(),
                OutputGuard(),
                OutputGuard(),
            )
        )
        record = _record()
        pipeline.run([record])
        self.assertEqual(quarantined[0].status, ProcessingStatus.QUARANTINED)
        self.assertEqual(quarantined[0].error_code, "leak_scan_failed")
        self.assertEqual(quarantined[0].locator, record.locator)

    def test_run_writes_only_safe_results_and_finalizes_report(self) -> None:
        written = []
        recorded = []
        finalized = []

        class Normalizer:
            def normalize(self, record):
                return record

        class Detector:
            def detect(self, record):
                return DetectionResult(identifier_count=0)

        class Linker:
            def decide(self, record):
                return LinkageDecision(LinkageAction.DO_NOT_LINK)

        class Privacy:
            def transform(self, record, detection, linkage):
                return SanitizationResult(ProcessingStatus.SANITIZED, record.locator)

        class LeakScanner:
            def is_safe(self, result):
                return True

        class Writer:
            def write(self, source, result):
                written.append((source, result))

        class Reporter:
            def record(self, source, result):
                recorded.append((source, result))
                return OutputManifestEntry(
                    source.sha256, "sanitized/records/note.txt", ProcessingStatus.SANITIZED
                )

            def finalize(self, report):
                finalized.append(report)

        record = _record()
        pipeline = Pipeline(
            PipelineStages(
                Normalizer(),
                Detector(),
                Linker(),
                Privacy(),
                LeakScanner(),
                Writer(),
                Reporter(),
            )
        )
        pipeline.run([record])
        self.assertEqual(len(written), 1)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(len(finalized), 1)
        self.assertEqual(finalized[0].files[0].input_sha256, record.source.sha256)

    def test_expected_processing_error_becomes_safe_quarantine(self) -> None:
        class FailedNormalizer:
            def normalize(self, record):
                raise ProcessingError("invalid_record")

        class Unused:
            def detect(self, record):
                raise AssertionError

            def decide(self, record):
                raise AssertionError

            def transform(self, record, detection, linkage):
                raise AssertionError

            def is_safe(self, result):
                return True

            def write(self, source, result):
                raise AssertionError

            def record(self, source, result):
                raise AssertionError

            def finalize(self, report):
                raise AssertionError

        result = Pipeline(
            PipelineStages(
                FailedNormalizer(),
                Unused(),
                Unused(),
                Unused(),
                Unused(),
                Unused(),
                Unused(),
            )
        ).process(_record())
        self.assertEqual(result.error_code, "invalid_record")
        self.assertEqual(result.status, ProcessingStatus.QUARANTINED)

    def test_unexpected_stage_errors_become_scanned_safe_quarantine(self) -> None:
        scanned = []

        class FailedNormalizer:
            def normalize(self, record):
                raise ValueError("SYNTHETIC-CANARY-ALPHA-8427")

        class Scanner:
            def is_safe(self, result):
                scanned.append(result)
                return True

        class Unused:
            def detect(self, record):
                raise AssertionError

            def decide(self, record):
                raise AssertionError

            def transform(self, record, detection, linkage):
                raise AssertionError

            def write(self, source, result):
                raise AssertionError

            def record(self, source, result):
                raise AssertionError

            def finalize(self, report):
                raise AssertionError

        result = Pipeline(
            PipelineStages(
                FailedNormalizer(),
                Unused(),
                Unused(),
                Unused(),
                Scanner(),
                Unused(),
                Unused(),
            )
        ).process(_record())
        self.assertEqual(result.status, ProcessingStatus.QUARANTINED)
        self.assertEqual(result.error_code, "internal_error")
        self.assertEqual(len(scanned), 1)
        self.assertNotIn("SYNTHETIC-CANARY-ALPHA-8427", repr(result))


class CliTests(unittest.TestCase):
    def test_baseline_clears_secret_and_canary_after_run(self) -> None:
        from starter import main as starter

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (input_root / "note.txt").write_text(
                "Clinical note without identifiers.", encoding="utf-8"
            )
            secret = "synthetic-secret-canary-phrase"
            scanner = SensitiveDataLeakScanner(canaries=(secret,))
            result = run_starter(
                input_root,
                output_root,
                PipelineConfig(),
                secret,
                scanner,
            )
            self.assertEqual(result, 0)
            self.assertEqual(starter.SECRET, b"")
            self.assertTrue(scanner.scan_text(secret))

    def test_cli_executes_starter_and_emits_validator_compatible_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (input_root / "note.txt").write_text(
                "Clinical note without identifiers.", encoding="utf-8"
            )
            environment = dict(
                os.environ, RAKSHA_SECRET="test-secret", PYTHONIOENCODING="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "main.py"),
                    "--input",
                    str(input_root),
                    "--output",
                    str(output_root),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn("test-secret", completed.stdout + completed.stderr)
            report = json.loads(
                (output_root / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["schema"], "raksha-report/1")
            validation = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "validate_output.py"),
                    "--input",
                    str(input_root),
                    "--output",
                    str(output_root),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                validation.returncode, 0, validation.stdout + validation.stderr
            )
            self.assertIn("CONTRACT OK", validation.stdout)

    def test_cli_fails_safely_when_secret_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            input_root.mkdir()
            environment = dict(os.environ)
            environment.pop("RAKSHA_SECRET", None)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "main.py"),
                    "--input",
                    str(input_root),
                    "--output",
                    str(root / "output"),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("secret_missing", completed.stderr)
            self.assertNotIn(str(input_root), completed.stderr)

    def test_cli_suppresses_singleton_without_leaking_structured_pii(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_root = root / "input"
            output_root = root / "output"
            input_root.mkdir()
            (input_root / "patients.csv").write_text(
                "patient_name,medication\nAsha Sharma,Paracetamol 500 mg\n",
                encoding="utf-8",
            )
            environment = dict(
                os.environ, RAKSHA_SECRET="test-secret", PYTHONIOENCODING="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "main.py"),
                    "--input",
                    str(input_root),
                    "--output",
                    str(output_root),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report_text = (output_root / "report.json").read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertEqual(report["files"][0]["status"], "suppressed")
            self.assertFalse((output_root / "sanitized" / "patients.csv").exists())
            self.assertNotIn("Asha Sharma", report_text)

            validation = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "validate_output.py"),
                    "--input",
                    str(input_root),
                    "--output",
                    str(output_root),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                validation.returncode, 0, validation.stdout + validation.stderr
            )
            self.assertIn("CONTRACT OK", validation.stdout)


def _record() -> ParsedRecord:
    metadata = InputFileMetadata(
        relative_path="records/note.txt",
        sha256=hashlib.sha256(b"note").hexdigest(),
        size_bytes=4,
    )
    return ParsedRecord(metadata, "doc", {"text": "hidden content"})


if __name__ == "__main__":
    unittest.main()
