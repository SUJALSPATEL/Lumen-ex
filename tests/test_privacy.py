import hashlib
import unittest

from lumen_ex.config import PipelineConfig
from lumen_ex.contracts.models import (
    DetectionChannel,
    DetectionEntityType,
    DetectionFinding,
    DetectionResult,
    InputFileMetadata,
    LinkageAction,
    LinkageDecision,
    NormalizedRecord,
    ProcessingStatus,
)
from lumen_ex.errors import ProcessingError
from lumen_ex.privacy.dates import DateShifter
from lumen_ex.privacy.generalization import AgeGeneralizer, LocationGeneralizer
from lumen_ex.privacy.integrity import ClinicalIntegrityValidator
from lumen_ex.privacy.pseudonym import Pseudonymizer
from lumen_ex.privacy.risk import (
    QuasiIdentifierRiskAnalyzer,
    RareValueSuppressor,
    extract_quasi_identifiers,
)
from lumen_ex.privacy.transformer import PrivacyInput, PrivacyTransformer


class PseudonymizationTests(unittest.TestCase):
    def test_pseudonyms_are_stable_secret_scoped_and_linkage_gated(self) -> None:
        first = Pseudonymizer("first-secret")
        same_secret = Pseudonymizer("first-secret")
        other_secret = Pseudonymizer("second-secret")
        self.assertEqual(first.pseudonym_for("patient-cluster"), same_secret.pseudonym_for("patient-cluster"))
        self.assertNotEqual(first.pseudonym_for("patient-cluster"), other_secret.pseudonym_for("patient-cluster"))
        self.assertIsNone(first.for_decision(LinkageDecision(LinkageAction.ABSTAIN)))
        self.assertEqual(
            first.for_decision(LinkageDecision(LinkageAction.LINK, "patient-cluster")),
            first.pseudonym_for("patient-cluster"),
        )
        self.assertNotIn("patient-cluster", repr(first))


class DateTransformationTests(unittest.TestCase):
    def test_patient_date_shift_is_deterministic_and_preserves_intervals(self) -> None:
        shifter = DateShifter("date-secret", max_days=180)
        first = shifter.shift_text("2020-03-01 to 2020-03-11", "cluster-a")
        self.assertEqual(first, shifter.shift_text("2020-03-01 to 2020-03-11", "cluster-a"))
        start, end = first.split(" to ")
        self.assertEqual(
            (date_from_iso(end) - date_from_iso(start)).days,
            10,
        )
        self.assertNotEqual(
            first,
            DateShifter("different-secret", max_days=180).shift_text(
                "2020-03-01 to 2020-03-11", "cluster-a"
            ),
        )
        self.assertNotEqual(
            shifter.offset_for("cluster-a"),
            shifter.offset_for("cluster-b"),
        )

    def test_ambiguous_dates_are_redacted_without_order_hint(self) -> None:
        shifter = DateShifter("date-secret")
        self.assertEqual(
            shifter.shift_text("Seen 01/02/2020; BP 120/80", "cluster-a"),
            "Seen [DATE REDACTED]; BP 120/80",
        )

    def test_ambiguous_dates_can_be_configured_to_fail_closed(self) -> None:
        with self.assertRaises(ProcessingError) as raised:
            DateShifter(
                "date-secret",
                ambiguous_date_action="quarantine",
            ).shift_text("01/02/2020", "cluster-a")
        self.assertEqual(raised.exception.code, "privacy_date_format_ambiguous")

    def test_source_date_order_resolves_ambiguous_dates_without_global_guessing(self) -> None:
        shifter = DateShifter("date-secret")
        original_dmy = date_from_iso("2020-02-01")
        original_mdy = date_from_iso("2020-01-02")
        self.assertEqual(
            shifter.shift_text("01/02/2020", "cluster-a", date_order="dmy"),
            shifter.shift(original_dmy, "cluster-a").isoformat(),
        )
        self.assertEqual(
            shifter.shift_text("01/02/2020", "cluster-a", date_order="mdy"),
            shifter.shift(original_mdy, "cluster-a").isoformat(),
        )

    def test_unambiguous_numeric_dates_are_emitted_in_iso_format(self) -> None:
        shifter = DateShifter("date-secret")
        shifted = shifter.shift_text("11/11/2020 to 2020/11/13", "cluster-a")
        start, end = map(date_from_iso, shifted.split(" to "))
        self.assertEqual((end - start).days, 2)


class GeneralizationTests(unittest.TestCase):
    def test_age_bands_include_true_age_and_bound_the_elderly_tail(self) -> None:
        generalizer = AgeGeneralizer(band_years=5)
        for age in range(85):
            band = generalizer.generalize(age)
            lower, upper = (int(part) for part in band.split("-"))
            self.assertLessEqual(lower, age)
            self.assertGreaterEqual(upper, age)
            self.assertEqual(upper - lower, 4)
        self.assertEqual(generalizer.generalize(85), "85+")
        self.assertEqual(generalizer.generalize(125), "85+")
        self.assertIsNone(generalizer.generalize("not an age"))
        non_divisor_width = AgeGeneralizer(band_years=7)
        band = non_divisor_width.generalize(84)
        self.assertEqual(band, "78-84")
        self.assertEqual(non_divisor_width.generalize(band), band)

    def test_location_hierarchy_suppresses_home_details_but_not_facility(self) -> None:
        transformed = LocationGeneralizer().generalize(
            {
                "address": {
                    "line1": "12 Example Road",
                    "village": "Small Village",
                    "district": "Example District",
                    "state": "Example State",
                    "pincode": "123456",
                },
                "hospital": {
                    "address": "Example Hospital",
                    "village": "Facility Locality",
                },
            }
        )
        address = transformed["address"]
        self.assertIsNone(address["line1"])
        self.assertEqual(address["village"], "Example District")
        self.assertEqual(address["district"], "Example State")
        self.assertEqual(address["pincode"], "123***")
        self.assertEqual(transformed["hospital"]["address"], "Example Hospital")
        self.assertEqual(transformed["hospital"]["village"], "Facility Locality")

    def test_clinical_integrity_allows_date_only_redaction(self) -> None:
        validator = ClinicalIntegrityValidator()
        validator.validate(
            {"diagnosis": "History noted 01/02/2020"},
            {"diagnosis": "History noted [DATE REDACTED]"},
        )
        with self.assertRaises(ProcessingError) as raised:
            validator.validate(
                {"diagnosis": "common condition"},
                {"diagnosis": "different condition"},
            )
        self.assertEqual(raised.exception.code, "clinical_integrity_failed")


class RiskAssessmentTests(unittest.TestCase):
    def test_indic_gender_and_birth_date_keys_are_included_in_risk_analysis(self) -> None:
        profile = extract_quasi_identifiers(
            {"ling": "female", "janmtithi": "2021-08-31"}
        )
        self.assertEqual(profile["gender"], "female")
        self.assertEqual(profile["date"], "2021-08")

        records = [{"ling": "female"}, {"ling": "male"}]
        assessment = QuasiIdentifierRiskAnalyzer().assess(records, min_group_size=2)
        suppressed = RareValueSuppressor().suppress(records, assessment)
        self.assertEqual(suppressed, ({"ling": None}, {"ling": None}))

    def test_rare_quasi_identifier_is_suppressed_cohort_wide(self) -> None:
        records = [
            {
                "age": "30-34",
                "gender": "female",
                "village": "Common locality" if index < 4 else "Rare locality",
                "diagnosis": "common condition",
                "medication": "Dose 500 mg",
            }
            for index in range(5)
        ]
        analyzer = QuasiIdentifierRiskAnalyzer()
        assessment = analyzer.assess(records, min_group_size=5)
        self.assertEqual(assessment.unique_records, 1)
        self.assertIn("village", assessment.rare_attributes_by_record[-1])

        suppressed = RareValueSuppressor().suppress(records, assessment)
        final_assessment = analyzer.assess(suppressed, min_group_size=5)
        self.assertEqual(final_assessment.equivalence_class_sizes, (5, 5, 5, 5, 5))
        self.assertTrue(all(record["village"] is None for record in suppressed))
        self.assertTrue(all(record["diagnosis"] == "common condition" for record in suppressed))
        self.assertTrue(all(record["medication"] == "Dose 500 mg" for record in suppressed))


class PrivacyTransformerTests(unittest.TestCase):
    def test_transformer_uses_documented_source_date_order_only(self) -> None:
        config = PipelineConfig(min_group_size=5)
        transformer = PrivacyTransformer("privacy-secret", config)
        inputs = []
        for index in range(5):
            record = _record(
                index,
                {"event_date": "01/02/2020", "diagnosis": "common condition"},
            )
            source = InputFileMetadata(
                relative_path="registration/arogya_legacy_export.csv",
                sha256=record.source.sha256,
                size_bytes=record.source.size_bytes,
            )
            inputs.append(
                PrivacyInput(
                    NormalizedRecord(source, record.locator, record.fields),
                    DetectionResult(identifier_count=0),
                    LinkageDecision(LinkageAction.LINK, "shared-cluster"),
                )
            )

        results = transformer.transform_batch(tuple(inputs))
        expected = DateShifter("privacy-secret", config.date_shift_max_days).shift_text(
            "01/02/2020", "shared-cluster", date_order="mdy"
        )
        self.assertTrue(
            all(result.status is ProcessingStatus.SANITIZED for result in results)
        )
        self.assertTrue(
            all(result.output_fields["event_date"] == expected for result in results)
        )

        unknown_results = transformer.transform_batch(
            tuple(
                PrivacyInput(
                    _record(
                        index + 10,
                        {
                            "event_date": "01/02/2020",
                            "diagnosis": "common condition",
                        },
                    ),
                    DetectionResult(identifier_count=0),
                    LinkageDecision(LinkageAction.DO_NOT_LINK),
                )
                for index in range(5)
            )
        )
        self.assertTrue(
            all(result.status is ProcessingStatus.SANITIZED for result in unknown_results)
        )
        self.assertTrue(
            all(
                result.output_fields["event_date"] == "[DATE REDACTED]"
                for result in unknown_results
            )
        )

    def test_cohort_transform_redacts_pii_and_preserves_clinical_values(self) -> None:
        transformer = PrivacyTransformer("privacy-secret", PipelineConfig(min_group_size=5))
        inputs = tuple(
            PrivacyInput(
                record=_record(
                    index,
                    {
                        "patient_name": "Asha",
                        "age": 31,
                        "gender": "female",
                        "village": "Small locality",
                        "district": "Example district",
                        "state": "Example state",
                        "diagnosis": "common condition",
                        "medication": "Paracetamol 500 mg",
                        "admission_date": "2022-01-01",
                        "discharge_date": "2022-01-03",
                    },
                ),
                detection=DetectionResult(
                    identifier_count=1,
                    findings=(
                        DetectionFinding(
                            DetectionEntityType.PATIENT_NAME,
                            "Asha",
                            "patient_name",
                            DetectionChannel.VALUE,
                            0,
                            4,
                        ),
                    ),
                ),
                linkage=LinkageDecision(LinkageAction.LINK, "shared-cluster"),
            )
            for index in range(5)
        )

        results = transformer.transform_batch(inputs)
        self.assertTrue(all(result.status is ProcessingStatus.SANITIZED for result in results))
        self.assertTrue(all(result.output_fields["patient_name"] == "[REDACTED]" for result in results))
        self.assertTrue(all(result.output_fields["age"] == "30-34" for result in results))
        self.assertTrue(all(result.output_fields["medication"] == "Paracetamol 500 mg" for result in results))
        self.assertTrue(
            all(
                (
                    date_from_iso(result.output_fields["discharge_date"])
                    - date_from_iso(result.output_fields["admission_date"])
                ).days
                == 2
                for result in results
            )
        )
        pseudonyms = {result.patient_pseudonym for result in results}
        self.assertEqual(len(pseudonyms), 1)
        self.assertTrue(all(result.risk_assessment.records_assessed == 5 for result in results))

    def test_pii_in_header_is_redacted_and_release_path_is_deferred(self) -> None:
        transformer = PrivacyTransformer("privacy-secret", PipelineConfig(min_group_size=5))
        items = []
        for index in range(5):
            record = _record(index, {"diagnosis": "common condition"})
            source = InputFileMetadata(
                relative_path=f"records/Asha-{index}.json",
                sha256=record.source.sha256,
                size_bytes=record.source.size_bytes,
            )
            record = NormalizedRecord(
                source=source,
                locator=record.locator,
                fields=record.fields,
                structure={"headers": ["Asha", "diagnosis"]},
            )
            filename = record.source.relative_path.index("Asha")
            items.append(
                PrivacyInput(
                    record=record,
                    detection=DetectionResult(
                        identifier_count=2,
                        findings=(
                            DetectionFinding(
                                DetectionEntityType.PATIENT_NAME,
                                "Asha",
                                "@header/0",
                                DetectionChannel.HEADER,
                                0,
                                4,
                            ),
                            DetectionFinding(
                                DetectionEntityType.PATIENT_NAME,
                                "Asha",
                                "@filename",
                                DetectionChannel.FILENAME,
                                filename,
                                filename + 4,
                            ),
                        ),
                    ),
                    linkage=LinkageDecision(LinkageAction.DO_NOT_LINK),
                )
            )
        results = transformer.transform_batch(tuple(items))
        self.assertTrue(all(result.status is ProcessingStatus.SANITIZED for result in results))
        self.assertTrue(all(result.output_structure["headers"][0] == "[REDACTED]" for result in results))
        self.assertTrue(all(result.output_relative_path is None for result in results))

    def test_unresolved_records_do_not_receive_a_patient_pseudonym(self) -> None:
        transformer = PrivacyTransformer("privacy-secret")
        record = _record(1, {"diagnosis": "common condition"})
        result = transformer.transform(
            record,
            DetectionResult(identifier_count=0),
            LinkageDecision(LinkageAction.ABSTAIN),
        )
        self.assertIsNone(result.patient_pseudonym)
        self.assertEqual(result.status, ProcessingStatus.SUPPRESSED)

    def test_incomplete_findings_and_invalid_dates_are_quarantined(self) -> None:
        transformer = PrivacyTransformer("privacy-secret")
        incomplete = transformer.transform(
            _record(1, {"patient_name": "Asha"}),
            DetectionResult(identifier_count=1),
            LinkageDecision(LinkageAction.ABSTAIN),
        )
        self.assertEqual(incomplete.status, ProcessingStatus.QUARANTINED)
        self.assertEqual(incomplete.error_code, "invalid_record")

        unmapped = transformer.transform(
            _record(3, {"note": "Patient Asha"}),
            DetectionResult(
                identifier_count=1,
                findings=(
                    DetectionFinding(
                        DetectionEntityType.PATIENT_NAME,
                        "Asha",
                        "unmapped.path",
                        DetectionChannel.VALUE,
                        8,
                        12,
                    ),
                ),
            ),
            LinkageDecision(LinkageAction.ABSTAIN),
        )
        self.assertEqual(unmapped.status, ProcessingStatus.QUARANTINED)
        self.assertEqual(unmapped.error_code, "invalid_record")

        invalid_date = transformer.transform(
            _record(2, {"event_date": "2020-13-40"}),
            DetectionResult(identifier_count=0),
            LinkageDecision(LinkageAction.ABSTAIN),
        )
        self.assertEqual(invalid_date.status, ProcessingStatus.QUARANTINED)
        self.assertEqual(invalid_date.error_code, "privacy_date_invalid")


def _record(index: int, fields: dict[str, object]) -> NormalizedRecord:
    content = f"synthetic-{index}".encode("utf-8")
    source = InputFileMetadata(
        relative_path=f"records/{index}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )
    return NormalizedRecord(source=source, locator=str(index), fields=fields)


def date_from_iso(value: str):
    from datetime import date

    return date.fromisoformat(value)


if __name__ == "__main__":
    unittest.main()
