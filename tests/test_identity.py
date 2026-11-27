import json
from pathlib import Path
import unicodedata
import unittest

from lumen_ex.config import PipelineConfig
from lumen_ex.contracts.identity import PatientIdentity
from lumen_ex.contracts.models import InputFileMetadata, InputFormat, ParsedRecord
from lumen_ex.identity import (
    PatientIdentityNormalizer,
    extract_fhir_identities,
    extract_identity,
    normalize_age,
    normalize_date,
    normalize_gender,
    normalize_email,
    normalize_identifier,
    normalize_location,
    normalize_phone,
)
from lumen_ex.detection.indic_names import names_match, normalize_name
from lumen_ex.errors import ProcessingError
from lumen_ex.release import _source_namespaces_by_file


_FIXTURES = Path(__file__).parent / "fixtures" / "identity_examples.json"


class NameNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.examples = json.loads(_FIXTURES.read_text(encoding="utf-8"))

    def test_cross_script_and_hinglish_honorific_forms(self) -> None:
        for first, second in self.examples["cross_script_names"]:
            with self.subTest(first=first, second=second):
                self.assertTrue(names_match(first, second))

    def test_common_unicode_and_spelling_variants_normalize_without_name_aliases(self) -> None:
        for first, second in self.examples["spelling_and_unicode_variants"]:
            with self.subTest(first=first, second=second):
                self.assertTrue(names_match(first, second))

    def test_similar_or_partial_names_are_not_equal(self) -> None:
        for first, second in self.examples["distinct_names"]:
            with self.subTest(first=first, second=second):
                self.assertFalse(names_match(first, second))

    def test_normalization_keeps_initials_and_name_component_order(self) -> None:
        self.assertEqual(normalize_name("M. Shahid Khan"), "m shahid khan")
        self.assertNotEqual(normalize_name("Shahid Khan"), normalize_name("Khan Shahid"))


class ScalarNormalizationTests(unittest.TestCase):
    def test_normalizes_indian_phone_forms_and_rejects_malformed_values(self) -> None:
        self.assertEqual(normalize_phone("+91 98765-43210"), "+919876543210")
        self.assertEqual(normalize_phone("09876543210"), "+919876543210")
        self.assertEqual(normalize_phone("९८७६५४३२१०"), "+919876543210")
        self.assertIsNone(normalize_phone("12345"))
        self.assertIsNone(normalize_phone("call 9876543210"))

    def test_normalizes_dates_only_when_the_numeric_order_is_unambiguous(self) -> None:
        self.assertEqual(normalize_date("1982-04-13"), "1982-04-13")
        self.assertEqual(normalize_date("13/04/1982"), "1982-04-13")
        self.assertEqual(normalize_date("04/13/1982"), "1982-04-13")
        self.assertIsNone(normalize_date("04/05/1982"))
        self.assertEqual(
            normalize_date("04/05/1982", date_order="dmy"),
            "1982-05-04",
        )
        self.assertEqual(
            normalize_date("04/05/1982", date_order="mdy"),
            "1982-04-05",
        )
        self.assertIsNone(normalize_date("31/02/1982"))
        self.assertIsNone(normalize_date("1982-04-13garbage"))
        self.assertIsNone(normalize_date("1982-04-13T23:59:00Z"))

    def test_normalizes_age_gender_identifiers_and_locations(self) -> None:
        self.assertEqual(normalize_age("48 years"), "48")
        self.assertEqual(normalize_age("48 saal"), "48")
        self.assertEqual(normalize_age("४८ वर्ष"), "48")
        self.assertIsNone(normalize_age("148"))
        self.assertEqual(normalize_gender("F"), "female")
        self.assertIsNone(normalize_gender("not specified"))
        self.assertEqual(normalize_identifier("१२३४-AB"), "1234AB")
        self.assertEqual(normalize_location("  Rae-Bareli  "), "rae bareli")
        self.assertEqual(normalize_email(" Patient@Example.ORG "), "patient@example.org")
        self.assertIsNone(normalize_email("not-an-email"))


class IdentityExtractionTests(unittest.TestCase):
    def test_verified_issuer_aliases_distinguish_provenance_and_reference_scope(self) -> None:
        config = PipelineConfig(issuer_aliases=(
            ("metadata", "Legacy A", "hospital-a"),
            ("metadata", "Export A", "hospital-a"),
            ("fhir", "urn:hospital:records", "hospital-a"),
        ))
        first = extract_identity({
            "hospital_code": "Legacy A", "MRN": "A-01", "patient_ref": "REF-1",
        }, "first.json", config=config)
        second = extract_identity({
            "_export_meta": {"hospital": "Export A"}, "MRN": "A-01", "patient_ref": "REF-1",
        }, "second.json", config=config)
        fhir, = extract_fhir_identities({
            "resourceType": "Bundle",
            "entry": [{"resource": {
                "resourceType": "Patient",
                "identifier": [{"system": "urn:hospital:records", "value": "A-01"}],
            }}],
        }, "third.json", config=config)
        self.assertEqual(first.source_system, second.source_system)
        self.assertEqual(first.source_system, fhir.hospital_identifier[0].namespace)
        references = [
            next(value.namespace for value in identity.hospital_identifier
                 if value.source_key == "patient_ref")
            for identity in (first, second)
        ]
        self.assertNotEqual(references[0], references[1])
        conflicting = extract_identity({
            "hospital_code": "Legacy A", "hospital_name": "Different Hospital", "MRN": "A-01",
        }, "conflict.json", config=config)
        self.assertTrue(conflicting.context_conflict)
        unknown = extract_identity({"provider": {"name": "Legacy A"}, "MRN": "A-01"},
                                   "unknown.json", config=config)
        self.assertNotEqual(unknown.source_system, first.source_system)
        mixed = extract_identity({
            "resourceType": "Patient",
            "identifier": [
                {"system": "urn:hospital:records", "value": "A-01"},
                {"value": "B-02"},
            ],
        }, "mixed.json", config=config)
        self.assertIsNone(mixed.source_system)
        self.assertTrue(any(value.namespace is None for value in mixed.hospital_identifier))

        source = InputFileMetadata("mixed-source.json", "a" * 64, 128, detected_format=InputFormat.JSON)
        records = (
            ParsedRecord(source, "/items/0", {"hospital_code": "Legacy A", "MRN": "A-01"}),
            ParsedRecord(source, "/items/1", {"MRN": "A-01"}),
        )
        normalizer = PatientIdentityNormalizer(config)
        normalized = {
            (source.relative_path, record.locator): normalizer.normalize(record)
            for record in records
        }
        self.assertEqual(_source_namespaces_by_file(records, normalized),
                         {source.relative_path: f"file:{source.sha256}"})
        self.assertIsNone(normalized[source.relative_path, "/items/1"]
                          .identities[0].hospital_identifier[0].namespace)

    def test_multilingual_note_labels_and_patient_headers(self) -> None:
        labeled = extract_identity(
            "मरीज़ का नाम — आशा शर्मा\r\n"
            "pita ka naam = Mohan Sharma\r\n"
            "जन्मतिथि：१३/०४/१९८२\r\n"
            "मोबाइल नंबर: ९८७६५४३२१०\r\n"
            "पंजीकरण सं.: H-102 आईपीडी सं.: E-200\r\n",
            "note.txt",
        )
        for field, normalized in (
            ("name", "asha sharma"), ("relative_name", "mohan sharma"),
            ("date_of_birth", "1982-04-13"), ("phone", "+919876543210"),
            ("hospital_identifier", "H102"),
        ):
            self.assertEqual([value.normalized for value in getattr(labeled, field)], [normalized])
        for note in (
            "Report of Asha Sharma  40 Y / F\r\nHb 12",
            "14:00 - Asha Sharma - K/C/O asthma",
            "13/04/2026 22:00 - Asha Sharma ka BP 120/80",
            "Patient ka naam: Asha Sharma",
        ):
            with self.subTest(note=note):
                self.assertEqual(extract_identity(note, "note.txt").name[0].normalized, "asha sharma")

    def test_clinical_note_values_and_unqualified_narrative_are_not_identifiers(self) -> None:
        identity = extract_identity(
            "14:00 - Serum Creatinine 1.4 mg/dL\n"
            "14:00 - Chest Pain - K/C/O asthma\n"
            "Report of serum creatinine: 1.4\n"
            "C/O: cough and fever\n"
            "Blood pressure: 120/80\nPlatelet count: 9876543210\n"
            "Continues dose 543210\n"
            "पंजीकरण सं.: unavailable आईपीडी सं.: E-200",
            "note.txt",
        )
        self.assertFalse(identity.name or identity.relative_name or identity.phone or identity.hospital_identifier)

    def test_dob_uses_source_order_and_rejects_ambiguous_or_invalid_values(self) -> None:
        record = {"DOB": "०४/०५/१९८२"}
        for order, expected in ((None, None), ("dmy", "1982-05-04"), ("mdy", "1982-04-05")):
            self.assertEqual(extract_identity(record, "synthetic.csv", date_order=order)
                             .date_of_birth[0].normalized, expected)
        self.assertIsNone(extract_identity({"DOB": "02/31/1982"}, "synthetic.csv", date_order="mdy")
                          .date_of_birth[0].normalized)
        self.assertIsNone(extract_identity({"DOB": "13/04/1982"}, "synthetic.csv", date_order="mdy")
                          .date_of_birth[0].normalized)

    def test_projects_csv_or_tsv_style_row_and_keeps_source_values(self) -> None:
        identity = extract_identity(
            {
                "Patient Name": "शाहिद खान",
                "PatientID": "SNJ-TEST-04",
                "DOB": "1982-04-13",
                "Age": 44,
                "Sex": "M",
                "Mobile Number": "+91 98765 43210",
                "Address": "Ward 2, Rae Bareli",
                "Aadhaar No": "१२३४-५६७८-९०१२",
                "Diagnosis": "not identity data",
            },
            "registration/test.tsv",
            "row:0",
        )
        self.assertIsInstance(identity, PatientIdentity)
        self.assertEqual(identity.record_locator, "row:0")
        self.assertEqual(identity.name[0].original, "शाहिद खान")
        self.assertEqual(identity.name[0].normalized, "shahid khan")
        self.assertEqual(identity.date_of_birth[0].normalized, "1982-04-13")
        self.assertEqual(identity.phone[0].normalized, "+919876543210")
        self.assertEqual(identity.hospital_identifier[0].normalized, "SNJTEST04")
        self.assertEqual(identity.government_identifier[0].normalized, "123456789012")
        self.assertNotIn("Diagnosis", repr(identity))
        self.assertNotIn("not identity data", repr(identity))

    def test_extracts_nested_json_and_preserves_distinct_name_parts(self) -> None:
        identity = extract_identity(
            {
                "patient": {
                    "name": {"given": ["Geeta"], "family": "Chauhan"},
                    "contact": {"mobile": "9876543210"},
                    "address": {"line": ["House 2"], "district": "Rae Bareli"},
                    "ids": {"aadhar_no": 123456789012},
                },
                "doctor": {"name": "Dr. Ramesh"},
            },
            "registration/patients.json",
            "/patients/0",
        )
        originals = {value.original for value in identity.name}
        self.assertIn("Geeta", originals)
        self.assertIn("Chauhan", originals)
        self.assertTrue(any(value.original == "Geeta Chauhan" for value in identity.name))
        self.assertFalse(any(value.original == "Dr. Ramesh" for value in identity.name))
        self.assertTrue(identity.address)
        self.assertIn("Rae Bareli", {value.original for value in identity.location})
        self.assertEqual(identity.government_identifier[0].normalized, "123456789012")

    def test_extracts_patient_contact_phone_but_not_doctor_phone(self) -> None:
        identity = extract_identity(
            {
                "patient": {"contact": {"mobile": "9876543210"}},
                "doctor": {"phone": "9123456789"},
            },
            "registration/patient.json",
        )

        self.assertEqual(len(identity.phone), 1)
        self.assertEqual(identity.phone[0].normalized, "+919876543210")
        self.assertEqual(identity.phone[0].source_key, "patient.contact.mobile")

    def test_extracts_hinglish_labels_and_insurance_identifier(self) -> None:
        identity = extract_identity(
            "Naam: Asha Sharma\n"
            "Umar: 48 saal\n"
            "Pata: Rae Bareli\n"
            "Mobile No: 98765 43210\n"
            "Bima Number: POLICY-TEST-1",
            "notes/hinglish.txt",
        )

        self.assertEqual(identity.name[0].normalized, "asha sharma")
        self.assertEqual(identity.age[0].normalized, "48")
        self.assertEqual(identity.address[0].normalized, "rae bareli")
        self.assertEqual(identity.phone[0].normalized, "+919876543210")
        self.assertEqual(identity.insurance_identifier[0].normalized, "POLICYTEST1")

    def test_extracts_insurance_identifier_from_structured_fields(self) -> None:
        identity = extract_identity(
            {"patient": {"insurance": {"policy_number": "POLICY-TEST-2"}}},
            "registration/patient.json",
        )

        self.assertEqual(
            identity.insurance_identifier[0].normalized, "POLICYTEST2"
        )

    def test_extracts_relative_name_and_email_for_linkage(self) -> None:
        identity = extract_identity(
            {
                "Patient Name": "Asha Sharma, W/o Rajan Sharma",
                "Email Address": "Asha.Sharma@Example.org",
                "relative": {"name": "Rajan Sharma"},
            },
            "registration/patient.json",
        )

        self.assertEqual(identity.name[0].normalized, "asha sharma")
        self.assertEqual(identity.relative_name[0].normalized, "rajan sharma")
        self.assertEqual(identity.email[0].normalized, "asha.sharma@example.org")

    def test_does_not_treat_a_care_of_complaint_as_a_relative_name(self) -> None:
        identity = extract_identity(
            {"Patient Name": "Meera Khan, C/O chest pain"},
            "notes/clinical.txt",
        )

        self.assertEqual(identity.name[0].normalized, "meera khan")
        self.assertFalse(identity.relative_name)

    def test_extracts_email_from_fhir_telecom(self) -> None:
        identity = extract_identity(
            {
                "resourceType": "Patient",
                "telecom": [{"system": "email", "value": "Asha@Example.org"}],
            },
            "fhir/patient.json",
        )

        self.assertEqual(identity.email[0].normalized, "asha@example.org")

    def test_rejects_excessively_nested_identity_mappings_instead_of_skipping(self) -> None:
        record: dict[str, object] = {}
        current = record
        for _ in range(26):
            child: dict[str, object] = {}
            current["nested"] = child
            current = child
        current["patient_id"] = "PATIENT-TEST-1"

        with self.assertRaises(ProcessingError) as too_deep:
            extract_identity(record, "registration/deep.json")

        self.assertEqual(
            too_deep.exception.code, "identity_structure_depth_exceeded"
        )
        self.assertNotIn("PATIENT-TEST-1", str(too_deep.exception))

    def test_extracts_fhir_patient_and_bundle_with_record_locators(self) -> None:
        bundle = {
            "resourceType": "Bundle",
            "entry": [
                {"resource": {"resourceType": "Observation", "id": "ignored"}},
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "Amina Khan", "given": ["Amina"], "family": "Khan"}],
                        "identifier": [
                            {"system": "urn:hospital:mrn", "value": "MRN-TEST-5"},
                            {"system": "urn:abha:number", "value": "ABHA-TEST-6"},
                        ],
                        "telecom": [{"system": "phone", "value": "9876543210"}],
                        "gender": "female",
                        "birthDate": "1982-04-13",
                        "address": [
                            {
                                "line": ["House 4"],
                                "city": "Lalganj",
                                "district": "Rae Bareli",
                                "postalCode": "229001",
                            }
                        ],
                    }
                },
            ],
        }
        identities = extract_fhir_identities(bundle, "fhir/bundle.json")
        self.assertEqual(len(identities), 1)
        patient = identities[0]
        self.assertEqual(patient.record_locator, "/entry/1/resource")
        self.assertEqual(patient.hospital_identifier[0].normalized, "MRNTEST5")
        self.assertEqual(patient.hospital_identifier[0].namespace, "urn:hospital:mrn")
        self.assertEqual(patient.government_identifier[0].normalized, "ABHATEST6")
        self.assertEqual(patient.phone[0].normalized, "+919876543210")
        self.assertTrue(patient.address)
        self.assertTrue(patient.location)

    def test_extracts_only_unambiguous_labeled_source_system(self) -> None:
        identity = extract_identity(
            {
                "source_system": "urn:clinic:west",
                "patient_name": "Asha Sharma",
                "hospital_id": "MRN-TEST-9",
            },
            "records/patient.json",
        )
        self.assertEqual(identity.source_system, "urn:clinic:west")
        self.assertEqual(identity.hospital_identifier[0].namespace, "urn:clinic:west")

        ambiguous = extract_identity(
            {
                "source_system": "urn:clinic:west",
                "issuer": "urn:clinic:east",
                "hospital_id": "MRN-TEST-9",
            },
            "records/patient.json",
        )
        self.assertIsNone(ambiguous.source_system)
        self.assertIsNone(ambiguous.hospital_identifier[0].namespace)

        insurance_issuer = extract_identity(
            {
                "patient_name": "Asha Sharma",
                "hospital_id": "MRN-TEST-9",
                "insurance": {"issuer": "urn:insurance:example"},
            },
            "records/patient.json",
        )
        self.assertIsNone(insurance_issuer.source_system)
        self.assertIsNone(insurance_issuer.hospital_identifier[0].namespace)

    def test_classifies_fhir_insurance_identifiers(self) -> None:
        identity = extract_identity(
            {
                "resourceType": "Patient",
                "identifier": [
                    {
                        "type": {
                            "coding": [
                                {"code": "INS", "display": "Insurance policy number"}
                            ]
                        },
                        "value": "POLICY-TEST-8",
                    }
                ],
            },
            "fhir/patient.json",
        )

        self.assertEqual(
            identity.insurance_identifier[0].normalized, "POLICYTEST8"
        )

    def test_extracts_only_explicitly_labeled_note_fields(self) -> None:
        identity = extract_identity(
            "नाम: मोहम्मद शाहिद\nउम्र: 48 वर्ष\nGender: M\n"
            "Phone: 98765 43210\nDOB: 1982-04-13\nUHID: JJH-TEST-7\n"
            "Asha ji ka BP 117/82",
            "notes/example.txt",
        )
        self.assertEqual(identity.name[0].normalized, "mohammad shahid")
        self.assertEqual(identity.age[0].normalized, "48")
        self.assertEqual(identity.gender[0].normalized, "male")
        self.assertEqual(identity.phone[0].normalized, "+919876543210")
        self.assertEqual(identity.hospital_identifier[0].normalized, "JJHTEST7")
        self.assertEqual(len(identity.name), 1)

    def test_normalizer_attaches_identity_without_mutating_source_fields(self) -> None:
        source_fields = {
            "text": "Naam: Asha Sharma\nUmar: 48 saal",
            "diagnosis": "synthetic diagnosis",
        }
        source = InputFileMetadata(
            relative_path="notes/synthetic.txt",
            sha256="a" * 64,
            size_bytes=64,
            detected_format=InputFormat.TEXT,
            encoding="utf-8",
        )
        parsed = ParsedRecord(source, "doc", source_fields)

        normalized = PatientIdentityNormalizer().normalize(parsed)

        self.assertEqual(normalized.fields, source_fields)
        self.assertEqual(normalized.identities[0].name[0].normalized, "asha sharma")
        self.assertEqual(normalized.identities[0].age[0].normalized, "48")
        self.assertNotIn("Asha Sharma", repr(normalized))
        self.assertNotIn("synthetic diagnosis", repr(normalized))

    def test_normalizer_extracts_all_patients_from_a_complete_bundle(self) -> None:
        bundle = {
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                {"resource": {"resourceType": "Observation", "id": "obs"}},
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "Asha Sharma"}],
                    }
                },
            ],
        }
        source = InputFileMetadata(
            relative_path="fhir/bundle.json",
            sha256="b" * 64,
            size_bytes=128,
            detected_format=InputFormat.FHIR,
            encoding="utf-8",
        )

        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(source, "doc", bundle)
        )

        self.assertEqual(len(normalized.identities), 1)
        self.assertEqual(
            normalized.identities[0].record_locator, "/entry/1/resource"
        )
        self.assertEqual(normalized.fields, bundle)

    def test_reports_missing_and_malformed_values_without_dropping_originals(self) -> None:
        identity = extract_identity(
            {"Patient Name": "M. Shahid", "Phone": "123", "DOB": "31/02/1982"},
            "registration/partial.csv",
            "row:3",
        )
        self.assertIn("phone", identity.invalid_fields)
        self.assertIn("date_of_birth", identity.invalid_fields)
        self.assertIsNone(identity.phone[0].normalized)
        self.assertEqual(identity.phone[0].original, "123")
        self.assertIn("gender", identity.missing_fields)
        self.assertIn("hospital_identifier", identity.missing_fields)

    def test_unicode_composition_and_full_width_phone_are_normalized(self) -> None:
        composed = extract_identity(
            {"Name": "Śāhīd Khān", "Phone": "＋９１　９８７６５４３２１０"},
            "registration/unicode.json",
        )
        decomposed = extract_identity(
            {"Name": unicodedata.normalize("NFD", "Śāhīd Khān")},
            "registration/unicode.json",
        )
        self.assertEqual(composed.name[0].normalized, "shahid khan")
        self.assertEqual(decomposed.name[0].normalized, composed.name[0].normalized)
        self.assertEqual(composed.phone[0].normalized, "+919876543210")


if __name__ == "__main__":
    unittest.main()
