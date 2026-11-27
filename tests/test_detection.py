import base64
import hashlib
import unittest

from lumen_ex.contracts import (
    DetectionChannel,
    DetectionEntityType,
    InputFileMetadata,
    InputFormat,
    NormalizedRecord,
    ParsedRecord,
)
from lumen_ex.detection import MultilingualPIIDetector
from lumen_ex.errors import ProcessingError
from lumen_ex.identity import PatientIdentityNormalizer


class MultilingualPIIDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = MultilingualPIIDetector()

    def test_zip_column_is_detected_without_classifying_clinical_numbers(self) -> None:
        source = _source("registration/record.csv", InputFormat.CSV)
        record = NormalizedRecord(
            source=source,
            locator="row:0",
            fields={"district": "[LOCATION]", "Zip": "411001", "phone": "[REDACTED]"},
            structure={"headers": ("district", "Zip", "phone")},
        )
        findings = self.detector.detect(record).findings
        self.assertIn(
            (DetectionEntityType.PIN_CODE, "Zip"),
            {(finding.entity_type, finding.source_key) for finding in findings},
        )

        clinical = NormalizedRecord(
            source=source,
            locator="row:1",
            fields={"lab_value": "140000", "field_10": "140000", "phone": "[REDACTED]"},
            structure={"headers": ("lab_value", "field_10", "phone")},
        )
        self.assertFalse(any(
            finding.entity_type is DetectionEntityType.PIN_CODE
            for finding in self.detector.detect(clinical).findings
        ))

    def test_unlabeled_numeric_range_is_not_aadhaar(self) -> None:
        record = NormalizedRecord(
            source=_source("labs/ranges.json", InputFormat.JSON),
            locator="doc",
            fields={"range": "150000-410000", "note": "1234 5678 9012"},
        )
        findings = self.detector.detect(record).findings
        self.assertFalse(any(
            finding.entity_type is DetectionEntityType.AADHAAR
            and finding.value == "150000-410000"
            for finding in findings
        ))
        self.assertTrue(any(
            finding.entity_type is DetectionEntityType.AADHAAR
            and finding.value == "1234 5678 9012"
            for finding in findings
        ))

    def test_clinical_phrases_do_not_override_identity_evidence(self) -> None:
        record = NormalizedRecord(
            source=_source("notes/clinical.txt", InputFormat.TEXT),
            locator="doc",
            fields={
                "patient_name": "Random Blood Sugar",
                "test": "Person Example",
                "text": (
                    "Patient name: Serum Sodium\n"
                    "K/C/O: Priya Kapoor\n"
                    "Phone: 9876543210\n"
                    "C/O: Arun Shah\n"
                    "Aadhaar: 150000-410000\n"
                    "Serum Sodium 135 mmol/L"
                ),
            },
        )
        findings = self.detector.detect(record).findings
        for value in (
            "Random Blood Sugar", "Person Example", "Serum Sodium", "Priya Kapoor",
            "9876543210", "Arun Shah", "150000-410000",
        ):
            self.assertIn(value, {finding.value for finding in findings})

    def test_detects_structured_patient_fields_and_identifier_types(self) -> None:
        source = _source("registration/patient.csv", InputFormat.CSV)
        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(
                source,
                "row:0",
                {
                    "Patient Name": "Asha Sharma",
                    "Aadhaar No": "१२३४ ५६७८ ९०१२",
                    "Mobile Number": "+91 98765 43210",
                    "DOB": "1982-04-13",
                    "Insurance Policy Number": "POLICY-TEST-1",
                    "Email Address": "asha@example.test",
                },
                {"headers": ("Patient Name", "Aadhaar No")},
            )
        )

        result = self.detector.detect(normalized)
        entity_types = {finding.entity_type for finding in result.findings}

        self.assertTrue(
            {
                DetectionEntityType.PATIENT_NAME,
                DetectionEntityType.AADHAAR,
                DetectionEntityType.PHONE,
                DetectionEntityType.DATE_OF_BIRTH,
                DetectionEntityType.INSURANCE_ID,
                DetectionEntityType.EMAIL,
            }.issubset(entity_types)
        )
        self.assertEqual(result.identifier_count, len(result.findings))
        self.assertEqual(sum(result.entity_counts.values()), result.identifier_count)

    def test_detects_hindi_and_hinglish_free_text_and_relative_names(self) -> None:
        text = (
            "नाम: मोहम्मद शाहिद\n"
            "उम्र: ४८ वर्ष\n"
            "मोबाइल: ९८७६५४३२१०\n"
            "W/o Rajan\n"
            "C/O Ramesh\n"
            "C/O fever\n"
            "Arif sahab ka BP 150/90"
        )
        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(
                _source("notes/hinglish.txt", InputFormat.TEXT),
                "doc",
                {"text": text},
            )
        )

        result = self.detector.detect(normalized)
        pairs = {(finding.entity_type, finding.value) for finding in result.findings}

        self.assertIn((DetectionEntityType.PATIENT_NAME, "मोहम्मद शाहिद"), pairs)
        self.assertIn((DetectionEntityType.AGE, "४८ वर्ष"), pairs)
        self.assertIn((DetectionEntityType.PHONE, "९८७६५४३२१०"), pairs)
        self.assertIn((DetectionEntityType.RELATIVE_NAME, "Rajan"), pairs)
        self.assertIn((DetectionEntityType.RELATIVE_NAME, "Ramesh"), pairs)
        self.assertIn((DetectionEntityType.PATIENT_NAME, "Arif"), pairs)
        self.assertNotIn((DetectionEntityType.RELATIVE_NAME, "fever"), pairs)

    def test_detects_unlabeled_latin_names_and_excludes_clinician_context(self) -> None:
        normalized = NormalizedRecord(
            source=_source("notes/visit.txt", InputFormat.TEXT),
            locator="doc",
            fields={
                "text": (
                    "Visit completed for Asha Sharma. "
                    "Dr. Ramesh Kumar reviewed the medication."
                )
            },
        )

        result = self.detector.detect(normalized)
        names = {
            finding.value
            for finding in result.findings
            if finding.entity_type is DetectionEntityType.PATIENT_NAME
        }

        self.assertIn("Asha Sharma", names)
        self.assertNotIn("Dr. Ramesh Kumar", names)

    def test_detects_fragmented_patient_and_relative_name(self) -> None:
        normalized = NormalizedRecord(
            source=_source("notes/fragment.txt", InputFormat.TEXT),
            locator="doc",
            fields={"text": "Meera, W/o Rajan"},
        )

        result = self.detector.detect(normalized)
        pairs = {(finding.entity_type, finding.value) for finding in result.findings}

        self.assertIn((DetectionEntityType.PATIENT_NAME, "Meera"), pairs)
        self.assertIn((DetectionEntityType.RELATIVE_NAME, "Rajan"), pairs)

    def test_detects_names_identifiers_in_keys_headers_and_filenames(self) -> None:
        source = _source(
            "records/Mohammed_Shahid_9876543210.csv",
            InputFormat.CSV,
        )
        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(
                source,
                "row:0",
                {
                    "Patient Name": "मोहम्मद शाहिद",
                    "Mohammad Shahid": "hidden-key-value",
                    "phone": "9876543210",
                },
                {"headers": ("Patient Name", "Mohammad Shahid")},
            )
        )

        result = self.detector.detect(normalized)
        located = {
            (finding.entity_type, finding.channel) for finding in result.findings
        }

        self.assertIn(
            (DetectionEntityType.PATIENT_NAME, DetectionChannel.KEY), located
        )
        self.assertIn(
            (DetectionEntityType.PATIENT_NAME, DetectionChannel.HEADER), located
        )
        self.assertIn(
            (DetectionEntityType.PATIENT_NAME, DetectionChannel.FILENAME), located
        )
        self.assertIn((DetectionEntityType.PHONE, DetectionChannel.FILENAME), located)

    def test_detects_labeled_names_in_keys_and_fhir_identifier_types(self) -> None:
        key_record = NormalizedRecord(
            source=_source("metadata/record.json", InputFormat.JSON),
            locator="doc",
            fields={"Patient_Asha_Sharma": "metadata"},
        )
        key_result = self.detector.detect(key_record)
        self.assertTrue(
            any(
                finding.entity_type is DetectionEntityType.PATIENT_NAME
                and finding.channel is DetectionChannel.KEY
                for finding in key_result.findings
            )
        )

        fhir = {
            "resourceType": "Patient",
            "identifier": [
                {
                    "system": "urn:example:aadhaar",
                    "value": "1234-5678-9012",
                },
                {
                    "type": {"text": "Insurance policy number"},
                    "value": "POLICY-TEST-3",
                },
            ],
        }
        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(
                _source("fhir/patient.json", InputFormat.FHIR),
                "doc",
                fhir,
            )
        )
        fhir_result = self.detector.detect(normalized)
        found_types = {finding.entity_type for finding in fhir_result.findings}

        self.assertIn(DetectionEntityType.AADHAAR, found_types)
        self.assertIn(DetectionEntityType.INSURANCE_ID, found_types)

    def test_detects_single_token_names_in_explicit_fields_and_short_mrns(self) -> None:
        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(
                _source("records/identity.json", InputFormat.JSON),
                "/records/0",
                {"patient_name": "Ravi", "MRN": "A1", "Ravi": "metadata"},
                {"headers": ("Ravi", "MRN")},
            )
        )

        result = self.detector.detect(normalized)
        detected = {
            (finding.entity_type, finding.channel, finding.value)
            for finding in result.findings
        }

        self.assertIn(
            (
                DetectionEntityType.PATIENT_NAME,
                DetectionChannel.VALUE,
                "Ravi",
            ),
            detected,
        )
        self.assertIn(
            (
                DetectionEntityType.PATIENT_NAME,
                DetectionChannel.HEADER,
                "Ravi",
            ),
            detected,
        )
        self.assertIn(
            (
                DetectionEntityType.PATIENT_NAME,
                DetectionChannel.KEY,
                "Ravi",
            ),
            detected,
        )
        self.assertIn(
            (
                DetectionEntityType.MEDICAL_RECORD_NUMBER,
                DetectionChannel.VALUE,
                "A1",
            ),
            detected,
        )

    def test_detects_file_scoped_identity_names_in_headers_and_keys(self) -> None:
        normalized = NormalizedRecord(
            source=_source("records/file.csv", InputFormat.CSV),
            locator="row:1",
            fields={"Asha Sharma": "metadata", "diagnosis": "hypertension"},
            structure={"headers": ("Asha Sharma", "diagnosis")},
        )

        result = self.detector.detect(
            normalized,
            known_names=("Asha Sharma",),
        )

        self.assertTrue(
            any(
                finding.entity_type is DetectionEntityType.PATIENT_NAME
                and finding.channel is DetectionChannel.HEADER
                for finding in result.findings
            )
        )

    def test_quarantines_printable_base64_payloads_but_ignores_binary_blobs(self) -> None:
        encoded_text = base64.b64encode(
            b"Patient Name: Synthetic Sample\nMRN: A1"
        ).decode("ascii")
        text_record = NormalizedRecord(
            source=_source("records/attachment.json", InputFormat.JSON),
            locator="doc",
            fields={"attachment_data": encoded_text},
        )
        with self.assertRaises(ProcessingError) as error:
            self.detector.detect(text_record)
        self.assertEqual(error.exception.code, "unsupported_format")

        encoded_binary = base64.b64encode(bytes(range(1, 33))).decode("ascii")
        binary_record = NormalizedRecord(
            source=_source("records/image.json", InputFormat.JSON),
            locator="doc",
            fields={"attachment_data": encoded_binary},
        )
        self.assertEqual(self.detector.detect(binary_record).findings, ())

    def test_does_not_flag_clinician_names_or_common_clinical_content(self) -> None:
        clinical = (
            "Dr. Ramesh reviewed the patient. "
            "C/O fever. Ramipril 5 mg; Dolo 650 BD x 5 days; "
            "1-0-1; Parkinson's disease; BP 150/90."
        )
        normalized = NormalizedRecord(
            source=_source("notes/clinical.txt", InputFormat.TEXT),
            locator="doc",
            fields={
                "text": clinical,
                "name": "Kumar",
                "Patient Name": "Parkinson's disease",
                "doctor": {"name": "Dr Ramesh", "phone": "9876543210"},
            },
        )

        result = self.detector.detect(normalized)

        self.assertEqual(result.findings, ())
        self.assertEqual(normalized.fields["text"], clinical)

    def test_name_label_stops_before_clinical_text_on_the_same_line(self) -> None:
        normalized = PatientIdentityNormalizer().normalize(
            ParsedRecord(
                _source("notes/clinical-name.txt", InputFormat.TEXT),
                "doc",
                {"text": "Patient Name: Arif sahab ka BP 150/90"},
            )
        )

        result = self.detector.detect(normalized)
        names = [
            finding.value
            for finding in result.findings
            if finding.entity_type is DetectionEntityType.PATIENT_NAME
        ]

        self.assertEqual(names, ["Arif"])

    def test_detects_phone_and_email_but_rejects_clinical_numbers(self) -> None:
        normalized = NormalizedRecord(
            source=_source("notes/contact.txt", InputFormat.TEXT),
            locator="doc",
            fields={
                "text": (
                    "Patient contact: 98765-43210; email: patient@example.test. "
                    "Dose 650 mg, BP 150/90, schedule 1-0-1."
                )
            },
        )

        result = self.detector.detect(normalized)
        found = {finding.entity_type for finding in result.findings}

        self.assertEqual(found, {DetectionEntityType.PHONE, DetectionEntityType.EMAIL})

    def test_detects_pan_abha_masked_aadhaar_mrn_and_pin(self) -> None:
        normalized = NormalizedRecord(
            source=_source("notes/identifiers.txt", InputFormat.TEXT),
            locator="doc",
            fields={
                "text": (
                    "PAN: ABCDE1234F\n"
                    "ABHA: 12-3456-7890-1234\n"
                    "Aadhaar: XXXX XXXX 1234\n"
                    "UHID: JJH-TEST-9\n"
                    "PIN: 229001"
                )
            },
        )

        result = self.detector.detect(normalized)
        found = {finding.entity_type for finding in result.findings}

        self.assertTrue(
            {
                DetectionEntityType.PAN,
                DetectionEntityType.ABHA,
                DetectionEntityType.AADHAAR,
                DetectionEntityType.MEDICAL_RECORD_NUMBER,
                DetectionEntityType.PIN_CODE,
            }.issubset(found)
        )

    def test_repr_hides_detected_values_and_source_keys(self) -> None:
        normalized = NormalizedRecord(
            source=_source("private/Asha_Sharma.csv", InputFormat.CSV),
            locator="row:0",
            fields={"Patient Name": "Asha Sharma"},
            identities=PatientIdentityNormalizer()
            .normalize(
                ParsedRecord(
                    _source("private/Asha_Sharma.csv", InputFormat.CSV),
                    "row:0",
                    {"Patient Name": "Asha Sharma"},
                )
            )
            .identities,
        )

        result = self.detector.detect(normalized)

        self.assertNotIn("Asha Sharma", repr(result))
        self.assertNotIn("Patient Name", repr(result))
        self.assertNotIn("Asha Sharma", repr(result.findings[0]))
        self.assertNotIn("Patient Name", repr(result.findings[0]))

    def test_quarantines_overdeep_structures_with_a_safe_error_code(self) -> None:
        nested: dict[str, object] = {}
        current = nested
        for _ in range(130):
            child: dict[str, object] = {}
            current["nested"] = child
            current = child
        current["patient_id"] = "PRIVATE-TEST-ID"
        record = NormalizedRecord(
            source=_source("records/deep.json", InputFormat.JSON),
            locator="doc",
            fields=nested,
        )

        with self.assertRaises(ProcessingError) as error:
            self.detector.detect(record)

        self.assertEqual(error.exception.code, "detection_structure_depth_exceeded")
        self.assertNotIn("PRIVATE-TEST-ID", str(error.exception))

    def test_clinical_history_kco_and_location_fields_are_not_misclassified_as_names(self) -> None:
        record = NormalizedRecord(
            source=_source("discharge/note.txt", InputFormat.TEXT),
            locator="doc",
            fields={"text": "History: No K/C/O HTN.\nHistory: K/C/O TB\nNo other issues."},
        )
        result = self.detector.detect(record)
        self.assertEqual(result.identifier_count, 0)

        reg_record = NormalizedRecord(
            source=_source("registration/reg.tsv", InputFormat.TSV),
            locator="row:0",
            fields={"Reg No": "JJH-0077305", "Village/Mohalla": "Amardih", "District": "Kanpur Dehat"},
        )
        reg_result = self.detector.detect(reg_record)
        detected = {(f.entity_type, f.source_key) for f in reg_result.findings}
        self.assertIn((DetectionEntityType.MEDICAL_RECORD_NUMBER, "Reg No"), detected)
        self.assertIn((DetectionEntityType.LOCATION, "Village/Mohalla"), detected)
        self.assertNotIn((DetectionEntityType.PATIENT_NAME, "District"), detected)

        addr_record = NormalizedRecord(
            source=_source("discharge/addr.txt", InputFormat.TEXT),
            locator="doc",
            fields={"text": "Address: H.No 12, Ward 10, Rampur, Distt. Hardoi - 261167\nBP: 120/80"},
        )
        addr_result = self.detector.detect(addr_record)
        addr_values = [f.value for f in addr_result.findings if f.entity_type is DetectionEntityType.ADDRESS]
        self.assertIn("H.No 12, Ward 10, Rampur, Distt. Hardoi - 261167", addr_values)

        honorific_record = NormalizedRecord(
            source=_source("discharge/hon.txt", InputFormat.TEXT),
            locator="doc",
            fields={"text": "Zainab amma is comfortable."},
        )
        hon_result = self.detector.detect(honorific_record)
        self.assertIn(
            (DetectionEntityType.PATIENT_NAME, "Zainab amma"),
            {(f.entity_type, f.value) for f in hon_result.findings},
        )


def _source(path: str, file_format: InputFormat) -> InputFileMetadata:
    return InputFileMetadata(
        relative_path=path,
        sha256=hashlib.sha256(path.encode("utf-8")).hexdigest(),
        size_bytes=1,
        detected_format=file_format,
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
