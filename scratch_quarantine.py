import json
from lumen_ex.security import SensitiveDataLeakScanner

scanner = SensitiveDataLeakScanner(canaries=('practice',))
content = """{
  "facility": {
    "name": "District Hospital Hardoi",
    "type": "District Hospital",
    "state": "UP"
  },
  "exported_at": "2026-11-20T08:15:00+05:30",
  "schema": "dhh.registration.v3",
  "patients": []
}"""

# What was in prep_records[0].sensitive_values?
from pathlib import Path
from lumen_ex.release import _sensitive_values, _PreparedRecord
from lumen_ex.ingestion import StreamingIngestor
from lumen_ex.detection import MultilingualPIIDetector
from lumen_ex.identity import PatientIdentityNormalizer
from lumen_ex.contracts.models import LinkageAction, LinkageDecision, SanitizationResult, ProcessingStatus

ingestor = StreamingIngestor()
source = next(s for s in ingestor.discover(Path('dev/input')) if s.relative_path == 'registration/dhh_patients.json')
records = list(ingestor.read(source))
r = records[0]
norm = PatientIdentityNormalizer().normalize(r)
det = MultilingualPIIDetector().detect(norm)
prep = _PreparedRecord(r, norm, det, LinkageDecision(LinkageAction.ABSTAIN), SanitizationResult(ProcessingStatus.SUPPRESSED, r.locator), False)
sens = _sensitive_values(prep)
print("sens:", sens)

for s in sens:
    safe_single = scanner.scan_artifact_text(content, filename='f.json', sensitive_values=(s,))
    if not safe_single:
        print(f"FAILED on sensitive value: '{s}'")
