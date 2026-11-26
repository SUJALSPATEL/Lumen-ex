# Security controls and output-release limitations

## Secret handling

The root CLI requires `RAKSHA_SECRET` from the process environment. It passes the
secret to the per-run registry and privacy transformer and clears the leak scanner's
canary reference after processing. Secrets are not written to reports, logs, or
temporary files. Python string and byte objects cannot be reliably zeroized; clearing
references is not proof of physical memory erasure.

The encrypted identity registry derives separate keys for database encryption and
blind-index lookup using HKDF-SHA-256. It encrypts persisted identity evidence with
AES-GCM, fresh 12-byte nonces, and associated data. A per-run temporary SQLite
directory is removed on close; SQLite temporary storage is configured for memory and
`secure_delete` is enabled. `secure_delete` and filesystem deletion do not guarantee
physical erasure on SSDs, snapshots, journals, backups, or every operating system.
Temporary directory permissions use the Python runtime defaults; Windows ACLs are not
customized by this project.

## Leak scanning

`SensitiveDataLeakScanner` reuses the existing offline M04 detector. It scans
structured values and keys, CSV/TSV headers and values, JSON/JSONL, free text,
filenames, reports, and caller-supplied log text. `SanitizedOutputWriter` scans each
complete serialized file and its record metadata before writing; the release pipeline
then scans `records.jsonl` and `report.json`. Known M06 placeholders (`[REDACTED]`,
`[LOCATION]`, `[DATE REDACTED]`) are masked only in the scanner's in-memory copy to
avoid treating the firewall's own replacements as identifiers. Gender and shifted
birth dates are allowed through the scanner only for generalized results with cohort
risk assessments; original detected values are still checked against file-scoped
canaries. Raw scanner calls remain strict. Valid generated `PSN-` pseudonyms and the
contract's typed entity-count keys are likewise treated as release metadata in the
scanner's in-memory copy. None of these exceptions alters the emitted artifact.
Detected or unscannable individual artifacts
are quarantined with safe reason codes; metadata scan failures stop report generation
with a nonzero CLI result.

The scanner is bounded to 64 MiB per artifact by default; JSON artifacts over 4 MiB or
structured streams with more than 100,000 items fail closed to limit parser memory and
work. It rejects symlinks and unreadable files. SQLite artifacts are opened read-only;
schema and text cells are scanned, and opaque binary cells are checked for configured
canaries; valid UTF-8/UTF-16 text inside binary cells is scanned as well. Encrypted
registry values are not decrypted by the scanner; encryption and
at-rest tests independently verify those values are not stored as plaintext.
Synthetic test canaries can be supplied in memory and are hidden from the scanner's
representation.

## Limitations

- The M04 detector is deterministic and rule-based, not a complete PII recognizer. An
  unrecognized identifier can pass the scanner; a scanner pass does not prove that the
  output contains no PII.
- Generic opaque binary formats are rejected rather than decoded. Arbitrary BLOB
  content in SQLite is not semantically inspected; the scanner checks canary bytes.
- The release pipeline currently retains parsed records and cohort transformations in
  memory. Large hidden inputs could require a bounded cohort strategy that preserves
  M06 risk semantics; that optimization has not been implemented.
- FHIR output reuses the ingestor's supported resource/Bundle shape checks and does not
  perform full profile, terminology, or general reference-resolution validation.
- The current release matcher has no configured per-hospital namespace, so hospital
  identifiers are not used as global blocking keys.
- Per-file artifacts are written only after their content and record metadata pass.
  If a later report-level check fails, previously written artifacts remain in the
  output directory; they have each passed the per-file scan, but the run returns an
  error and may not satisfy the output validator.
- Secret references are cleared, not guaranteed erased from process memory. Temporary
  file deletion and SQLite `secure_delete` are best effort, not cryptographic erasure.
- No custom Windows ACL, memory locking, core-dump control, or filesystem-level secure
  deletion is implemented.

These controls reduce accidental disclosure and fail closed at the implemented
boundaries. They are not a formal security proof or a guarantee of zero re-identification
risk.
