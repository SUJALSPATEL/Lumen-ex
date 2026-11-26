# Lumen-ex release architecture

Lumen-ex is a single-process Python application. It runs locally, offline, on CPU;
there are no services, model downloads, or runtime network dependencies. The root
`main.py` is the evaluator entry point and `lumen_ex` contains the application
foundation. The official starter remains under `starter/` as a compatibility baseline;
the submission CLI uses the modular release pipeline.

## Data flow

```text
raksha.toml → main.py / CLI → validated policy, secret, and input/output paths
                            → ReleasePipeline
                              → file discovery, hashing, and parsing
                              → identity normalization and PII detection
                              → encrypted registry and conservative matching
                              → cohort privacy transformation
                              → whole-file serialization and leak scanning
                              → records.jsonl, report.json, and contract validation
```

The processing stages are integrated into submission output. The
release pipeline retains the complete cohort for M06 risk assessment, then groups
results by source file so a file is emitted only after its sanitized representation
and record mappings pass the M07 scanner. The scanner is a fail-closed safeguard for
recognized findings, not a guarantee of complete de-identification.

The writer rereads source bytes to verify the ingestion digest and reconstruct
the original file envelope and headers. Record-level failures are omitted when
other records in the same structured file pass; the artifact is still scanned as a
whole, and file-level failures remain quarantined. Its contract validator independently
resolves published locators and verifies pseudonyms against on-disk artifacts.
The practice truth and synthetic attacker are used by development tools only.

## Boundaries and responsibilities

| Area | Responsibility and expected interface |
|---|---|
| CLI / orchestration | Parse submission arguments, load validated settings, enforce safe path relationships, and invoke `ReleasePipeline`. `lumen_ex.cli.main` is the executable interface. |
| Input discovery / ingestion | `lumen_ex.ingestion.StreamingIngestor` walks inputs in stable order, rejects symlinks, hashes source files in chunks, detects supported encodings, prevalidates each file, and returns per-file ingestion or quarantine outcomes. CSV/TSV rows retain raw headers/cells; JSON record arrays use escaped JSON Pointers; standalone FHIR R4 resources, complete FHIR Bundles, and text files use `doc`. Parsed records are lazy and record values are hidden from repr. |
| Shared contracts | Hold file metadata, normalized records with optional identity projections and source structure, typed processing outcomes, linkage decisions, manifest entries, and aggregate reports without depending on format-specific algorithms. |
| Normalization | Normalize representation while retaining source locators and medical values. `Normalizer.normalize` accepts a `ParsedRecord` and returns a `NormalizedRecord`; `PatientIdentityNormalizer` provides the identity-projection implementation. |
| PII detection | `lumen_ex.detection.MultilingualPIIDetector` scans structured fields, free text, keys, headers, and filenames for context-labelled identity fields and validated direct identifiers. It returns typed, offset-bearing findings with values and source keys hidden from repr. It is deterministic, offline, and does not alter records; it is not a general-purpose NER model. |
| Identity extraction and normalization | `lumen_ex.identity` projects parsed row/object values, FHIR R4 Patient resources or Bundles, and explicitly labeled English, Hindi, or Hinglish note fields into compact `PatientIdentity` values. It includes email and explicitly labeled relative names alongside identity/insurance identifiers, and patient-contact phones are distinguished from clinician context. `PatientIdentityNormalizer` attaches projections without changing parsed source fields. |
| Identity registry storage | `lumen_ex.registry.EncryptedIdentityRegistry` stores encrypted evidence in one per-run SQLite database and keyed block indexes for candidate retrieval. Hospital identifiers are scoped by an explicit issuer/source namespace when available; the matcher uses file-scoped namespaces when source context is absent or ambiguous. It is shared across batches, removes its private database directory on close, and refuses cluster merges with transitive same-issuer identifier conflicts. |
| Indic name normalization | `lumen_ex.detection.indic_names` normalizes supplied Latin/Devanagari name candidates with ITRANS transliteration, Unicode, punctuation, a small honorific vocabulary, and a limited set of common Mohammad spelling variants. It preserves initials and token order; name equality is not proof of identity. |
| Candidate matching | `lumen_ex.matching.IdentityMatcher` retrieves a bounded set of indexed candidates and applies deterministic evidence rules. A unique strong identifier, or a name plus DOB, relative name, or village and age (within one year), can support a link; names alone cannot. Ambiguous or conflicting evidence stays unresolved. `IdentityLinker` adapts results to the pipeline's LINK/DO_NOT_LINK/ABSTAIN contract. Registry cluster aliases are merged only when same-issuer hospital-identifier conflicts are absent across both transitive families. |
| Privacy transformation | `lumen_ex.privacy.PrivacyTransformer` applies keyed pseudonyms only for LINK decisions, per-patient date shifts, truthful age bands, conservative home-location generalization, finding-based identifier redaction, and cohort quasi-identifier assessment. Sanitized paths include a keyed opaque source code, not the issuer value. `transform_batch` is the release-capable API; its outputs can be sanitized, suppressed, or quarantined. |
| Leak scanning / security | `lumen_ex.security.SensitiveDataLeakScanner` reuses the M04 detector for structured values, text, headers, filenames, JSON/JSONL/CSV/TSV, reports, logs supplied for scanning, and on-disk files. Release artifacts and metadata are checked before publication; scan failures fail closed. |
| Output writing | `SanitizedOutputWriter` preserves CSV/TSV delimiters and headers, updates JSON records by RFC 6901 locators, writes text as UTF-8, adds pseudonyms only to an existing identity field (or a text-note header), and quarantines whole files on serialization or scanning failures. |
| Reporting | `PipelineReport` serializes the official `raksha-report/1` shape. `records.jsonl` maps exported input locators to output locators and pseudonyms; source names and exception text are excluded. |
| Validation / testing | `OutputContractValidator` checks manifest counts, output containment, record locators, and pseudonym presence in referenced records. The official validator remains unchanged and is run independently. |

The record-at-a-time `Pipeline` remains an injectable coordinator for stage tests.
`ReleasePipeline` provides the cohort-aware submission path and reuses the existing
normalizer, detector, matcher, transformer, scanner, output contracts, and registry
rather than duplicating their algorithms.

The M06 transformer requires cohort context to make its minimum-group-size decision.
Its `transform` adapter processes a singleton and therefore fails closed by suppressing
it when the configured minimum cannot be met. `transform_batch` generalizes the cohort,
measures equivalence classes and rare values, suppresses permitted quasi-identifiers
cohort-wide, then suppresses any remaining record whose group is still below the
configured minimum. `ReleasePipeline` supplies the complete cohort to
`transform_batch`; the smaller `Pipeline.run` API remains record-at-a-time and is not
used for submission releases.

## M06 transformation details

The privacy package shares purpose-separated HKDF key derivation with the encrypted
registry. Pseudonyms and date shifts use distinct derived keys and HMAC domain tags;
unlinked/abstained records receive no patient pseudonym and use a record-local date
shift reference instead. Dates are shifted by one deterministic offset per patient or
unresolved record, preserving time intervals. Source-unresolved ambiguous numeric dates
are redacted according to `ambiguous_date_action`; malformed date-like values remain
fail-closed rather than being silently emitted unchanged.

Age bands use the configured width below 85 and an open `85+` band above it. Residence
location follows the configured village → tehsil → district → state hierarchy, drops
street-level fields, and retains hospital/facility locations. Clinical fields (including
diagnoses, medications, doses, frequencies, vitals, labs, procedures, and stay
intervals) are checked for preservation. Rare clinical values are never individually
rewritten; if the configured risk threshold cannot be met through permitted QI
suppression, the record is explicitly suppressed.

Risk figures are cohort-specific estimates over recognized quasi-identifier fields,
not a security guarantee or a formal guarantee against linkage. Serialization and
leak scanning are performed by the separate release output boundary.

The identity helpers consume parsed values from the ingestion boundary. JSON discovery
selects root arrays and arrays under common collection keys; otherwise a JSON document
is one record. Each file is prevalidated before the lazy record stream is exposed, and
one unsupported or malformed file does not prevent outcomes for other files. The
ingestor performs basic FHIR resource and Bundle structure checks, not full profile or
terminology validation. Free-text extraction is limited to explicit field labels; it is
not a general name recognizer and does not perform record linking. The ingestion API is
available through `Pipeline.ingest_directory` and is also used directly by the
submission `ReleasePipeline`.

The registry provides encrypted storage, exact keyed block lookup, and streaming
candidate iteration. Issuer namespaces are taken from FHIR `Identifier.system` or
explicitly labeled source/facility/issuer metadata; the code does not infer a facility
from patient names. A file with one unambiguous source namespace can share its hospital
identifier block scope with other files carrying that namespace. Missing or conflicting
source context remains file-scoped. Exact hospital-identifier matches still require
corroborating name evidence; transliteration is not proof of identity. The bounded
matcher abstains when the candidate set overflows. Closing the registry removes its
private database and SQLite sidecars.

## Operational constraints

The command requires `RAKSHA_SECRET`, passes it to the per-run registry and transformer,
and clears the scanner canary after processing. Logs contain only safe error codes and
aggregate counts. Processing errors carry codes rather than source text. The ingestion API returns
safe per-file error codes without raw file contents; it does not write or modify input
files. These are engineering choices, not a claim that the current baseline removes PII
reliably or provides a complete security guarantee; see [security limitations](security.md).
