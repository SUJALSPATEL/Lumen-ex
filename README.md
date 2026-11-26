# Lumen-ex

Lumen-ex is an offline, CPU-only, LLM-free healthcare-data privacy firewall for
Secret Wards. It turns mixed hospital exports into research releases by detecting
personal identifiers in English, Hindi, and Hinglish, linking records when the
identity evidence supports a match, and reducing quasi-identifier exposure while
checking recognized clinical values and stay lengths.

The official challenge kit is included in this repository. Read [START_HERE.md](START_HERE.md)
and the official [problem statement](docs/PROBLEM_STATEMENT.md),
[output specification](docs/SPEC.md), [scoring](docs/SCORING.md),
[dataset guide](docs/DATASET.md), [attack guide](docs/ATTACKS.md),
[sandbox rules](docs/SANDBOX.md), and [FAQ](docs/FAQ.md).
`dev/truth/truth.json` is practice evaluation data only: production processing must not
read it, and this foundation does not import it.

## Architecture

```text
Read-only input tree
  -> discover, hash and parse records
  -> normalize identity evidence and detect PII
  -> link through an encrypted registry or abstain
  -> derive pseudonyms, shift dates, generalize and apply cohort policy
  -> serialize by file and scan artifacts
  -> validate sanitized/, report.json and records.jsonl
```

CSV, TSV, JSON, FHIR R4 resources and text enter through the same release pipeline.
Unsupported or unsafe files receive a hash-only report entry. Unresolved exported
records carry a null pseudonym. Release paths with detected identifiers receive a
keyed replacement.

## Runtime and security

- Runtime must work offline on CPU and must not use LLMs, generative models, or
  pretrained transformers above the permitted parameter limit.
- Do not access the network during submission execution.
- Keep processing deterministic for identical input and secret.
- Keep secrets out of files and output; do not modify input data.
- Quarantine unsupported or unsafe files; never silently pass them through as clean.
- Preserve clinical values according to the official specification.

Purpose-separated keys protect registry evidence, candidate indexes, patient
pseudonyms and date offsets. The CLI emits aggregate counts and safe error codes.
The evaluation budget is two CPUs, 4 GB RAM and 15 minutes per run. Setup can
download dependencies. Runtime processing uses local files and libraries.

## Setup

Python 3.10 or later is required. Runtime dependencies are
`indic-transliteration` for offline Indic-script transliteration and `phonenumbers`
for offline phone validation and normalization, `ijson` for bounded JSON parsing, and
`cryptography` for authenticated encryption and keyed indexes.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The submission contract is the root [`raksha.toml`](raksha.toml). The evaluator runs
`python main.py --input {input} --output {output}` and supplies `RAKSHA_SECRET` through
the environment. For local practice in PowerShell:

```powershell
$env:RAKSHA_SECRET = "practice"
python main.py --input dev\input --output my_output
python validate_output.py --input dev\input --output my_output
python check_dev.py --output my_output --show 20
```

The final two commands are official kit checks. `check_dev.py` reads the practice
truth file during evaluation.

## Development

```powershell
python -m unittest discover -s tests -v
python -m tools.m09_synthetic
python -m tools.practice_metrics --output my_output
```

Run the unmodified Team Kit submission checker from a clean checkout in a POSIX
environment.

```sh
python check_submission.py --repo . --run
```

The checker uses POSIX shell quoting for absolute paths. Windows cmd.exe rejects
that quoting when paths contain spaces. Verify practice input hashes against the
kit manifest. Line-ending conversion can break the answer key's hash-based lookup
for renamed files.

```powershell
python -m tools.prepare_practice --output my_output_practice_input
$env:RAKSHA_SECRET = "practice"
python main.py --input my_output_practice_input --output my_output_verified
python validate_output.py --input my_output_practice_input --output my_output_verified
python check_dev.py --output my_output_verified --show 20
python -m tools.practice_metrics --output my_output_verified
```

## Measured evaluation

The output validator returned **CONTRACT OK** on all 200 hash-verified practice
inputs. The run exported 41 files and 186 record mappings, quarantined 158 files,
and suppressed one file. The practice self-check reported 49 of 3,230 identifier
matches (1.5%), including checks against original names of quarantined files.
An export-only check found five labeled matches in released content and metadata.
The checker found zero of four planted canaries and zero broken-file raw copies.

The practice self-check found 362 of 414 clinical values in released files (87.4%).
Across all 4,855 labeled values in the inputs, the file-level match rate was 7.5%.
Pairwise precision was 100%, recall was 1.67%, and F0.5 was 0.08. The supplemental
check counted 115 correct pairs, zero incorrect pairs, 6,777 missed pairs, and
zero complete patient clusters out of 48. Of 163 required units with an exported
mapping, 39 were deliberately left unlinked.

With Windows process affinity restricted to two CPUs, the practice run reported
24.65 seconds and 52.9 MB peak RSS. An expanded 601-file synthetic workload
reported 74.42 seconds and 72.7 MB peak RSS. It comprised three copies of the
practice input and a nested JSON file with 500 generated records.

The separate synthetic test released 10 of 12 records and preserved 70 of 70
checked clinical fields in those records, plus all five two-day stays. The
stay and other retained evidence let the simulated attacker correctly identify
five of ten records, with zero false claims. Requiring exact visit dates yielded
zero claims on those admissions. The attack uses an independently specified
synthetic population and reads the actual CLI output. Hidden-dataset results
are unavailable.

The [two-page Project Brief](docs/Lumen-ex-Project-Brief.pdf) follows the Team Kit
template. The practice results expose release blockers despite format compliance.

## Known limitations

- Malformed dates and file-level validation failures can quarantine a whole file.
  Unsafe records are omitted when other records in the same structured file pass.
  Ambiguous numeric dates without a source hint are redacted, not guessed; this
  lowers date utility. The cohort minimum can also suppress clinically valid rows
  when retained quasi-identifiers are rare.
- Text detection relies on multilingual patterns and known names. Unknown
  identifiers in content or JSON envelope metadata can survive.
- The matcher abstains when evidence is sparse or conflicting. Cross-file
  coverage is limited when hospitals use unrelated local identifiers.
- Shifting dates preserves stay duration, which can still identify a patient
  when combined with a diagnosis or facility. Stable pseudonyms also allow
  aggregation across records in one release.
- FHIR checks cover the supported resource and Bundle shapes. Profile semantics
  and arbitrary binary attachments have limited coverage.

## Structure

```text
main.py                    evaluator entry point
raksha.toml                official submission metadata and command
config/policy.yaml         validated policy settings
lumen_ex/
  cli.py                   arguments, configuration, safe diagnostics
  config.py                validated policy loading
  pipeline.py              injectable record-stage coordinator
  release.py               cohort-aware submission orchestration
  output.py                whole-file serialization and output validation
  stages.py                future module interfaces
  contracts/models.py      pipeline and report data contracts
  contracts/identity.py    compact identity projection contracts
  privacy/                 keyed pseudonyms, dates, generalization, risk, and transforms
  value_normalization.py   low-level age/date normalizers shared without package cycles
  ingestion.py             deterministic discovery, quarantine outcomes, and readers
  identity.py              identity extraction and field normalization
  registry.py              encrypted per-run registry and guarded cluster aliases
  matching.py              bounded candidate retrieval and conservative linkage
  detection/indic_names.py Devanagari-aware candidate name normalization
  detection/pii.py       deterministic multilingual PII detection
  security/                 pre-write leak scanning and artifact checks
  baseline.py              compatibility adapter for the shipped starter
starter/                   starter implementation with M07 pre-write guard
tests/                     foundation, ingestion, identity, detection, linkage, and privacy tests
docs/architecture.md       responsibilities, boundaries, and data flow
docs/contracts.md          internal models and official format compatibility
docs/security.md           key handling, scanning coverage, and limitations
docs/decisions/            material architecture decisions
validate_output.py         official output format validator (unchanged)
check_dev.py               official practice self-check (unchanged)
check_submission.py        official pre-submit check (unchanged)
```

More detail: [architecture](docs/architecture.md), [contracts](docs/contracts.md), and
[ADR 0001](docs/decisions/0001-project-foundation.md).
