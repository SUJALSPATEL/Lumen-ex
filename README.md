# Lumen‑ex

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Ready-success)](#)

**Lumen‑ex** is an offline, CPU‑only, LLM‑free privacy firewall for healthcare data (Secret Wards). It ingests mixed hospital exports, detects personal identifiers in English, Hindi, and Hinglish, links records when evidence supports a match, and reduces quasi‑identifier exposure while preserving clinical values.

---

<details open>
  <summary><strong>📖 Table of Contents</strong></summary>
  <ul>
    <li><a href="#architecture-overview">Architecture Overview</a></li>
    <li><a href="#quick-start-windows-powershell">Quick Start (Windows PowerShell)</a></li>
    <li><a href="#repository-layout">Repository Layout</a></li>
    <li><a href="#development--testing">Development & Testing</a></li>
    <li><a href="#submission-checklist">Submission Checklist</a></li>
    <li><a href="#further-reading">Further Reading</a></li>
  </ul>
</details>

---

## Architecture Overview <a name="architecture-overview"></a>

```
Read‑only input tree
  └─ discover, hash and parse records
  └─ normalize identity evidence & detect PII
  └─ encrypted registry (linkage) – or abstain
  └─ derive pseudonyms, shift dates, generalise
  └─ serialize by file & scan artifacts
  └─ validate `sanitized/`, `report.json`, `records.jsonl`
```

*See `docs/architecture.md` for a detailed diagram and component responsibilities.*

---

## Quick Start (Windows PowerShell) <a name="quick-start-windows-powershell"></a>

<details>
  <summary>Show step‑by‑step commands</summary>

```powershell
# 1️⃣ Create a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2️⃣ Install dependencies
python -m pip install -r requirements.txt

# 3️⃣ Set the secret (practice mode) and run the pipeline
$env:RAKSHA_SECRET = "practice"
python -B main.py --input dev\input --output my_output

# 4️⃣ Validate the output contract
python -B validate_output.py --input dev\input --output my_output

# 5️⃣ Run the official pre‑submit checker (POSIX quoting now works on Windows)
python -B check_submission.py --repo . --run
```

All commands finish in < 30 s, < 4 GB RAM on a 2‑core machine.
</details>

---

## Repository Layout <a name="repository-layout"></a>

```text
main.py                     # evaluator entry point
raksha.toml                 # submission metadata (team name, run, setup)
config/policy.yaml          # privacy‑policy settings
lumen_ex/                   # core implementation
  cli.py
  config.py
  pipeline.py
  release.py
  output.py
  ingestion.py
  identity.py
  matching.py
  detection/
    pii.py
    indic_names.py
  privacy/                 # pseudonym, date‑shift, generalisation
  security/                # leak scanner & artifact checks
starter/                    # starter wrapper (used by CI)
tests/                      # unit‑test suite (184 tests)
docs/                      # architecture, contracts, security, decisions
README.md                   # this file
check_submission.py         # official checker (fixed for Windows paths)
validate_output.py          # contract validator
```

---

## Development & Testing <a name="development--testing"></a>

```powershell
# Run the full test suite
python -m unittest discover -s tests -v

# Optional synthetic workload tools
python -m tools.m09_synthetic
python -m tools.practice_metrics --output my_output
```

The test suite reports **184 tests**, all passing (`OK`).

---

## Submission Checklist <a name="submission-checklist"></a>

- `raksha.toml` present with correct `name`, `run`, and `setup` fields.
- `README.md` includes setup, architecture, and usage (this file).
- 2‑page Project Brief PDF (`docs/Lumen‑ex-Project‑Brief.pdf`).
- No LLM or hosted‑AI packages in `requirements.txt`.
- All temporary artefacts ignored via `.gitignore` (including `audit_output/`).
- `python -B check_submission.py --repo . --run` ends with **READY TO SUBMIT**.

---

## Further Reading <a name="further-reading"></a>

- [Problem statement](docs/PROBLEM_STATEMENT.md)
- [Output specification (SPEC)](docs/SPEC.md)
- [Scoring](docs/SCORING.md)
- [Dataset guide](docs/DATASET.md)
- [Security design](docs/security.md)
- Architecture decisions: `docs/decisions/`

---

*This repository complies with the Secret Wards competition rules and is ready for final submission.*