# AuthGuard-AI
<img width="1196" height="605" alt="image" src="https://github.com/user-attachments/assets/216209a2-0fbb-467c-b774-4e7f73267a61" />

A CodeQL-based security analysis pipeline for LLM-generated source code.

## Overview

AuthGuard-AI is a research prototype developed as part of a master's thesis on security risks in large language model (LLM)-generated code.

It implements an automated pipeline that:

- analyzes AI-generated JavaScript programs
- runs static application security testing (SAST) with CodeQL
- extracts findings in SARIF format
- maps findings to CWE identifiers
- classifies weaknesses using a structured taxonomy
- generates mitigation-oriented security reports

## Research Objectives

- Detect injection and input-validation vulnerabilities systematically
- Classify findings using standardized CWE identifiers
- Validate recurring weakness patterns empirically
- Support cross-model comparability
- Produce evidence-based mitigation guidance

## System Architecture

```text
Source Code (LLM Output)
        |
        v
CodeQL SAST Analysis
        |
        v
SARIF Output
        |
        v
Parser
        |
        v
Taxonomy Mapper
        |
        v
Report Generator
```

## Technology Stack

| Component | Tool |
| --- | --- |
| Programming Language | Python 3.11+ |
| Static Analysis | CodeQL CLI 2.24.1 |
| Output Format | SARIF 2.1.0 |
| Data Storage | JSON |
| Platform | Windows / Linux |

## Project Structure

```text
authguard_ai/
|- main.py              # Pipeline controller
|- config.py            # Tool configuration
|- codeql_runner.py     # CodeQL integration
|- parser.py            # SARIF parser
|- mapper.py            # Taxonomy mapping
|- taxonomy.py          # Vulnerability taxonomy
|- reporter.py          # Report generator
|- dataset/             # LLM-generated samples
|- reports/             # Output reports
`- results.sarif        # Raw analysis output
```

## Requirements

- Python 3.11+
- CodeQL CLI (2.24.1 or newer recommended)
- Windows, Linux, or macOS

No third-party Python package is required at runtime.

## Configuration

You can configure the pipeline using environment variables:

- `AUTHGUARD_CODEQL_PATH`
- `AUTHGUARD_LANGUAGE`
- `AUTHGUARD_QUERY_PACK`
- `AUTHGUARD_SOURCE_PATH`
- `AUTHGUARD_DB_PATH`
- `AUTHGUARD_SARIF_PATH`
- `AUTHGUARD_REPORT_PATH`

If not set, defaults from `config.py` are used.

## Usage

Run the full pipeline:

```powershell
python main.py
```

Optional arguments:

```powershell
python main.py --source-path dataset --db-path codeql_db --sarif-path results.sarif --report-path reports/report.json
python main.py --no-download
```

`python main.py` runs CodeQL with query pack download enabled (default), which can
fetch updates and may change findings over time.

`python main.py --no-download` disables query pack download and uses local packs
only, which is faster and more reproducible but may fail if packs are not already
installed.

## Testing

Run unit tests:

```powershell
python -m unittest -v
```

## Output

- SARIF output path: `results.sarif` (default)
- Mapped report path: `reports/report.json` (default)

Example report item:

```json
{
  "category": "Injection",
  "rule_id": "js/sql-injection",
  "cwe": ["CWE-89"],
  "severity": "error"
}
```

## Reproducibility Notes

Results are reproducible when using:

1. The same dataset
2. The same CodeQL CLI version
3. The same query pack version
4. The same pipeline configuration

If `--download` is enabled, query packs may update over time and change findings.

## Limitations

- Static analysis only
- No runtime validation or exploit confirmation
- Accuracy depends on CodeQL models and query coverage

## Security

See `SECURITY.md` for vulnerability reporting guidance.
