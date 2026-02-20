# AuthGuard-AI
<img width="1196" height="605" alt="image" src="https://github.com/user-attachments/assets/216209a2-0fbb-467c-b774-4e7f73267a61" />

A CodeQL-based security analysis pipeline for LLM-generated source code.

## Overview

AuthGuard-AI is a research prototype focused on security risks in generated code.
It automates:

1. CodeQL database creation
2. CodeQL security analysis
3. SARIF parsing
4. CWE-to-taxonomy mapping
5. JSON report generation

## Project Structure

```text
authguard_ai/
|- main.py
|- config.py
|- codeql_runner.py
|- parser.py
|- mapper.py
|- taxonomy.py
|- reporter.py
|- test_parser.py
|- dataset/
`- .github/workflows/codeql.yml
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
