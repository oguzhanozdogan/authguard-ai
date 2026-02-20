# AuthGuard-AI
<img width="1196" height="605" alt="image" src="https://github.com/user-attachments/assets/216209a2-0fbb-467c-b774-4e7f73267a61" />


A CodeQL-based security analysis agent for LLM-generated source code.

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

### Software

- Python 3.11 or higher
- CodeQL CLI 2.24.1
- Windows, Linux, or macOS

### Python Packages

No external packages are required. The project uses only standard libraries.

## Installation

### 1. Install Python

Download: `https://www.python.org/downloads/`

Verify:

```powershell
python --version
```

### 2. Install CodeQL

Download: `https://github.com/github/codeql-cli-binaries/releases`

Example extraction path:

```text
D:\codeql-win64\codeql
```

### 3. Configure CodeQL Path

Edit `config.py`:

```python
CODEQL_PATH = r"D:\codeql-win64\codeql\codeql.exe"
LANGUAGE = "javascript"
QUERY_PACK = "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls"
```

Adjust paths/settings as needed for your environment.

## Preparing the Dataset

Place LLM-generated JavaScript files in:

```text
dataset/
```

Example:

```text
dataset/login_model1.js
```

## Running the System

From the project root:

```powershell
python main.py
```

Execution flow:

1. Database creation
2. Static analysis
3. SARIF generation
4. Parsing
5. Taxonomy mapping
6. Report generation

## Outputs

### Raw Output

`results.sarif` contains standardized CodeQL findings.

### Processed Report

`reports/report.json` contains structured results:

- category
- CWE identifiers
- severity
- location
- mitigation guidance

Example:

```json
{
  "category": "Injection",
  "cwe": ["CWE-89"],
  "severity": "error",
  "security_severity": "8.8"
}
```

## Reproducibility

To reproduce experiments:

1. Install dependencies
2. Configure `config.py`
3. Use the same dataset
4. Run `python main.py`

All steps are deterministic.

## Limitations

This prototype does not perform:

- dynamic analysis
- runtime exploitation
- penetration testing
- proprietary tool integration

Detection accuracy depends on CodeQL modeling of application context.

## Research Use
This artifact supports:

- empirical vulnerability analysis
- taxonomy validation
- comparative model evaluation
- methodological replication

Intended primarily for academic research and evaluation.
