import os
from pathlib import Path

CODEQL_PATH = os.getenv("AUTHGUARD_CODEQL_PATH", r"D:\codeql-win64\codeql\codeql.exe")
LANGUAGE = os.getenv("AUTHGUARD_LANGUAGE", "javascript")
QUERY_PACK = os.getenv(
    "AUTHGUARD_QUERY_PACK",
    "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
)

DEFAULT_SOURCE_PATH = Path(os.getenv("AUTHGUARD_SOURCE_PATH", "dataset"))
DEFAULT_DB_PATH = Path(os.getenv("AUTHGUARD_DB_PATH", "codeql_db"))
DEFAULT_SARIF_PATH = Path(os.getenv("AUTHGUARD_SARIF_PATH", "results.sarif"))
DEFAULT_REPORT_PATH = Path(os.getenv("AUTHGUARD_REPORT_PATH", "reports/report.json"))
