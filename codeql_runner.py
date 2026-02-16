import subprocess
from config import CODEQL_PATH, LANGUAGE, QUERY_PACK


def create_codeql_database(source_path: str, db_path: str) -> None:

    command = [
        CODEQL_PATH,
        "database",
        "create",
        db_path,
        "--overwrite",
        f"--language={LANGUAGE}",
        f"--source-root={source_path}"
    ]

    subprocess.run(command, check=True)


def run_analysis(db_path: str, output_file: str) -> None:

    command = [
        CODEQL_PATH,
        "database",
        "analyze",
        db_path,
        QUERY_PACK,
        "--download",
        "--format=sarifv2.1.0",
        f"--output={output_file}"
    ]

    subprocess.run(command, check=True)
