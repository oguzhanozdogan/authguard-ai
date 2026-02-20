import shutil
import subprocess
from pathlib import Path

from config import CODEQL_PATH, LANGUAGE, QUERY_PACK


def _resolve_codeql_path() -> str:
    configured = Path(CODEQL_PATH)
    if configured.exists():
        return str(configured)

    discovered = shutil.which(CODEQL_PATH) or shutil.which("codeql")
    if discovered:
        return discovered

    raise FileNotFoundError(
        "CodeQL executable not found. Set AUTHGUARD_CODEQL_PATH or update config.py."
    )


def _run_command(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        output = (exc.stderr or exc.stdout or "").strip()
        raise RuntimeError(f"CodeQL command failed: {' '.join(command)}\n{output}") from exc


def create_codeql_database(source_path: str | Path, db_path: str | Path) -> None:
    source = Path(source_path)
    db = Path(db_path)
    if not source.exists():
        raise FileNotFoundError(f"Source path does not exist: {source}")

    command = [
        _resolve_codeql_path(),
        "database",
        "create",
        str(db),
        "--overwrite",
        f"--language={LANGUAGE}",
        f"--source-root={source}",
    ]

    _run_command(command)


def run_analysis(
    db_path: str | Path,
    output_file: str | Path,
    *,
    download: bool = True,
) -> None:
    db = Path(db_path)
    output = Path(output_file)
    if not db.exists():
        raise FileNotFoundError(f"CodeQL database path does not exist: {db}")

    command = [
        _resolve_codeql_path(),
        "database",
        "analyze",
        str(db),
        QUERY_PACK,
        "--format=sarifv2.1.0",
        f"--output={output}",
    ]
    if download:
        command.append("--download")

    _run_command(command)
