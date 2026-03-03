import argparse

from codeql_runner import create_codeql_database, run_analysis
from config import (
    DEFAULT_DB_PATH,
    DEFAULT_REPORT_PATH,
    DEFAULT_SARIF_PATH,
    DEFAULT_SOURCE_PATH,
)
from parser import parse_sarif
from mapper import map_to_taxonomy
from reporter import generate_report


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be a positive integer.")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run AuthGuard-AI pipeline: CodeQL -> SARIF parser -> taxonomy report."
    )
    parser.add_argument("--source-path", default=str(DEFAULT_SOURCE_PATH))
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--sarif-path", default=str(DEFAULT_SARIF_PATH))
    parser.add_argument("--report-path", default=str(DEFAULT_REPORT_PATH))
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Disable CodeQL query pack download during analysis.",
    )
    parser.add_argument(
        "--ram",
        type=_positive_int,
        default=None,
        help="Maximum RAM for CodeQL in MB (for example, 3072 or 4096).",
    )
    parser.add_argument(
        "--threads",
        type=_positive_int,
        default=None,
        help="Number of CodeQL threads to use.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        print("[1] Creating CodeQL database...")
        create_codeql_database(
            args.source_path,
            args.db_path,
            ram=args.ram,
            threads=args.threads,
        )

        print("[2] Running analysis...")
        run_analysis(
            args.db_path,
            args.sarif_path,
            download=not args.no_download,
            ram=args.ram,
            threads=args.threads,
        )

        print("[3] Parsing results...")
        findings = parse_sarif(args.sarif_path, source_root=args.source_path)

        print("[4] Mapping to taxonomy...")
        mapped = map_to_taxonomy(findings)

        print("[5] Generating report...")
        report_path = generate_report(mapped, args.report_path)

        print(f"[OK] Pipeline completed. Report: {report_path}")
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
