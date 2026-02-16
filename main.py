from codeql_runner import create_codeql_database, run_analysis
from parser import parse_sarif
from mapper import map_to_taxonomy
from reporter import generate_report


def main():

    source_path = "dataset"
    db_path = "codeql_db"
    output_file = "results.sarif"

    print("[1] Creating CodeQL database...")
    create_codeql_database(source_path, db_path)

    print("[2] Running analysis...")
    run_analysis(db_path, output_file)

    print("[3] Parsing results...")
    findings = parse_sarif(output_file)

    print("[4] Mapping to taxonomy...")
    mapped = map_to_taxonomy(findings)

    print("[5] Generating report...")
    generate_report(mapped)

    print("[OK] Pipeline completed.")


if __name__ == "__main__":
    main()
