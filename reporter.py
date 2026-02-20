import json
from pathlib import Path


def generate_report(results, output_path: str | Path = "reports/report.json") -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Report written to {output}")
    return output
