# reporter.py

import json


def generate_report(results):

    with open("reports/report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("Report written to reports/report.json")
