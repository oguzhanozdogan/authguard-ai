import json
import tempfile
import unittest
from pathlib import Path

from mapper import map_to_taxonomy
from parser import parse_sarif
from reporter import generate_report


class TestPipelineComponents(unittest.TestCase):
    def test_parse_sarif_extracts_finding_data(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "js/sql-injection",
                                    "defaultConfiguration": {"level": "error"},
                                    "properties": {
                                        "tags": [
                                            "security",
                                            "external/cwe/cwe-089",
                                        ],
                                        "security-severity": "8.8",
                                    },
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "js/sql-injection",
                            "message": {"text": "SQL query built from user input."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "sample.js"},
                                        "region": {"startLine": 25},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "results.sarif"
            sarif_path.write_text(json.dumps(sarif), encoding="utf-8")

            findings = parse_sarif(sarif_path)

        self.assertEqual(1, len(findings))
        self.assertEqual("js/sql-injection", findings[0]["rule_id"])
        self.assertEqual(["CWE-089"], findings[0]["cwe"])
        self.assertEqual("error", findings[0]["severity"])
        self.assertEqual("sample.js", findings[0]["file"])
        self.assertEqual(25, findings[0]["line"])

    def test_mapper_normalizes_cwes_for_taxonomy_matching(self) -> None:
        findings = [
            {
                "rule_id": "js/sql-injection",
                "message": "SQL query built from user input.",
                "cwe": ["CWE-089"],
                "severity": "error",
                "security_severity": "8.8",
                "file": "sample.js",
                "line": 25,
            }
        ]

        mapped = map_to_taxonomy(findings)
        self.assertEqual(1, len(mapped))
        self.assertEqual("Injection", mapped[0]["category"])
        self.assertEqual(["CWE-89"], mapped[0]["cwe"])

    def test_reporter_creates_output_directory(self) -> None:
        results = [{"category": "Test"}]

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "nested" / "report.json"
            written_path = generate_report(results, output_path)

            self.assertEqual(output_path, written_path)
            self.assertTrue(output_path.exists())
            stored = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(results, stored)


if __name__ == "__main__":
    unittest.main(verbosity=2)
