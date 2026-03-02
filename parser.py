import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any, TypedDict


class Finding(TypedDict):
    rule_id: str | None
    message: str
    cwe: list[str]
    severity: str | None
    security_severity: str | None
    file: str | None
    line: int | None


def _extract_cwes(tags: list[str]) -> list[str]:
    cwes: list[str] = []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("external/cwe/"):
            cwes.append(tag.split("/")[-1].upper())
    return cwes


def parse_sarif(file_path: str | Path) -> list[Finding]:
    """
    Parses a SARIF file produced by CodeQL and extracts
    structured vulnerability findings.

    Returns:
        List of dictionaries containing:
        - rule_id
        - message
        - cwe
        - severity
        - security_severity
        - file
        - line
    """

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"SARIF file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
    except JSONDecodeError as exc:
        raise ValueError(f"Invalid SARIF JSON: {path}") from exc

    findings: list[Finding] = []

    for run in data.get("runs", []):

        tool = run.get("tool", {})
        rules_index = {}

        # Build rule metadata lookup from both driver and extensions.
        for rule in tool.get("driver", {}).get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                rules_index[rule_id] = rule
        for extension in tool.get("extensions", []):
            for rule in extension.get("rules", []):
                rule_id = rule.get("id")
                if rule_id and rule_id not in rules_index:
                    rules_index[rule_id] = rule

        # Iterate over results
        for result in run.get("results", []):

            rule_id = result.get("ruleId") or result.get("rule", {}).get("id")
            message_data = result.get("message", {})
            message = (
                message_data.get("text")
                or message_data.get("markdown")
                or "No message provided."
            )

            rule_metadata = rules_index.get(rule_id, {})
            properties = rule_metadata.get("properties", {})
            result_properties = result.get("properties", {})

            # Extract CWE
            cwe_list = _extract_cwes(properties.get("tags", []))

            # Extract severity
            severity = (
                rule_metadata.get("defaultConfiguration", {}).get("level")
                or result.get("level")
            )
            security_severity = (
                properties.get("security-severity")
                or result_properties.get("security-severity")
            )

            # Extract location
            location_file_path = None
            line_number = None

            locations = result.get("locations", [])
            if locations:
                physical_location = locations[0].get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                region = physical_location.get("region", {})

                location_file_path = artifact_location.get("uri")
                line_number = region.get("startLine")
            findings.append(
                {
                    "rule_id": rule_id,
                    "message": message,
                    "cwe": cwe_list,
                    "severity": severity,
                    "security_severity": security_severity,
                    "file": location_file_path,
                    "line": line_number,
                }
            )

    return findings
