# parser.py

import json


def parse_sarif(file_path: str):
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

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []

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
            message = result.get("message", {}).get("text")

            rule_metadata = rules_index.get(rule_id, {})
            properties = rule_metadata.get("properties", {})

            # Extract CWE
            cwe_list = []
            for tag in properties.get("tags", []):
                if tag.startswith("external/cwe/"):
                    cwe_number = tag.split("/")[-1].upper()
                    cwe_list.append(cwe_number)

            # Extract severity
            severity = (
                rule_metadata.get("defaultConfiguration", {}).get("level")
                or result.get("level")
            )
            security_severity = properties.get("security-severity")

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

            findings.append({
                "rule_id": rule_id,
                "message": message,
                "cwe": cwe_list,
                "severity": severity,
                "security_severity": security_severity,
                "file": location_file_path,
                "line": line_number
            })

    return findings
