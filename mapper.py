# mapper.py

from taxonomy import TAXONOMY


def normalize_cwe(cwe: str) -> str:

    if not cwe.startswith("CWE-"):
        return cwe

    num = cwe.replace("CWE-", "")
    return "CWE-" + str(int(num))


def map_to_taxonomy(findings):

    mapped = []

    for f in findings:

        normalized_cwes = [normalize_cwe(c) for c in f.get("cwe", [])]
        matches = []

        for category, data in TAXONOMY.items():

            if any(c in data["cwe"] for c in normalized_cwes):
                matches.append((category, data))

        if matches:
            for category, data in matches:
                mapped.append({
                    "category": category,
                    "description": data["description"],
                    "rule_id": f["rule_id"],
                    "message": f["message"],
                    "cwe": normalized_cwes,
                    "severity": f["severity"],
                    "security_severity": f["security_severity"],
                    "file": f["file"],
                    "line": f["line"],
                    "mitigation": data["mitigation"]
                })
        else:
            mapped.append({
                "category": "Uncategorized",
                "description": "Finding did not match the current taxonomy CWE groups.",
                "rule_id": f["rule_id"],
                "message": f["message"],
                "cwe": normalized_cwes,
                "severity": f["severity"],
                "security_severity": f["security_severity"],
                "file": f["file"],
                "line": f["line"],
                "mitigation": [
                    "Review finding details and rule documentation.",
                    "Extend taxonomy coverage for this CWE or rule."
                ]
            })

    return mapped
