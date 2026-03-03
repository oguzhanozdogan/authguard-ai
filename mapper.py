# mapper.py

import re

from taxonomy import TAXONOMY

_CWE_PATTERN = re.compile(r"^CWE-0*(\d+)$", re.IGNORECASE)


def normalize_cwe(cwe: str) -> str:
    cleaned = str(cwe).strip().upper()
    match = _CWE_PATTERN.match(cleaned)
    if not match:
        return cleaned
    return f"CWE-{int(match.group(1))}"


def _build_taxonomy_index() -> dict[str, list[tuple[str, dict]]]:
    index: dict[str, list[tuple[str, dict]]] = {}
    for category, data in TAXONOMY.items():
        for cwe in data.get("cwe", []):
            normalized = normalize_cwe(cwe)
            index.setdefault(normalized, []).append((category, data))
    return index


_TAXONOMY_INDEX = _build_taxonomy_index()


def map_to_taxonomy(findings):

    mapped = []

    for f in findings:

        normalized_cwes = [normalize_cwe(c) for c in f.get("cwe", []) if c]
        matches = []

        for cwe in normalized_cwes:
            for category_data in _TAXONOMY_INDEX.get(cwe, []):
                if category_data not in matches:
                    matches.append(category_data)

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
                    "model": f.get("model"),
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
                "model": f.get("model"),
                "mitigation": [
                    "Review finding details and rule documentation.",
                    "Extend taxonomy coverage for this CWE or rule."
                ]
            })

    return mapped
