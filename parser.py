import json
from json import JSONDecodeError
from pathlib import Path
import re
from typing import Any, TypedDict


class Finding(TypedDict):
    rule_id: str | None
    message: str
    cwe: list[str]
    severity: str | None
    security_severity: str | None
    file: str | None
    line: int | None
    model: str | None


_MODEL_PATTERN = re.compile(r"^\s*Model:\s*(?P<model>.+?)\s*$", re.IGNORECASE)


def _normalize_model_name(raw_model: str | None) -> str | None:
    if not raw_model:
        return None

    cleaned = raw_model.strip()
    while cleaned.lower().startswith("model:"):
        cleaned = cleaned.split(":", 1)[1].strip()

    lowered = cleaned.lower()
    if "chaptgpt" in lowered or "chatgpt" in lowered:
        return "Chaptgpt-5"
    if "grok" in lowered:
        return "xAI Grok 4"
    if "claude" in lowered and "sonnet" in lowered:
        return "Anthropic Claude Sonnet 4.6"
    if "copilot" in lowered:
        return "Copilot GPT-4-class"
    return cleaned


def _resolve_source_file(file_uri: str | None, source_root: Path | None) -> Path | None:
    if not file_uri:
        return None

    normalized = file_uri.replace("\\", "/")
    relative = Path(normalized)
    candidates: list[Path] = [relative, Path(relative.name)]

    if source_root is not None:
        candidates.extend([source_root / relative, source_root / relative.name])

    dataset_root = Path("dataset")
    candidates.extend([dataset_root / relative, dataset_root / relative.name])

    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _extract_model_from_source(file_uri: str | None, source_root: Path | None) -> str | None:
    source_file = _resolve_source_file(file_uri, source_root)
    if source_file is None:
        return None

    try:
        with source_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for _ in range(80):
                line = handle.readline()
                if not line:
                    break
                match = _MODEL_PATTERN.match(line)
                if match:
                    return _normalize_model_name(match.group("model"))
    except OSError:
        return None
    return None


def _extract_cwes(tags: list[str]) -> list[str]:
    cwes: list[str] = []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("external/cwe/"):
            cwes.append(tag.split("/")[-1].upper())
    return cwes


def parse_sarif(file_path: str | Path, source_root: str | Path | None = None) -> list[Finding]:
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
    resolved_source_root = Path(source_root) if source_root is not None else None

    try:
        with path.open("r", encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
    except JSONDecodeError as exc:
        raise ValueError(f"Invalid SARIF JSON: {path}") from exc

    findings: list[Finding] = []
    model_cache: dict[str | None, str | None] = {}

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

            if location_file_path not in model_cache:
                model_cache[location_file_path] = _extract_model_from_source(
                    location_file_path, resolved_source_root
                )

            findings.append(
                {
                    "rule_id": rule_id,
                    "message": message,
                    "cwe": cwe_list,
                    "severity": severity,
                    "security_severity": security_severity,
                    "file": location_file_path,
                    "line": line_number,
                    "model": model_cache[location_file_path],
                }
            )

    return findings
