import json
from pathlib import Path
import re


DATASET_CATEGORIES = [
    "credential_verification",
    "input_processing",
    "password_hashing",
    "session",
    "token_management",
    "user_login_validation",
]

_NUMERIC_SUFFIX_PATTERN = re.compile(r"^(?P<dataset>.+?)_(?P<index>\d+)$")
_CATEGORY_ALIASES = {
    "credential_verification": "credential_verification",
    "crendential_verification": "credential_verification",
    "input_processing": "input_processing",
    "password_hashing": "password_hashing",
    "passowrd_hashing": "password_hashing",
    "session": "session",
    "session_handling": "session",
    "token_management": "token_management",
    "user_login_validation": "user_login_validation",
}


def _dataset_category_from_file(file_path: str | None) -> str:
    if not file_path:
        return "other"

    filename = Path(file_path.replace("\\", "/")).name
    stem = Path(filename).stem
    match = _NUMERIC_SUFFIX_PATTERN.match(stem)
    if match:
        base = match.group("dataset").lower()
        return _CATEGORY_ALIASES.get(base, "other")
    return _CATEGORY_ALIASES.get(stem.lower(), "other")


def _strip_dataset_fields(finding: dict) -> dict:
    cleaned = dict(finding)
    cleaned.pop("dataset_name", None)
    cleaned.pop("dataset_category", None)
    return cleaned


def _group_by_dataset_category(results) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {name: [] for name in DATASET_CATEGORIES}
    grouped["other"] = []

    for finding in results:
        dataset_category = _dataset_category_from_file(finding.get("file"))
        grouped[dataset_category].append(_strip_dataset_fields(finding))

    return grouped


def generate_report(results, output_path: str | Path = "reports/report.json") -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    grouped_results = _group_by_dataset_category(results)

    with output.open("w", encoding="utf-8") as f:
        json.dump(grouped_results, f, indent=2)

    print(f"Report written to {output}")
    return output
