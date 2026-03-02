#!/usr/bin/env python3
"""Validate KQL detection files for required metadata and formatting."""

import re
import sys
from pathlib import Path

REQUIRED_FIELDS = ["Name", "MITRE", "Severity", "Description"]
VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
MITRE_PATTERN = re.compile(r"T\d{4}(\.\d{3})?")

DETECTIONS_DIR = Path(__file__).resolve().parent.parent / "detections"


def parse_metadata(filepath: Path) -> dict[str, str]:
    """Extract metadata fields from comment headers in a .kql file."""
    metadata = {}
    with open(filepath, encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line.startswith("//"):
                break
            match = re.match(r"^//\s*(\w[\w\s]*?):\s*(.+)$", line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                metadata[key] = (value, line_num)
    return metadata


def validate_file(filepath: Path) -> list[str]:
    """Validate a single .kql file. Returns a list of error messages."""
    errors = []
    relative = filepath.relative_to(DETECTIONS_DIR.parent)

    metadata = parse_metadata(filepath)

    for field in REQUIRED_FIELDS:
        if field not in metadata:
            errors.append(f"{relative}: Missing required metadata field '{field}'")

    if "Severity" in metadata:
        severity_val, line_num = metadata["Severity"]
        if severity_val not in VALID_SEVERITIES:
            errors.append(
                f"{relative}:{line_num}: Invalid severity '{severity_val}'. "
                f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )

    if "MITRE" in metadata:
        mitre_val, line_num = metadata["MITRE"]
        if not MITRE_PATTERN.search(mitre_val):
            errors.append(
                f"{relative}:{line_num}: Invalid MITRE technique ID in '{mitre_val}'. "
                f"Expected format: T<nnnn> or T<nnnn>.<nnn>"
            )

    # Check that the file has a query body (non-comment, non-empty lines)
    with open(filepath, encoding="utf-8") as f:
        has_query = any(
            line.strip() and not line.strip().startswith("//")
            for line in f
        )
    if not has_query:
        errors.append(f"{relative}: No KQL query body found after metadata headers")

    return errors


def main() -> int:
    """Validate all .kql files in the detections directory."""
    if not DETECTIONS_DIR.exists():
        print(f"ERROR: Detections directory not found: {DETECTIONS_DIR}")
        return 1

    kql_files = sorted(DETECTIONS_DIR.rglob("*.kql"))

    if not kql_files:
        print(f"ERROR: No .kql files found in {DETECTIONS_DIR}")
        return 1

    print(f"Validating {len(kql_files)} KQL detection file(s)...\n")

    all_errors = []
    for filepath in kql_files:
        errors = validate_file(filepath)
        if errors:
            all_errors.extend(errors)
            print(f"  FAIL: {filepath.relative_to(DETECTIONS_DIR.parent)}")
            for error in errors:
                print(f"    - {error}")
        else:
            print(f"  PASS: {filepath.relative_to(DETECTIONS_DIR.parent)}")

    print()
    if all_errors:
        print(f"FAILED: {len(all_errors)} error(s) found in {len(kql_files)} file(s)")
        return 1

    print(f"SUCCESS: All {len(kql_files)} detection file(s) are valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
