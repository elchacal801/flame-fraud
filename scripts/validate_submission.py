#!/usr/bin/env python3
"""
validate_submission.py - FLAME Submission Validator

Validates the structure and frontmatter of FLAME submission
markdown files. Designed to run in CI (GitHub Actions) on PRs
that modify ThreatPaths/, Baselines/, or DetectionLogic/.

Usage:
    python scripts/validate_submission.py <file.md> [<file2.md> ...]

Exit codes:
    0 - All files pass validation
    1 - One or more files failed validation
"""

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

VALID_CFPF_PHASES = {"P1", "P2", "P3", "P4", "P5"}

VALID_CATEGORIES = {"ThreatPath", "Baseline", "DetectionLogic"}

VALID_ID_PREFIXES = {
    "ThreatPath": "TP-",
    "Baseline": "BL-",
    "DetectionLogic": "DL-",
}

VALID_TLP = {"WHITE", "GREEN", "AMBER", "RED"}

TAXONOMY_FILE = Path(__file__).resolve().parent.parent / "flame_taxonomy.json"
try:
    with open(TAXONOMY_FILE, "r", encoding="utf-8") as _f:
        _tax = json.load(_f)
        VALID_SECTORS = set(_tax.get("sectors", []))
        VALID_FRAUD_TYPES = set(_tax.get("fraud_types", []))
except Exception as _e:
    print(f"WARNING: Failed to load taxonomy from {TAXONOMY_FILE}: {_e}", file=sys.stderr)
    VALID_SECTORS = set()
    VALID_FRAUD_TYPES = set()

REQUIRED_FRONTMATTER_FIELDS = [
    "id", "title", "category", "date", "author", "source",
    "tlp", "sector", "fraud_types", "cfpf_phases",
]

REQUIRED_BODY_SECTIONS = [
    "Summary",
    "CFPF Phase Mapping",
    "Detection Approaches",
    "Controls & Mitigations",
    "References",
]

# Matches code-fenced YAML blocks
FRONTMATTER_PATTERN = re.compile(
    r"```ya?ml\s*\n---\s*\n(.*?)\n---\s*\n```",
    re.DOTALL
)


# ---------------------------------------------------------------------------
# Validation logic
# ---------------------------------------------------------------------------

class ValidationResult:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str):
        self.errors.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def report(self) -> str:
        lines = [f"--- {self.filepath} ---"]
        if self.passed:
            lines.append("  PASS")
        else:
            lines.append(f"  FAIL ({len(self.errors)} error(s))")
        for e in self.errors:
            lines.append(f"  ERROR: {e}")
        for w in self.warnings:
            lines.append(f"  WARNING: {w}")
        return "\n".join(lines)


def validate_file(filepath: Path) -> ValidationResult:
    """Validate a single submission file."""
    result = ValidationResult(str(filepath))

    if not filepath.exists():
        result.error(f"File not found: {filepath}")
        return result

    if not filepath.suffix == ".md":
        result.error("File must be a .md markdown file")
        return result

    text = filepath.read_text(encoding="utf-8")

    # --- Extract frontmatter ---
    match = FRONTMATTER_PATTERN.search(text)
    if not match:
        result.error("No YAML frontmatter block found (expected ```yaml ... ``` with --- delimiters)")
        return result

    try:
        meta = yaml.safe_load(match.group(1))
    except yaml.YAMLError as e:
        result.error(f"YAML parse error: {e}")
        return result

    if not isinstance(meta, dict):
        result.error("Frontmatter is not a YAML mapping")
        return result

    # --- Required fields ---
    for field in REQUIRED_FRONTMATTER_FIELDS:
        if field not in meta or meta[field] is None:
            result.error(f"Missing required field: {field}")

    # --- Field-specific validation ---
    # Category
    category = meta.get("category", "")
    if category and category not in VALID_CATEGORIES:
        result.error(f"Invalid category '{category}'. Must be one of: {', '.join(sorted(VALID_CATEGORIES))}")

    # ID format
    sub_id = meta.get("id", "")
    if sub_id and category:
        expected_prefix = VALID_ID_PREFIXES.get(category, "")
        if expected_prefix and not str(sub_id).startswith(expected_prefix):
            result.error(f"ID '{sub_id}' does not match expected prefix '{expected_prefix}' for category '{category}'")

    # TLP
    tlp = meta.get("tlp", "")
    if tlp and str(tlp).upper() not in VALID_TLP:
        result.error(f"Invalid TLP value '{tlp}'. Must be one of: {', '.join(sorted(VALID_TLP))}")

    # CFPF phases
    phases = meta.get("cfpf_phases", [])
    if isinstance(phases, list):
        for p in phases:
            if str(p) not in VALID_CFPF_PHASES:
                result.error(f"Invalid CFPF phase '{p}'. Must be one of: {', '.join(sorted(VALID_CFPF_PHASES))}")
    elif phases is not None:
        result.error("cfpf_phases must be a list")

    # Sectors
    sectors = meta.get("sector", [])
    if isinstance(sectors, list):
        for s in sectors:
            if s not in VALID_SECTORS:
                result.warn(f"Unrecognized sector '{s}' (not in standard list)")
    elif sectors is not None:
        result.error("sector must be a list")

    # Fraud types
    fraud_types = meta.get("fraud_types", [])
    if isinstance(fraud_types, list):
        for ft in fraud_types:
            if ft not in VALID_FRAUD_TYPES:
                result.warn(f"Unrecognized fraud type '{ft}' (not in standard list)")
    elif fraud_types is not None:
        result.error("fraud_types must be a list")

    # List fields that should be lists
    list_fields = ["tags", "mitre_attack", "ft3_tactics", "mitre_f3", "groupib_stages"]
    for field in list_fields:
        val = meta.get(field)
        if val is not None and not isinstance(val, list):
            result.error(f"Field '{field}' must be a list")

    # UCFF domains (optional, must be a mapping if present)
    ucff = meta.get("ucff_domains")
    if ucff is not None:
        if not isinstance(ucff, dict):
            result.error("Field 'ucff_domains' must be a mapping (object), not a list or scalar")
        else:
            valid_ucff_keys = {"commit", "assess", "plan", "act", "monitor", "report", "improve"}
            for key in ucff:
                if key not in valid_ucff_keys:
                    result.warn(f"Unrecognized UCFF domain '{key}'. Expected: {', '.join(sorted(valid_ucff_keys))}")

    # MITRE ATT&CK format validation
    mitre = meta.get("mitre_attack", [])
    if isinstance(mitre, list):
        for t in mitre:
            t_str = str(t)
            if t_str and not re.match(r"^T\d{4}(\.\d{3})?$", t_str):
                result.warn(f"MITRE ATT&CK ID '{t_str}' may not match expected format (T####[.###])")

    # --- Body section validation ---
    body_after_frontmatter = text[match.end():]
    for section in REQUIRED_BODY_SECTIONS:
        pattern = rf"^##\s+{re.escape(section)}"
        if not re.search(pattern, body_after_frontmatter, re.MULTILINE):
            result.error(f"Missing required section: ## {section}")

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_submission.py <file.md> [<file2.md> ...]", file=sys.stderr)
        sys.exit(2)

    files = [Path(f) for f in sys.argv[1:]]
    results = [validate_file(f) for f in files]

    all_passed = True
    for r in results:
        print(r.report())
        if not r.passed:
            all_passed = False

    print()
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    print(f"Results: {passed} passed, {failed} failed out of {len(results)} file(s)")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
