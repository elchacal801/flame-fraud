#!/usr/bin/env python3
"""
ft3_mapper.py - FT3 Auto-Mapper for FLAME Threat Paths

Reads the vendored FT3 JSON files and each threat path's existing YAML
frontmatter, then suggests appropriate FT3 tactic and technique IDs for
each of the 23 threat paths using three mapping signals:
    1. CFPF phase -> FT3 tactic position alignment
    2. Group-IB stage -> FT3 tactic name matching
    3. Fraud type keywords -> FT3 technique name/description matching

Usage:
    python scripts/ft3_mapper.py                    # dry-run (default)
    python scripts/ft3_mapper.py --apply            # update frontmatter
    python scripts/ft3_mapper.py --root /path/to/repo

Output:
    ft3_mapping_suggestions.json  (written to repo root)
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
log = logging.getLogger("ft3_mapper")

# ---------------------------------------------------------------------------
# Constants — mapping tables
# ---------------------------------------------------------------------------

# CFPF phase -> FT3 tactic IDs (kill chain position alignment)
CFPF_TO_FT3_TACTICS: dict[str, list[str]] = {
    "P1": ["FTA001", "FTA002"],
    "P2": ["FTA003", "FTA004"],
    "P3": ["FTA005", "FTA006"],
    "P4": ["FTA007", "FTA009"],
    "P5": ["FTA010"],
}

# Group-IB stage name -> FT3 tactic ID (name alignment)
GROUPIB_TO_FT3_TACTIC: dict[str, str] = {
    "Reconnaissance":       "FTA001",
    "Resource Development": "FTA002",
    "Initial Access":       "FTA003",
    "Trust Abuse":          "FTA003",   # closest: gaining trust = initial access
    "End-user Interaction": "FTA003",   # social engineering = initial access vector
    "Credential Access":    "FTA003",   # credential theft = initial access
    "Account Access":       "FTA003",   # account access = initial access
    "Execution":            "FTA004",
    "Defence Evasion":      "FTA005",
    "Defense Evasion":      "FTA005",
    "Perform Fraud":        "FTA007",
    "Monetization":         "FTA010",
    "Laundering":           "FTA010",
}

# Fraud-type keyword -> FT3 technique search terms
# These are expanded keyword sets for fuzzy matching against technique
# names and descriptions.
FRAUD_TYPE_KEYWORDS: dict[str, list[str]] = {
    "account-takeover": [
        "account takeover", "credential", "password", "login",
        "session", "exposed credential", "password reset",
    ],
    "vishing": [
        "phishing", "social engineering", "phone", "voice",
        "impersonat",
    ],
    "wire-fraud": [
        "wire", "transfer", "payment", "transaction",
        "fraudulent transaction",
    ],
    "malvertising": [
        "malvertising", "ad fraud", "advertising",
    ],
    "BEC": [
        "business email", "email compromise", "email account",
        "spearphishing", "impersonat",
    ],
    "business-email-compromise": [
        "business email", "email compromise", "email account",
        "spearphishing", "impersonat",
    ],
    "invoice-fraud": [
        "invoice", "payment", "billing", "falsifying",
    ],
    "payment-diversion": [
        "payment", "diversion", "redirect", "wire", "transfer",
    ],
    "synthetic-identity": [
        "synthetic", "identity", "fake", "fabricat", "falsifying",
        "identity document", "establish account",
    ],
    "new-account-fraud": [
        "new account", "account open", "establish account",
        "fake merchant", "application",
    ],
    "application-fraud": [
        "application", "falsify", "document", "identity",
    ],
    "payroll-diversion": [
        "payroll", "diversion", "direct deposit", "payment",
        "account manipulation",
    ],
    "phishing": [
        "phishing", "social engineering", "credential",
        "spearphishing",
    ],
    "premium-diversion": [
        "premium", "diversion", "insurance", "payment",
        "account manipulation",
    ],
    "impersonation": [
        "impersonat", "identity theft", "fake", "social media attack",
        "website cloning",
    ],
    "deepfake": [
        "deepfake", "synthetic", "impersonat", "identity",
        "falsifying", "voice",
    ],
    "crypto-laundering": [
        "crypto", "laundering", "cash-out", "shell",
        "scheduled transfer", "payout",
    ],
    "check-fraud": [
        "check", "deposit", "document", "falsify",
        "fabricat",
    ],
    "fraudulent-claim": [
        "claim", "fraudulent", "billing", "document",
        "falsify",
    ],
    "disability-fraud": [
        "disability", "insurance", "claim", "fraudulent",
        "document",
    ],
    "provider-fraud": [
        "provider", "billing", "claim", "fraudulent",
        "upcoding",
    ],
    "romance-scam": [
        "romance", "social engineering", "social media",
        "trust", "impersonat",
    ],
    "money-mule": [
        "mule", "money", "laundering", "cash-out",
        "scheduled transfer",
    ],
    "credential-stuffing": [
        "credential", "stuffing", "credential dump",
        "account takeover", "enumeration",
    ],
    "insider-threat": [
        "insider", "internal", "access", "data exfiltration",
        "account manipulation", "cross account",
    ],
    "collusion": [
        "collusion", "insider", "internal", "account manipulation",
    ],
    "data-theft": [
        "data", "exfiltration", "collection", "theft",
    ],
    "identity-theft": [
        "identity theft", "identity", "falsifying identity",
        "document", "credential",
    ],
    "advance-fee-fraud": [
        "advance fee", "fee", "payment", "social engineering",
    ],
    "first-party-fraud": [
        "first party", "bust-out", "churning", "dispute",
        "refund", "policy abuse",
    ],
    "bust-out": [
        "bust-out", "bust out", "churning", "dispute",
        "credit", "refund",
    ],
    "investment-scam": [
        "investment", "scam", "social engineering",
        "fraudulent purchase", "wire",
    ],
    "social-engineering": [
        "social engineering", "phishing", "impersonat",
        "trust", "spearphishing",
    ],
    "authorized-push-payment": [
        "authorized push", "payment", "wire", "transfer",
        "social engineering",
    ],
    "documentary-fraud": [
        "document", "falsify", "identity document",
        "fake", "fabricat",
    ],
    "loan-fraud": [
        "loan", "application", "falsify", "document",
        "identity",
    ],
    "vendor-impersonation": [
        "vendor", "impersonat", "supply chain",
        "business email", "invoice",
    ],
    "healthcare-fraud": [
        "healthcare", "billing", "claim", "falsify",
        "provider", "upcoding",
    ],
    "phantom-billing": [
        "phantom", "billing", "claim", "fraudulent",
        "falsify",
    ],
    "upcoding": [
        "upcoding", "billing", "claim", "fraudulent",
    ],
    "benefit-fraud": [
        "benefit", "government", "claim", "identity",
        "fraudulent",
    ],
    "tax-fraud": [
        "tax", "fraudulent", "identity", "document",
        "falsify",
    ],
    "malware": [
        "malware", "trojan", "execution", "hijack",
        "resource hijacking",
    ],
    "unauthorized-transaction": [
        "unauthorized", "transaction", "fraudulent transaction",
        "account takeover",
    ],
}


# ---------------------------------------------------------------------------
# FT3 data loading
# ---------------------------------------------------------------------------

def load_ft3_tactics(path: Path) -> dict[str, dict]:
    """Load FT3 tactics JSON, keyed by tactic ID (e.g. FTA001)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return {t["ID"]: t for t in data}


def load_ft3_techniques(path: Path) -> list[dict]:
    """Load FT3 techniques JSON."""
    return json.loads(path.read_text(encoding="utf-8"))


def build_tactic_name_to_id(tactics: dict[str, dict]) -> dict[str, str]:
    """Build a mapping from tactic name -> tactic ID."""
    return {v["name"]: k for k, v in tactics.items()}


# ---------------------------------------------------------------------------
# Frontmatter parsing (reuse FLAME convention)
# ---------------------------------------------------------------------------

FRONTMATTER_PATTERN = re.compile(
    r"```ya?ml\s*\n---\s*\n(.*?)\n---\s*\n```",
    re.DOTALL,
)


def extract_frontmatter_raw(filepath: Path) -> tuple[dict | None, str]:
    """Extract YAML frontmatter dict and the raw YAML string."""
    try:
        import yaml
    except ImportError:
        print("ERROR: pyyaml is required. Install with: pip install pyyaml",
              file=sys.stderr)
        sys.exit(1)

    text = filepath.read_text(encoding="utf-8")
    match = FRONTMATTER_PATTERN.search(text)
    if not match:
        return None, ""
    raw_yaml = match.group(1)
    try:
        data = yaml.safe_load(raw_yaml)
    except Exception as e:
        log.error("YAML parse error in %s: %s", filepath, e)
        return None, raw_yaml
    if not isinstance(data, dict):
        return None, raw_yaml
    return data, raw_yaml


# ---------------------------------------------------------------------------
# Mapping logic
# ---------------------------------------------------------------------------

def map_cfpf_to_tactics(cfpf_phases: list[str]) -> set[str]:
    """Signal 1: Map CFPF phases to FT3 tactic IDs."""
    result: set[str] = set()
    for phase in cfpf_phases:
        phase_key = phase.strip().upper()
        if phase_key in CFPF_TO_FT3_TACTICS:
            result.update(CFPF_TO_FT3_TACTICS[phase_key])
    return result


def map_groupib_to_tactics(groupib_stages: list[str]) -> set[str]:
    """Signal 2: Map Group-IB stages to FT3 tactic IDs."""
    result: set[str] = set()
    for stage in groupib_stages:
        stage_clean = stage.strip()
        if stage_clean in GROUPIB_TO_FT3_TACTIC:
            result.update([GROUPIB_TO_FT3_TACTIC[stage_clean]])
    return result


def map_fraud_types_to_techniques(
    fraud_types: list[str],
    techniques: list[dict],
) -> list[tuple[str, str, float]]:
    """Signal 3: Match fraud_types keywords against FT3 technique names/descriptions.

    Returns list of (technique_id, technique_name, score) tuples,
    sorted by score descending. Only parent techniques and techniques
    with score > 0 are returned.
    """
    # Collect all search terms for this TP's fraud types
    all_terms: list[str] = []
    for ft in fraud_types:
        ft_key = ft.strip().lower()
        if ft_key in FRAUD_TYPE_KEYWORDS:
            all_terms.extend(FRAUD_TYPE_KEYWORDS[ft_key])
        else:
            # Fallback: use the fraud type itself as a search term
            all_terms.append(ft_key.replace("-", " "))

    if not all_terms:
        return []

    scored: list[tuple[str, str, float]] = []
    for tech in techniques:
        tech_id = tech["id"]
        tech_name = tech.get("name", "").lower()
        tech_desc = tech.get("description", "").lower()
        searchable = tech_name + " " + tech_desc

        score = 0.0
        matched_terms: set[str] = set()
        for term in all_terms:
            term_lower = term.lower()
            if term_lower in matched_terms:
                continue
            # Name match is worth more than description match
            if term_lower in tech_name:
                score += 3.0
                matched_terms.add(term_lower)
            elif term_lower in searchable:
                score += 1.0
                matched_terms.add(term_lower)

        if score > 0:
            scored.append((tech_id, tech["name"], score))

    scored.sort(key=lambda x: x[2], reverse=True)
    return scored


def determine_confidence(
    cfpf_tactics: set[str],
    groupib_tactics: set[str],
    technique_matches: list[tuple[str, str, float]],
) -> str:
    """Determine mapping confidence based on signal agreement.

    high:   all 3 signals contribute
    medium: 2 signals contribute
    low:    only 1 signal contributes
    """
    signals_active = 0
    if cfpf_tactics:
        signals_active += 1
    if groupib_tactics:
        signals_active += 1
    if technique_matches:
        signals_active += 1

    if signals_active >= 3:
        return "high"
    elif signals_active >= 2:
        return "medium"
    else:
        return "low"


def generate_notes(
    tp_id: str,
    cfpf_tactics: set[str],
    groupib_tactics: set[str],
    combined_tactics: list[str],
    top_techniques: list[tuple[str, str, float]],
    fraud_types: list[str],
) -> str:
    """Generate human-readable mapping notes."""
    parts: list[str] = []

    # Tactic source breakdown
    both = cfpf_tactics & groupib_tactics
    cfpf_only = cfpf_tactics - groupib_tactics
    gib_only = groupib_tactics - cfpf_tactics

    if both:
        parts.append(
            f"Tactics {', '.join(sorted(both))} confirmed by both "
            f"CFPF and Group-IB signals"
        )
    if cfpf_only:
        parts.append(
            f"Tactics {', '.join(sorted(cfpf_only))} from CFPF phases only"
        )
    if gib_only:
        parts.append(
            f"Tactics {', '.join(sorted(gib_only))} from Group-IB stages only"
        )

    # Technique summary
    if top_techniques:
        top3 = top_techniques[:3]
        tech_summary = ", ".join(
            f"{tid} ({tname}, score={score:.0f})"
            for tid, tname, score in top3
        )
        parts.append(f"Top technique matches: {tech_summary}")

    # Fraud type context
    if fraud_types:
        parts.append(f"Fraud types: {', '.join(fraud_types)}")

    return "; ".join(parts)


def map_single_tp(
    meta: dict,
    techniques: list[dict],
    tactic_name_to_id: dict[str, str],
) -> dict:
    """Map a single threat path to FT3 suggestions."""
    tp_id = meta.get("id", "unknown")
    cfpf_phases = meta.get("cfpf_phases", [])
    groupib_stages = meta.get("groupib_stages", [])
    fraud_types = meta.get("fraud_types", [])

    # Normalize cfpf_phases (can be list of strings or YAML flow format)
    if isinstance(cfpf_phases, list):
        cfpf_phases = [str(p) for p in cfpf_phases]
    else:
        cfpf_phases = []

    if isinstance(groupib_stages, list):
        groupib_stages = [str(s) for s in groupib_stages]
    else:
        groupib_stages = []

    if isinstance(fraud_types, list):
        fraud_types = [str(f) for f in fraud_types]
    else:
        fraud_types = []

    # Signal 1: CFPF -> tactics
    cfpf_tactics = map_cfpf_to_tactics(cfpf_phases)

    # Signal 2: Group-IB -> tactics
    groupib_tactics = map_groupib_to_tactics(groupib_stages)

    # Combine tactic suggestions (union, sorted)
    combined_tactics_set = cfpf_tactics | groupib_tactics
    combined_tactics = sorted(combined_tactics_set)

    # Signal 3: Fraud type -> techniques
    technique_matches = map_fraud_types_to_techniques(fraud_types, techniques)

    # Filter techniques: only include parent techniques (no sub-techniques)
    # unless the sub-technique has a very high score
    top_techniques: list[tuple[str, str, float]] = []
    seen_parents: set[str] = set()
    for tid, tname, score in technique_matches:
        is_sub = "." in tid
        parent_id = tid.split(".")[0] if is_sub else tid

        if is_sub:
            # Only include sub-technique if parent not already added
            # and score is significant
            if parent_id not in seen_parents and score >= 4.0:
                top_techniques.append((tid, tname, score))
                seen_parents.add(parent_id)
        else:
            if parent_id not in seen_parents:
                top_techniques.append((tid, tname, score))
                seen_parents.add(parent_id)

        # Cap at 10 techniques per TP
        if len(top_techniques) >= 10:
            break

    # Add technique-implied tactics
    technique_tactic_set: set[str] = set()
    for tid, tname, score in top_techniques:
        # Look up the technique's tactic
        for tech in techniques:
            if tech["id"] == tid:
                tactic_name = tech.get("tactics", "")
                if tactic_name in tactic_name_to_id:
                    technique_tactic_set.add(tactic_name_to_id[tactic_name])
                break

    # Merge technique-implied tactics (but don't let them dominate)
    all_tactics = sorted(combined_tactics_set | technique_tactic_set)

    confidence = determine_confidence(
        cfpf_tactics, groupib_tactics, top_techniques,
    )

    notes = generate_notes(
        tp_id, cfpf_tactics, groupib_tactics, all_tactics,
        top_techniques, fraud_types,
    )

    return {
        "suggested_ft3_tactics": all_tactics,
        "suggested_ft3_techniques": [t[0] for t in top_techniques],
        "confidence": confidence,
        "notes": notes,
        # Store detailed breakdown for review
        "_detail": {
            "cfpf_tactics": sorted(cfpf_tactics),
            "groupib_tactics": sorted(groupib_tactics),
            "technique_implied_tactics": sorted(technique_tactic_set),
            "technique_scores": [
                {"id": t[0], "name": t[1], "score": t[2]}
                for t in top_techniques
            ],
        },
    }


# ---------------------------------------------------------------------------
# Apply mode — update YAML frontmatter
# ---------------------------------------------------------------------------

def apply_ft3_tactics(filepath: Path, tactic_ids: list[str]) -> bool:
    """Update the ft3_tactics field in a threat path's YAML frontmatter.

    Uses regex replacement of just the ft3_tactics line to avoid
    corrupting other YAML fields.
    """
    text = filepath.read_text(encoding="utf-8")

    # Build the replacement YAML value
    if tactic_ids:
        # Format as YAML flow sequence on one line
        items = ", ".join(f'"{tid}"' for tid in tactic_ids)
        replacement = f"ft3_tactics: [{items}]"
    else:
        replacement = "ft3_tactics: []"

    # Match the existing ft3_tactics line (handles [] or multi-line)
    # Pattern 1: ft3_tactics: [] with optional trailing comment
    pattern_inline = re.compile(
        r"^(ft3_tactics:\s*\[.*?\])(\s*#.*)?$",
        re.MULTILINE,
    )
    # Pattern 2: ft3_tactics: followed by YAML list items
    pattern_block = re.compile(
        r"^ft3_tactics:\s*\n((?:\s+-\s+.*\n)*)",
        re.MULTILINE,
    )

    match_inline = pattern_inline.search(text)
    match_block = pattern_block.search(text)

    if match_inline:
        # Preserve any trailing comment
        comment = match_inline.group(2) or ""
        new_text = (
            text[:match_inline.start()]
            + replacement
            + comment
            + text[match_inline.end():]
        )
    elif match_block:
        new_text = (
            text[:match_block.start()]
            + replacement + "\n"
            + text[match_block.end():]
        )
    else:
        log.warning("Could not find ft3_tactics field in %s", filepath)
        return False

    filepath.write_text(new_text, encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FT3 Auto-Mapper for FLAME Threat Paths",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Root directory of the FLAME repository",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply suggested mappings to frontmatter YAML (default: dry-run)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON path (default: <root>/ft3_mapping_suggestions.json)",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    output_path = args.output or (root / "ft3_mapping_suggestions.json")

    log.info("FT3 Auto-Mapper for FLAME Threat Paths")
    log.info("Root: %s", root)
    log.info("Mode: %s", "APPLY" if args.apply else "dry-run")

    # Load FT3 data
    tactics_path = root / "data" / "ft3" / "FT3_Tactics.json"
    techniques_path = root / "data" / "ft3" / "FT3_Techniques.json"

    if not tactics_path.exists():
        log.error("FT3 Tactics JSON not found: %s", tactics_path)
        sys.exit(1)
    if not techniques_path.exists():
        log.error("FT3 Techniques JSON not found: %s", techniques_path)
        sys.exit(1)

    tactics = load_ft3_tactics(tactics_path)
    techniques = load_ft3_techniques(techniques_path)
    tactic_name_to_id = build_tactic_name_to_id(tactics)

    log.info("Loaded %d tactics, %d techniques", len(tactics), len(techniques))

    # Note: "Discovery & Profiling" appears in technique tactic names
    # but is not in the FT3 Tactics JSON. We'll treat it as unmapped.
    extra_tactic_names = set()
    for tech in techniques:
        tname = tech.get("tactics", "")
        if tname and tname not in tactic_name_to_id:
            extra_tactic_names.add(tname)
    if extra_tactic_names:
        log.warning(
            "Technique tactic names not in Tactics JSON: %s",
            extra_tactic_names,
        )

    # Find threat path files
    tp_dir = root / "ThreatPaths"
    tp_files = sorted(tp_dir.glob("TP-*.md"))
    log.info("Found %d threat path files", len(tp_files))

    if not tp_files:
        log.error("No threat path files found in %s", tp_dir)
        sys.exit(1)

    # Process each threat path
    results: dict[str, dict] = {}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}

    for filepath in tp_files:
        meta, raw_yaml = extract_frontmatter_raw(filepath)
        if meta is None:
            log.warning("Skipping %s: no valid frontmatter", filepath.name)
            continue

        tp_id = meta.get("id", filepath.stem)
        mapping = map_single_tp(meta, techniques, tactic_name_to_id)
        results[tp_id] = mapping
        confidence_counts[mapping["confidence"]] += 1

        # Print summary
        tactics_str = ", ".join(mapping["suggested_ft3_tactics"])
        techs_str = ", ".join(mapping["suggested_ft3_techniques"][:5])
        log.info(
            "  %s [%s]: tactics=[%s] techniques=[%s%s]",
            tp_id,
            mapping["confidence"],
            tactics_str,
            techs_str,
            "..." if len(mapping["suggested_ft3_techniques"]) > 5 else "",
        )

    # Write output JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("Wrote mapping suggestions to %s", output_path)

    # Summary
    log.info("---")
    log.info("Mapping summary:")
    log.info("  Total TPs: %d", len(results))
    log.info("  High confidence:   %d", confidence_counts["high"])
    log.info("  Medium confidence: %d", confidence_counts["medium"])
    log.info("  Low confidence:    %d", confidence_counts["low"])

    medium_or_high = confidence_counts["high"] + confidence_counts["medium"]
    log.info(
        "  Medium+High: %d / %d (target: >= 18)",
        medium_or_high,
        len(results),
    )

    if medium_or_high < 18:
        log.warning(
            "Below target: only %d of %d TPs have medium/high confidence",
            medium_or_high,
            len(results),
        )

    # Apply mode
    if args.apply:
        log.info("---")
        log.info("Applying mappings to frontmatter...")
        applied = 0
        for filepath in tp_files:
            meta, _ = extract_frontmatter_raw(filepath)
            if meta is None:
                continue
            tp_id = meta.get("id", filepath.stem)
            if tp_id not in results:
                continue
            tactic_ids = results[tp_id]["suggested_ft3_tactics"]
            if apply_ft3_tactics(filepath, tactic_ids):
                log.info("  Applied to %s: %s", tp_id, tactic_ids)
                applied += 1
            else:
                log.warning("  FAILED to apply to %s", tp_id)
        log.info("Applied mappings to %d files", applied)

    return 0


if __name__ == "__main__":
    sys.exit(main())
