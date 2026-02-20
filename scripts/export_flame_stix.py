#!/usr/bin/env python3
"""
export_flame_stix.py — FLAME STIX 2.1 Exporter

Reads threat path content from database/flame-content/TP-XXXX.json and
produces:
  1. database/flame_stix_bundle.json   — STIX 2.1 bundle with attack-patterns
  2. database/flame_detection_rules.json — aggregated detection rules
  3. database/flame-content/TP-XXXX-rules.json — per-TP detection rules

All STIX IDs are deterministic (uuid5) so repeated builds produce identical
output.  The bundle validates against the stix2 Python library before writing.
"""

import json
import re
import uuid
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import stix2
except ImportError:
    print("[!] stix2 library required: pip install stix2>=3.0.0")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # NAMESPACE_DNS

FLAME_IDENTITY_UUID = uuid.uuid5(NAMESPACE, "flame-fraud-project")
FLAME_IDENTITY_ID = f"identity--{FLAME_IDENTITY_UUID}"

TLP_CLEAR = stix2.TLP_WHITE  # stix2 uses TLP_WHITE for TLP:CLEAR
TLP_CLEAR_ID = TLP_CLEAR.id

CFPF_KILL_CHAIN = [
    {"kill_chain_name": "cfpf", "phase_name": "P1-reconnaissance"},
    {"kill_chain_name": "cfpf", "phase_name": "P2-initial-access"},
    {"kill_chain_name": "cfpf", "phase_name": "P3-positioning"},
    {"kill_chain_name": "cfpf", "phase_name": "P4-execution"},
    {"kill_chain_name": "cfpf", "phase_name": "P5-monetization"},
]

PHASE_MAP = {
    "P1": "P1-reconnaissance",
    "P2": "P2-initial-access",
    "P3": "P3-positioning",
    "P4": "P4-execution",
    "P5": "P5-monetization",
}

FLAME_PAGES_BASE = "https://elchacal801.github.io/flame-fraud"

# Paths
CONTENT_DIR = Path("database/flame-content")
INDEX_FILE = Path("database/flame-index.json")
OUTPUT_BUNDLE = Path("database/flame_stix_bundle.json")
OUTPUT_RULES = Path("database/flame_detection_rules.json")

# Detection block regex — matches fenced code blocks with language tags
# Captures: language tag and content
DETECTION_BLOCK_RE = re.compile(
    r"```(spl|sql|yaml|yara|pseudocode|sigma)\s*\n(.*?)```",
    re.DOTALL,
)

# Regex to find TP cross-references in body text
TP_REF_RE = re.compile(r"\bTP-(\d{4})\b")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def deterministic_id(stix_type: str, seed: str) -> str:
    """Generate a deterministic STIX ID from a seed string."""
    return f"{stix_type}--{uuid.uuid5(NAMESPACE, seed)}"


def load_index() -> List[Dict[str, Any]]:
    """Load flame-index.json."""
    if not INDEX_FILE.exists():
        print(f"[!] Index not found: {INDEX_FILE}")
        return []
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_tp_content(tp_id: str) -> Optional[Dict[str, Any]]:
    """Load individual TP-XXXX.json content file."""
    path = CONTENT_DIR / f"{tp_id}.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def map_cfpf_phases(phases: List[str]) -> List[Dict[str, str]]:
    """Map short phase codes (P1, P2...) to STIX kill_chain_phases."""
    result = []
    for p in phases:
        phase_name = PHASE_MAP.get(p)
        if phase_name:
            result.append({
                "kill_chain_name": "cfpf",
                "phase_name": phase_name,
            })
    return result


def build_external_refs(tp: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build external_references for a threat path."""
    refs = [
        {
            "source_name": "FLAME Project",
            "description": f"Threat Path {tp['id']}",
            "url": f"{FLAME_PAGES_BASE}/?tp={tp['id']}",
        }
    ]
    # Add MITRE ATT&CK references
    for tech_id in tp.get("mitre_attack", []):
        refs.append({
            "source_name": "mitre-attack",
            "external_id": tech_id,
            "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
        })
    # Add source reference if available
    source = tp.get("source", "")
    if source and source.startswith("http"):
        refs.append({
            "source_name": "Reference",
            "url": source,
        })
    return refs


# ---------------------------------------------------------------------------
# Detection Rule Extraction
# ---------------------------------------------------------------------------

def extract_detection_section(body: str) -> str:
    """Extract the Detection Approaches section from a TP body."""
    # Find the start of the section
    start_match = re.search(r"^## Detection Approaches", body, re.MULTILINE)
    if not start_match:
        return ""

    # Find the end (next ## header or end of string)
    rest = body[start_match.start():]
    end_match = re.search(r"\n## (?!Detection)", rest)
    if end_match:
        return rest[:end_match.start()]
    return rest


def extract_detection_rules(tp_id: str, body: str) -> List[Dict[str, str]]:
    """Extract fenced code blocks from the Detection Approaches section."""
    detection_section = extract_detection_section(body)
    if not detection_section:
        return []

    rules = []
    for match in DETECTION_BLOCK_RE.finditer(detection_section):
        lang = match.group(1).strip().lower()
        content = match.group(2).strip()

        # Normalize yaml to sigma if content looks like a Sigma rule
        rule_type = lang
        if lang == "yaml" and ("detection:" in content or "logsource:" in content):
            rule_type = "sigma"

        # Try to extract a title from the content or surrounding context
        title = ""
        # Look for a title line before the code block
        block_start = match.start()
        preceding = detection_section[:block_start]
        lines = preceding.rstrip().split("\n")
        for line in reversed(lines[-5:]):
            line = line.strip()
            if line.startswith("**") and line.endswith("**"):
                title = line.strip("*").strip()
                break
            elif line.startswith("### ") or line.startswith("#### "):
                title = line.lstrip("#").strip()
                break

        rules.append({
            "type": rule_type,
            "content": content,
            "title": title or f"{tp_id} detection rule ({rule_type})",
        })

    return rules


def save_tp_rules(tp_id: str, rules: List[Dict[str, str]]) -> None:
    """Save per-TP detection rules file."""
    if not rules:
        return
    output = {"tp_id": tp_id, "rules": rules}
    path = CONTENT_DIR / f"{tp_id}-rules.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"    [{tp_id}] {len(rules)} detection rules -> {path.name}")


# ---------------------------------------------------------------------------
# STIX Object Construction
# ---------------------------------------------------------------------------

def build_identity() -> stix2.Identity:
    """Build the FLAME project identity object."""
    return stix2.Identity(
        id=FLAME_IDENTITY_ID,
        name="FLAME Project",
        identity_class="organization",
        description="Fraud Lifecycle Attack Map & Encyclopedia — open-source "
                    "framework for structured fraud threat intelligence.",
        external_references=[{
            "source_name": "FLAME GitHub",
            "url": "https://github.com/elchacal801/flame-fraud",
        }],
        object_marking_refs=[TLP_CLEAR.id],
        allow_custom=True,
    )


def build_attack_pattern(tp: Dict[str, Any]) -> stix2.AttackPattern:
    """Build a STIX attack-pattern from a FLAME threat path."""
    tp_id = tp["id"]
    phases = map_cfpf_phases(tp.get("cfpf_phases", []))
    ext_refs = build_external_refs(tp)

    return stix2.AttackPattern(
        id=deterministic_id("attack-pattern", f"flame-{tp_id}"),
        created_by_ref=FLAME_IDENTITY_ID,
        name=tp.get("title", tp_id),
        description=tp.get("summary", ""),
        kill_chain_phases=phases if phases else None,
        external_references=ext_refs,
        labels=tp.get("fraud_types", []),
        object_marking_refs=[TLP_CLEAR.id],
        allow_custom=True,
    )


def find_tp_cross_refs(body: str, own_id: str, known_ids: set) -> List[str]:
    """Find cross-references to other TPs in the body text."""
    refs = set()
    for match in TP_REF_RE.finditer(body):
        ref_id = f"TP-{match.group(1)}"
        if ref_id != own_id and ref_id in known_ids:
            refs.add(ref_id)
    return sorted(refs)


def build_relationship(source_id: str, target_id: str,
                       rel_type: str = "related-to") -> stix2.Relationship:
    """Build a STIX relationship between two objects."""
    seed = f"rel-{source_id}-{rel_type}-{target_id}"
    return stix2.Relationship(
        id=deterministic_id("relationship", seed),
        relationship_type=rel_type,
        source_ref=source_id,
        target_ref=target_id,
        created_by_ref=FLAME_IDENTITY_ID,
        object_marking_refs=[TLP_CLEAR.id],
        allow_custom=True,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("[*] FLAME STIX 2.1 Exporter")
    print(f"    Content dir: {CONTENT_DIR}")
    print(f"    Index: {INDEX_FILE}")

    # Load index
    index = load_index()
    if not index:
        print("[!] No threat paths found. Exiting.")
        sys.exit(1)

    print(f"[*] Found {len(index)} threat paths in index.")

    known_tp_ids = {tp["id"] for tp in index}

    # Build STIX objects
    identity = build_identity()
    attack_patterns = {}  # tp_id -> AttackPattern
    all_rules = []        # Aggregated detection rules
    relationships = []

    for tp in index:
        tp_id = tp["id"]

        # Build attack-pattern
        ap = build_attack_pattern(tp)
        attack_patterns[tp_id] = ap
        print(f"    [+] {tp_id}: {tp.get('title', '?')}")

        # Load full content for detection rules and cross-refs
        content = load_tp_content(tp_id)
        body = content.get("body", "") if content else ""

        # Extract detection rules
        rules = extract_detection_rules(tp_id, body)
        if rules:
            save_tp_rules(tp_id, rules)
            for r in rules:
                r["tp_id"] = tp_id
            all_rules.extend(rules)

        # Find cross-references for relationships
        cross_refs = find_tp_cross_refs(body, tp_id, known_tp_ids)
        for ref_id in cross_refs:
            # We'll create these after all APs are built
            relationships.append((tp_id, ref_id))

    # Build relationship objects (deduplicate bidirectional)
    seen_rels = set()
    stix_relationships = []
    for src_id, tgt_id in relationships:
        # Normalize to avoid A->B and B->A duplicates
        pair = tuple(sorted([src_id, tgt_id]))
        if pair in seen_rels:
            continue
        seen_rels.add(pair)

        src_ap = attack_patterns.get(src_id)
        tgt_ap = attack_patterns.get(tgt_id)
        if src_ap and tgt_ap:
            rel = build_relationship(src_ap.id, tgt_ap.id)
            stix_relationships.append(rel)
            print(f"    [~] {src_id} <-> {tgt_id}")

    # Assemble bundle
    all_objects = [identity]
    all_objects.extend(attack_patterns.values())
    all_objects.extend(stix_relationships)

    print(f"\n[*] Bundle summary:")
    print(f"    - Identity: 1")
    print(f"    - Attack patterns: {len(attack_patterns)}")
    print(f"    - Relationships: {len(stix_relationships)}")
    print(f"    - Detection rules: {len(all_rules)}")

    # Build and validate bundle
    bundle = stix2.Bundle(
        objects=all_objects,
        id=deterministic_id("bundle", "flame-stix-bundle"),
        allow_custom=True,
    )

    # Validate by parsing back
    try:
        stix2.parse(bundle.serialize(), allow_custom=True)
        print("[+] STIX validation passed.")
    except Exception as e:
        print(f"[!] STIX validation failed: {e}")
        sys.exit(1)

    # Write STIX bundle
    OUTPUT_BUNDLE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_BUNDLE, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"[+] STIX bundle written to {OUTPUT_BUNDLE}")

    # Write aggregated detection rules
    with open(OUTPUT_RULES, "w", encoding="utf-8") as f:
        json.dump(all_rules, f, indent=2, ensure_ascii=False)
    print(f"[+] Detection rules written to {OUTPUT_RULES} ({len(all_rules)} rules)")

    print("[*] Done.")


if __name__ == "__main__":
    main()
