#!/usr/bin/env python3
"""
build_database.py - FLAME Database Builder

Parses markdown threat path files, extracts YAML frontmatter,
builds a SQLite index database and exports a JSON data file
for the static frontend.

Usage:
    python scripts/build_database.py [--root /path/to/flame-fraud]

The script scans ThreatPaths/, Baselines/, and DetectionLogic/
directories for markdown files, parses their YAML frontmatter
(code-fenced blocks), and produces:
    - database/flame.db    (SQLite index)
    - database/flame-data.json (flat JSON for frontend)
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
log = logging.getLogger("build_database")

# ---------------------------------------------------------------------------
# Frontmatter extraction
# ---------------------------------------------------------------------------

# Matches code-fenced YAML blocks: ```yaml ... ``` with --- delimiters inside
FRONTMATTER_PATTERN = re.compile(
    r"```ya?ml\s*\n---\s*\n(.*?)\n---\s*\n```",
    re.DOTALL
)


def extract_frontmatter(filepath: Path) -> dict | None:
    """Extract YAML frontmatter from a markdown file.

    Supports the FLAME convention where frontmatter is wrapped in
    a code-fenced yaml block with --- delimiters.
    """
    text = filepath.read_text(encoding="utf-8")
    match = FRONTMATTER_PATTERN.search(text)
    if not match:
        log.warning("No frontmatter found in %s", filepath)
        return None

    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as e:
        log.error("YAML parse error in %s: %s", filepath, e)
        return None

    if not isinstance(data, dict):
        log.warning("Frontmatter in %s is not a mapping", filepath)
        return None

    return data


def extract_body(filepath: Path) -> str:
    """Extract the body content after the frontmatter block."""
    text = filepath.read_text(encoding="utf-8")
    match = FRONTMATTER_PATTERN.search(text)
    if match:
        # Everything after the closing ``` of the frontmatter
        end = text.find("```", match.end() - 3) + 3
        body = text[end:].strip()
    else:
        body = text.strip()
    return body


def extract_summary(body: str) -> str:
    """Extract the Summary section content from the body."""
    lines = body.split("\n")
    capture = False
    summary_lines = []
    for line in lines:
        if re.match(r"^##\s+Summary", line):
            capture = True
            continue
        if capture:
            if re.match(r"^##\s+", line):
                break
            summary_lines.append(line)
    return "\n".join(summary_lines).strip()


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    date TEXT,
    author TEXT,
    source TEXT,
    tlp TEXT DEFAULT 'WHITE',
    summary TEXT,
    body TEXT,
    file_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS submission_sectors (
    submission_id TEXT NOT NULL,
    sector TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_fraud_types (
    submission_id TEXT NOT NULL,
    fraud_type TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_tags (
    submission_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_cfpf_phases (
    submission_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_mitre_attack (
    submission_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_ft3_tactics (
    submission_id TEXT NOT NULL,
    tactic_id TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_mitre_f3 (
    submission_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS submission_groupib_stages (
    submission_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

CREATE TABLE IF NOT EXISTS techniques (
    id TEXT PRIMARY KEY,
    phase TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    indicators TEXT,
    mitre_attack TEXT,
    fraud_types TEXT
);

CREATE INDEX IF NOT EXISTS idx_sectors ON submission_sectors(sector);
CREATE INDEX IF NOT EXISTS idx_fraud_types ON submission_fraud_types(fraud_type);
CREATE INDEX IF NOT EXISTS idx_cfpf ON submission_cfpf_phases(phase);
CREATE INDEX IF NOT EXISTS idx_tags ON submission_tags(tag);
"""


def init_database(db_path: Path) -> sqlite3.Connection:
    """Create or recreate the database with the schema."""
    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_submission(conn: sqlite3.Connection, meta: dict, body: str, summary: str, filepath: Path):
    """Insert a single submission and its related data into the database."""
    sub_id = meta.get("id", "")
    if not sub_id:
        log.warning("Skipping %s: no 'id' in frontmatter", filepath)
        return

    conn.execute(
        """INSERT OR REPLACE INTO submissions
           (id, title, category, date, author, source, tlp, summary, body, file_path)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            sub_id,
            meta.get("title", ""),
            meta.get("category", ""),
            str(meta.get("date", "")),
            meta.get("author", ""),
            meta.get("source", ""),
            meta.get("tlp", "WHITE"),
            summary,
            body,
            str(filepath),
        )
    )

    # Multi-value fields
    _insert_multi(conn, "submission_sectors", sub_id, "sector", meta.get("sector", []))
    _insert_multi(conn, "submission_fraud_types", sub_id, "fraud_type", meta.get("fraud_types", []))
    _insert_multi(conn, "submission_tags", sub_id, "tag", meta.get("tags", []))
    _insert_multi(conn, "submission_cfpf_phases", sub_id, "phase", meta.get("cfpf_phases", []))
    _insert_multi(conn, "submission_mitre_attack", sub_id, "technique_id", meta.get("mitre_attack", []))
    _insert_multi(conn, "submission_ft3_tactics", sub_id, "tactic_id", meta.get("ft3_tactics", []))
    _insert_multi(conn, "submission_mitre_f3", sub_id, "technique_id", meta.get("mitre_f3", []))
    _insert_multi(conn, "submission_groupib_stages", sub_id, "stage", meta.get("groupib_stages", []))


def _insert_multi(conn: sqlite3.Connection, table: str, sub_id: str, col: str, values):
    """Insert multi-value list entries for a submission."""
    if not values or not isinstance(values, list):
        return
    for val in values:
        if val:  # skip empty strings/None
            conn.execute(
                f"INSERT INTO {table} (submission_id, {col}) VALUES (?, ?)",
                (sub_id, str(val))
            )


def load_techniques(conn: sqlite3.Connection, techniques_path: Path):
    """Load CFPF techniques from cfpf_techniques.json."""
    if not techniques_path.exists():
        log.warning("cfpf_techniques.json not found at %s", techniques_path)
        return 0

    data = json.loads(techniques_path.read_text(encoding="utf-8"))
    count = 0
    phases = data.get("phases", {})
    for phase_id, phase_data in phases.items():
        for tech in phase_data.get("techniques", []):
            conn.execute(
                """INSERT OR REPLACE INTO techniques
                   (id, phase, name, description, indicators, mitre_attack, fraud_types)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    tech["id"],
                    phase_id,
                    tech["name"],
                    tech.get("description", ""),
                    json.dumps(tech.get("indicators", [])),
                    json.dumps(tech.get("mitre_attack", [])),
                    json.dumps(tech.get("fraud_types", [])),
                )
            )
            count += 1
    return count


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(conn: sqlite3.Connection, output_path: Path):
    """Export the database to a flat JSON array for the frontend."""
    cursor = conn.execute("SELECT * FROM submissions ORDER BY id")
    columns = [desc[0] for desc in cursor.description]
    submissions = []

    for row in cursor.fetchall():
        entry = dict(zip(columns, row))
        sub_id = entry["id"]

        # Attach multi-value lists
        entry["sectors"] = _fetch_list(conn, "submission_sectors", "sector", sub_id)
        entry["fraud_types"] = _fetch_list(conn, "submission_fraud_types", "fraud_type", sub_id)
        entry["tags"] = _fetch_list(conn, "submission_tags", "tag", sub_id)
        entry["cfpf_phases"] = _fetch_list(conn, "submission_cfpf_phases", "phase", sub_id)
        entry["mitre_attack"] = _fetch_list(conn, "submission_mitre_attack", "technique_id", sub_id)
        entry["ft3_tactics"] = _fetch_list(conn, "submission_ft3_tactics", "tactic_id", sub_id)
        entry["mitre_f3"] = _fetch_list(conn, "submission_mitre_f3", "technique_id", sub_id)
        entry["groupib_stages"] = _fetch_list(conn, "submission_groupib_stages", "stage", sub_id)

        # Remove full body from JSON export (too large for frontend)
        entry.pop("body", None)

        submissions.append(entry)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(submissions, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return len(submissions)


def _fetch_list(conn: sqlite3.Connection, table: str, col: str, sub_id: str) -> list:
    """Fetch a list of values from a multi-value table."""
    rows = conn.execute(
        f"SELECT {col} FROM {table} WHERE submission_id = ? ORDER BY rowid",
        (sub_id,)
    ).fetchall()
    return [r[0] for r in rows]


def _build_full_entry(conn: sqlite3.Connection, entry: dict) -> dict:
    """Attach all multi-value lists to a submission entry dict."""
    sub_id = entry["id"]
    entry["sectors"] = _fetch_list(conn, "submission_sectors", "sector", sub_id)
    entry["fraud_types"] = _fetch_list(conn, "submission_fraud_types", "fraud_type", sub_id)
    entry["tags"] = _fetch_list(conn, "submission_tags", "tag", sub_id)
    entry["cfpf_phases"] = _fetch_list(conn, "submission_cfpf_phases", "phase", sub_id)
    entry["mitre_attack"] = _fetch_list(conn, "submission_mitre_attack", "technique_id", sub_id)
    entry["ft3_tactics"] = _fetch_list(conn, "submission_ft3_tactics", "tactic_id", sub_id)
    entry["mitre_f3"] = _fetch_list(conn, "submission_mitre_f3", "technique_id", sub_id)
    entry["groupib_stages"] = _fetch_list(conn, "submission_groupib_stages", "stage", sub_id)
    return entry


def export_index_json(conn: sqlite3.Connection, output_path: Path):
    """Export metadata-only index for fast frontend initial load."""
    cursor = conn.execute("SELECT * FROM submissions ORDER BY id")
    columns = [desc[0] for desc in cursor.description]
    index_entries = []

    for row in cursor.fetchall():
        entry = dict(zip(columns, row))
        entry = _build_full_entry(conn, entry)

        # Truncate summary for index (first 200 chars)
        full_summary = entry.get("summary", "")
        entry["summary"] = full_summary[:200] + ("..." if len(full_summary) > 200 else "")

        # Remove body — not needed for browse view
        entry.pop("body", None)
        # Remove file_path — internal only
        entry.pop("file_path", None)

        index_entries.append(entry)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(index_entries, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return len(index_entries)


def export_content_files(conn: sqlite3.Connection, output_dir: Path):
    """Export individual TP-XXXX.json files for lazy loading."""
    cursor = conn.execute("SELECT * FROM submissions ORDER BY id")
    columns = [desc[0] for desc in cursor.description]
    count = 0

    output_dir.mkdir(parents=True, exist_ok=True)

    for row in cursor.fetchall():
        entry = dict(zip(columns, row))
        entry = _build_full_entry(conn, entry)

        # Remove file_path — internal only
        entry.pop("file_path", None)

        sub_id = entry["id"]
        filepath = output_dir / f"{sub_id}.json"
        filepath.write_text(
            json.dumps(entry, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        count += 1

    return count


def export_stats_json(conn: sqlite3.Connection, output_path: Path):
    """Export pre-computed aggregate statistics."""
    total = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]

    fraud_types = conn.execute(
        "SELECT DISTINCT fraud_type FROM submission_fraud_types ORDER BY fraud_type"
    ).fetchall()
    fraud_type_list = [r[0] for r in fraud_types]

    sectors = conn.execute(
        "SELECT DISTINCT sector FROM submission_sectors ORDER BY sector"
    ).fetchall()
    sector_list = [r[0] for r in sectors]

    tags = conn.execute(
        "SELECT tag, COUNT(*) as cnt FROM submission_tags GROUP BY tag ORDER BY cnt DESC"
    ).fetchall()
    top_tags = [{"tag": r[0], "count": r[1]} for r in tags[:20]]

    # CFPF phase coverage: count of TPs per phase
    phases = conn.execute(
        "SELECT phase, COUNT(*) as cnt FROM submission_cfpf_phases GROUP BY phase ORDER BY phase"
    ).fetchall()
    phase_coverage = {r[0]: r[1] for r in phases}

    # Coverage matrix: fraud_type × phase
    coverage_matrix = []
    for ft in fraud_type_list:
        # Find all TPs with this fraud type
        tp_rows = conn.execute(
            "SELECT submission_id FROM submission_fraud_types WHERE fraud_type = ?",
            (ft,)
        ).fetchall()
        tp_ids = [r[0] for r in tp_rows]
        phases_for_ft = {}
        for tp_id in tp_ids:
            tp_phases = conn.execute(
                "SELECT phase FROM submission_cfpf_phases WHERE submission_id = ?",
                (tp_id,)
            ).fetchall()
            for p in tp_phases:
                phases_for_ft[p[0]] = phases_for_ft.get(p[0], 0) + 1
        coverage_matrix.append({
            "fraud_type": ft,
            "phases": phases_for_ft,
            "total_tps": len(tp_ids)
        })

    stats = {
        "total": total,
        "fraudTypes": len(fraud_type_list),
        "fraudTypeList": fraud_type_list,
        "sectors": len(sector_list),
        "sectorList": sector_list,
        "phaseCoverage": phase_coverage,
        "topTags": top_tags,
        "coverageMatrix": coverage_matrix,
        "generatedAt": str(Path(__file__).stat().st_mtime),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(stats, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def find_markdown_files(root: Path) -> list[Path]:
    """Find all markdown files in submission directories."""
    dirs = ["ThreatPaths", "Baselines", "DetectionLogic"]
    files = []
    for d in dirs:
        dir_path = root / d
        if dir_path.exists():
            for f in sorted(dir_path.glob("*.md")):
                # Skip index files
                if f.name.upper() == "INDEX.MD":
                    continue
                files.append(f)
    return files


def main():
    parser = argparse.ArgumentParser(description="FLAME Database Builder")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Root directory of the FLAME repository"
    )
    args = parser.parse_args()
    root = args.root.resolve()

    log.info("FLAME Database Builder")
    log.info("Root: %s", root)

    # Find submission files
    md_files = find_markdown_files(root)
    log.info("Found %d markdown files", len(md_files))

    if not md_files:
        log.error("No markdown files found. Check directory structure.")
        sys.exit(1)

    # Initialize database
    db_path = root / "database" / "flame.db"
    conn = init_database(db_path)
    log.info("Database initialized: %s", db_path)

    # Load techniques catalog
    techniques_path = root / "cfpf_techniques.json"
    tech_count = load_techniques(conn, techniques_path)
    log.info("Loaded %d CFPF techniques", tech_count)

    # Process each submission file
    loaded = 0
    errors = 0
    for filepath in md_files:
        meta = extract_frontmatter(filepath)
        if meta is None:
            errors += 1
            continue

        body = extract_body(filepath)
        summary = extract_summary(body)
        load_submission(conn, meta, body, summary, filepath)
        loaded += 1
        log.info("  Loaded: %s (%s)", meta.get("id", "?"), meta.get("title", "?"))

    conn.commit()

    # Export JSON (legacy — backward compatibility)
    json_path = root / "database" / "flame-data.json"
    count = export_json(conn, json_path)
    log.info("Exported %d submissions to %s (legacy)", count, json_path)

    # Export v2 data files
    index_path = root / "database" / "flame-index.json"
    idx_count = export_index_json(conn, index_path)
    log.info("Exported %d submissions to %s (index)", idx_count, index_path)

    content_dir = root / "database" / "flame-content"
    ct_count = export_content_files(conn, content_dir)
    log.info("Exported %d content files to %s", ct_count, content_dir)

    stats_path = root / "database" / "flame-stats.json"
    stats = export_stats_json(conn, stats_path)
    log.info("Exported stats to %s (total=%d)", stats_path, stats["total"])

    conn.close()

    # Summary
    log.info("---")
    log.info("Build complete: %d loaded, %d errors, %d techniques", loaded, errors, tech_count)

    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
