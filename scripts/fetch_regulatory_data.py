#!/usr/bin/env python3
"""
fetch_regulatory_data.py -- CLI orchestrator for FLAME regulatory feed ingestion.

Loads configuration, instantiates enabled regulatory sources, collects alerts
from each source, and writes the merged results to a CSV file.

Usage examples
--------------
    # Fetch all enabled sources and write to default CSV path
    python scripts/fetch_regulatory_data.py

    # Fetch only CFPB and FinCEN
    python scripts/fetch_regulatory_data.py --sources cfpb,fincen

    # Dry-run: print first 10 alerts without writing to disk
    python scripts/fetch_regulatory_data.py --dry-run

    # Custom output and config paths
    python scripts/fetch_regulatory_data.py --output data/out.csv --config config/my.yaml
"""

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Ensure scripts/ is on sys.path so ``regulatory`` package resolves when run
# as ``python scripts/fetch_regulatory_data.py`` from the repo root.
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from regulatory.models import RegulatoryAlert, CSV_COLUMNS, load_source_config
from regulatory.sources import (
    CFPBSource,
    OCCSource,
    SECSource,
    OFACSource,
    FinCENSource,
    FBIC3Source,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

SOURCE_REGISTRY: Dict[str, type] = {
    "cfpb": CFPBSource,
    "occ": OCCSource,
    "sec": SECSource,
    "ofac": OFACSource,
    "fincen": FinCENSource,
    "fbi_ic3": FBIC3Source,
}

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def collect_alerts(sources: dict) -> List[RegulatoryAlert]:
    """Run all source instances and merge results into a single list.

    Parameters
    ----------
    sources : dict
        Mapping of source name to an instantiated ``RegulatorySource`` object.

    Returns
    -------
    list[RegulatoryAlert]
        Merged alerts from every source.  Sources that fail return empty
        lists (handled internally by ``RegulatorySource.run()``).
    """
    all_alerts: List[RegulatoryAlert] = []
    for name, source in sources.items():
        logger.info("Collecting alerts from %s ...", name)
        alerts = source.run()
        logger.info("  -> %d alert(s) from %s", len(alerts), name)
        all_alerts.extend(alerts)
    return all_alerts


def write_csv(alerts: List[RegulatoryAlert], output_path: Path) -> None:
    """Write alerts to CSV using ``csv.DictWriter`` with ``CSV_COLUMNS``.

    Creates parent directories if they do not exist.  The ``mapped_tp_ids``
    field is serialized as a ``|``-delimited string and the ``date`` field
    is normalized to an ISO-format date string.

    Parameters
    ----------
    alerts : list[RegulatoryAlert]
        Alerts to write.
    output_path : Path
        Destination CSV file path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for alert in alerts:
            row = dict(zip(CSV_COLUMNS, alert.to_csv_row()))
            writer.writerow(row)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _repo_root() -> Path:
    """Return the repository root (parent of the ``scripts/`` directory)."""
    return _SCRIPTS_DIR.parent


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="FLAME regulatory feed ingestion — fetch, parse, and export alerts.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_repo_root() / "data" / "regulatory_alerts.csv",
        help="Output CSV path (default: data/regulatory_alerts.csv relative to repo root).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_repo_root() / "config" / "regulatory_sources.yaml",
        help="YAML config path (default: config/regulatory_sources.yaml relative to repo root).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Parse sources but do not write CSV; print first 10 alerts instead.",
    )
    parser.add_argument(
        "--sources",
        type=str,
        default="",
        help="Comma-separated list of source names to run (default: all enabled).",
    )
    return parser


def main(argv: List[str] | None = None) -> None:
    """Entry point: load config, collect alerts, write CSV (or dry-run).

    Parameters
    ----------
    argv : list[str] or None
        CLI arguments.  ``None`` means use ``sys.argv[1:]``.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # ---- Load config -------------------------------------------------------
    logger.info("Loading config from %s", args.config)
    config = load_source_config(args.config)
    source_configs = config.get("sources", {})

    # ---- Determine which sources to run ------------------------------------
    if args.sources:
        requested = [s.strip() for s in args.sources.split(",") if s.strip()]
    else:
        requested = list(SOURCE_REGISTRY.keys())

    # ---- Instantiate sources -----------------------------------------------
    active_sources: Dict[str, object] = {}
    for name in requested:
        if name not in SOURCE_REGISTRY:
            logger.warning("Unknown source '%s' -- skipping.", name)
            continue
        src_config = source_configs.get(name, {})
        if not src_config.get("enabled", False):
            logger.info("Source '%s' is disabled in config -- skipping.", name)
            continue
        active_sources[name] = SOURCE_REGISTRY[name](src_config)

    if not active_sources:
        logger.warning("No active sources to run. Exiting.")
        return

    # ---- Collect alerts ----------------------------------------------------
    logger.info("Running %d source(s): %s", len(active_sources), ", ".join(active_sources))
    alerts = collect_alerts(active_sources)
    logger.info("Total alerts collected: %d", len(alerts))

    # ---- Output ------------------------------------------------------------
    if args.dry_run:
        print(f"\n=== Dry-run: showing first 10 of {len(alerts)} alert(s) ===\n")
        for alert in alerts[:10]:
            print(
                f"  [{alert.source}] {alert.alert_id} | {alert.title} "
                f"| {alert.date} | {alert.category} | TPs: {alert.mapped_tp_ids}"
            )
        if len(alerts) > 10:
            print(f"\n  ... and {len(alerts) - 10} more alert(s).")
    else:
        write_csv(alerts, args.output)
        logger.info("Wrote %d alert(s) to %s", len(alerts), args.output)


if __name__ == "__main__":
    main()
