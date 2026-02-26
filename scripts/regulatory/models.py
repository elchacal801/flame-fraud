"""
models.py — Data models and config helpers for FLAME regulatory feed ingestion.

Defines the RegulatoryAlert dataclass for normalised alerts from any
regulatory source, plus YAML config loading utilities.
"""

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import List, Union

import yaml


# Column order used for CSV export
CSV_COLUMNS: List[str] = [
    "source",
    "alert_id",
    "title",
    "date",
    "category",
    "mapped_tp_ids",
    "url",
    "severity",
    "summary",
]


@dataclass
class RegulatoryAlert:
    """A single normalised regulatory alert/advisory."""

    source: str
    alert_id: str
    title: str
    date: Union[date, str]
    category: str
    mapped_tp_ids: List[str] = field(default_factory=list)
    url: str = ""
    severity: str = ""
    summary: str = ""

    def to_csv_row(self) -> list:
        """Return a list of values matching CSV_COLUMNS order.

        ``mapped_tp_ids`` is serialized as a ``|``-delimited string so it
        fits in a single CSV cell (e.g. ``TP-0012|TP-0034``).
        """
        return [
            self.source,
            self.alert_id,
            self.title,
            date(self.date.year, self.date.month, self.date.day).isoformat()
            if isinstance(self.date, date)
            else str(self.date),
            self.category,
            "|".join(self.mapped_tp_ids),
            self.url,
            self.severity,
            self.summary,
        ]


def load_source_config(path) -> dict:
    """Load a YAML regulatory-sources config file.

    Parameters
    ----------
    path : str or Path
        Path to the YAML configuration file.

    Returns
    -------
    dict
        Parsed configuration dictionary.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist on disk.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
