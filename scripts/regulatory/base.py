"""
base.py — Abstract base class for FLAME regulatory feed sources.

Each concrete source (FinCEN, CFPB, etc.) subclasses ``RegulatorySource``
and implements ``fetch()`` and ``parse()``.  The concrete ``run()`` method
orchestrates both steps with error handling.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List

from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class RegulatorySource(ABC):
    """Abstract base class for a regulatory alert source.

    Subclasses must set the ``name`` class attribute and implement
    ``fetch()`` and ``parse()``.
    """

    name: str = ""

    def __init__(self, config: dict) -> None:
        """Initialise the source from a per-source config block.

        Parameters
        ----------
        config : dict
            The source-specific section from ``regulatory_sources.yaml``,
            e.g. ``{"enabled": true, "url": "...", "category_mapping": {...}}``.
        """
        self.config = config
        self.enabled: bool = config.get("enabled", False)
        self.category_mapping: Dict[str, List[str]] = config.get("category_mapping", {})

    def map_category_to_tps(self, category: str) -> List[str]:
        """Map a regulatory category string to FLAME TP IDs.

        Returns an empty list when the category has no mapping configured.
        """
        return self.category_mapping.get(category, [])

    @abstractmethod
    def fetch(self) -> str:
        """Fetch raw content from the regulatory source.

        Returns
        -------
        str
            Raw content (HTML, XML, JSON, etc.) to be parsed.
        """

    @abstractmethod
    def parse(self, raw: str) -> List[RegulatoryAlert]:
        """Parse raw content into a list of ``RegulatoryAlert`` objects.

        Parameters
        ----------
        raw : str
            The raw content returned by ``fetch()``.

        Returns
        -------
        list[RegulatoryAlert]
            Parsed alerts.
        """

    def run(self) -> List[RegulatoryAlert]:
        """Execute the full fetch-and-parse pipeline.

        Returns an empty list on any failure and logs the error.
        """
        try:
            raw = self.fetch()
            return self.parse(raw)
        except Exception:
            logger.exception("Error running source %s", self.name)
            return []
