"""
sec.py — SEC EDGAR RSS/Atom feed source.

Fetches SEC litigation releases and administrative proceedings via RSS
and normalises each entry into a ``RegulatoryAlert``.
"""

import hashlib
import logging
from typing import List

import feedparser

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class SECSource(RegulatorySource):
    """Securities and Exchange Commission — EDGAR RSS feed."""

    name = "sec"

    def fetch(self):
        """Parse the SEC RSS feed and return the feedparser result."""
        url = self.config.get("feed_url", self.config.get("url", ""))
        return feedparser.parse(url)

    def parse(self, raw) -> List[RegulatoryAlert]:
        """Parse feedparser result into a list of RegulatoryAlert objects."""
        alerts: List[RegulatoryAlert] = []

        for entry in raw.entries:
            entry_id = getattr(entry, "id", "")
            title = getattr(entry, "title", "")
            published = getattr(entry, "published", "")
            link = getattr(entry, "link", "")
            summary = getattr(entry, "summary", "")

            # Determine category from title
            if "administrative" in title.lower():
                category = "Administrative Proceeding"
            else:
                category = "Litigation Release"

            tp_ids = self.map_category_to_tps(category)
            severity = "high" if tp_ids else "medium"

            digest = hashlib.sha256(entry_id.encode()).hexdigest()[:8]
            alert_id = f"sec-{digest}"

            alerts.append(
                RegulatoryAlert(
                    source=self.name,
                    alert_id=alert_id,
                    title=title,
                    date=published,
                    category=category,
                    mapped_tp_ids=tp_ids,
                    url=link,
                    severity=severity,
                    summary=summary,
                )
            )

        return alerts
