"""
occ.py — OCC Bulletins RSS feed source.

Fetches OCC bulletin/enforcement entries via RSS and normalises each
into a ``RegulatoryAlert``.
"""

import hashlib
import logging
from typing import List

import feedparser

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class OCCSource(RegulatorySource):
    """Office of the Comptroller of the Currency — Bulletins RSS."""

    name = "occ"

    def fetch(self):
        """Parse the OCC RSS feed and return the feedparser result."""
        url = self.config["feed_url"]
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

            # Determine category from tags or title keywords
            tags = getattr(entry, "tags", [])
            if tags:
                category = tags[0].term
            elif "enforcement" in title.lower():
                category = "Enforcement Action"
            else:
                category = "Bulletin"

            tp_ids = self.map_category_to_tps(category)
            severity = "medium" if tp_ids else "low"

            digest = hashlib.sha256(entry_id.encode()).hexdigest()[:8]
            alert_id = f"occ-{digest}"

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
