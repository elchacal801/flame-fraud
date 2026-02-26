"""
cfpb.py — CFPB Consumer Complaints API source.

Fetches consumer complaint data from the CFPB REST API and normalises
each complaint into a ``RegulatoryAlert``.
"""

import logging
from typing import List

import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class CFPBSource(RegulatorySource):
    """Consumer Financial Protection Bureau — Consumer Complaints API."""

    name = "cfpb"

    def fetch(self):
        """GET the CFPB complaints API and return the parsed JSON dict."""
        url = self.config["base_url"]
        resp = requests.get(
            url,
            params={"size": 100, "sort": "created_date_desc"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def parse(self, raw_data) -> List[RegulatoryAlert]:
        """Parse CFPB API JSON into a list of RegulatoryAlert objects.

        Expected structure::

            {"hits": {"hits": [{"_source": { ... }}, ...]}}
        """
        alerts: List[RegulatoryAlert] = []
        hits = raw_data.get("hits", {}).get("hits", [])

        for hit in hits:
            src = hit.get("_source", {})
            complaint_id = str(src.get("complaint_id", ""))
            product = src.get("product", "")
            date_received = src.get("date_received", "")
            issue = src.get("issue", "")
            narrative = src.get("complaint_what_happened", "")

            tp_ids = self.map_category_to_tps(product)

            alerts.append(
                RegulatoryAlert(
                    source=self.name,
                    alert_id=f"cfpb-{complaint_id}",
                    title=issue,
                    date=date_received,
                    category=product,
                    mapped_tp_ids=tp_ids,
                    url="",
                    severity="medium",
                    summary=narrative,
                )
            )

        return alerts
