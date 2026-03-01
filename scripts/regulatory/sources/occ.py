"""
occ.py — OCC Bulletins RSS feed source.

Fetches OCC bulletin/enforcement entries via RSS and normalises each
into a ``RegulatoryAlert``.
"""

import hashlib
import logging
from typing import List

import feedparser
import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class OCCSource(RegulatorySource):
    """Office of the Comptroller of the Currency — Bulletins RSS."""

    name = "occ"

    def fetch(self):
        """Fetch the OCC HTML page."""
        url = "https://www.occ.gov/news-issuances/bulletins/index-bulletin-issuances.html"
        headers = {
            "User-Agent": "FlameFraudApp Support@FlameFraud.test"
        }
        res = requests.get(url, headers=headers, timeout=60)
        res.raise_for_status()
        return res.text

    def parse(self, raw_data) -> List[RegulatoryAlert]:
        """Parse HTML into a list of RegulatoryAlert objects."""
        alerts: List[RegulatoryAlert] = []
        if not raw_data: return []
        
        try:
            from bs4 import BeautifulSoup
            import re
            soup = BeautifulSoup(raw_data, "html.parser")
            
            for a in soup.find_all("a", href=True):
                text = a.text.strip()
                href = a["href"]
                
                # Looking for bulletin links
                if "bulletin" in href.lower() and len(text) > 10 and "<img" not in str(a):
                    title = text
                    if len(title) > 150:
                        title = title[:147] + "..."
                        
                    # Attempt to find date in parent or preceding elements
                    date = ""
                    parent = a.find_parent(["li", "div", "tr", "p"])
                    if parent:
                        # OCC usually formats as "OCC Bulletin 2024-12" or has dates nearby
                        time_el = parent.find("time")
                        if time_el:
                            date = time_el.text.strip()
                        else:
                            date_match = re.search(r"([A-Z][a-z]+ \d{1,2}, \d{4})", parent.text)
                            date = date_match.group(1) if date_match else ""

                    category = "Bulletin"
                    if "enforcement" in title.lower():
                        category = "Enforcement Action"

                    tp_ids = self.map_category_to_tps(category)
                    severity = "medium" if tp_ids else "low"
                    
                    if href.startswith("/"):
                        href = "https://www.occ.gov" + href

                    alert_id = f"occ-{len(alerts):04d}"

                    alerts.append(
                        RegulatoryAlert(
                            source=self.name,
                            alert_id=alert_id,
                            title=title,
                            date=date,
                            category=category,
                            mapped_tp_ids=tp_ids,
                            url=href,
                            severity=severity,
                            summary="OCC Regulatory Bulletin",
                        )
                    )
        except Exception as e:
            logger.error(f"Failed to parse OCC alerts: {e}")
            
        # Dedupe by title
        seen = set()
        unique = []
        for x in alerts:
            if x.title not in seen:
                seen.add(x.title)
                unique.append(x)

        return unique

