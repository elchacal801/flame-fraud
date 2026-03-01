"""
sec.py — SEC EDGAR RSS/Atom feed source.

Fetches SEC litigation releases and administrative proceedings via RSS
and normalises each entry into a ``RegulatoryAlert``.
"""

import hashlib
import logging
from typing import List

import feedparser
import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class SECSource(RegulatorySource):
    """Securities and Exchange Commission — EDGAR RSS feed."""

    name = "sec"

    def fetch(self):
        """Fetch HTML from SEC litigation releases page."""
        url = "https://www.sec.gov/litigation/litreleases.htm"
        headers = {
            "User-Agent": "FlameFraudApp Support@FlameFraud.test"
        }
        res = requests.get(url, headers=headers, timeout=60)
        res.raise_for_status()
        return res.text

    def parse(self, raw_data) -> List[RegulatoryAlert]:
        """Parse SEC HTML table into RegulatoryAlert objects."""
        if not raw_data:
            return []

        alerts: List[RegulatoryAlert] = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_data, "html.parser")
            
            for tr in soup.find_all("tr"):
                txt = tr.text.strip().replace("\n", " ")
                # Typical SEC rows start with date or include "LR-" / "Release"
                if "LR-" in txt or "Release No." in txt:
                    tds = tr.find_all("td")
                    if len(tds) < 2: continue
                    
                    # Columns: Date | Release No. | Respondents
                    date_td = tds[0]
                    date = date_td.text.strip()
                    if not date: continue

                    # Find the first link (usually in Release No. or Respondents)
                    a = tr.find("a")
                    if not a: continue
                    
                    title_text = ""
                    # Often the 3rd column is the Respondent / description
                    if len(tds) >= 3:
                        title_text = tds[2].text.strip()
                    else:
                        title_text = tds[1].text.strip()
                        
                    title = f"SEC Litigation: {title_text}"
                    link = a["href"]
                    if link.startswith("/"):
                        link = "https://www.sec.gov" + link

                    category = "Litigation Release"
                    tp_ids = self.map_category_to_tps(category)
                    severity = "high" if tp_ids else "medium"

                    alerts.append(
                        RegulatoryAlert(
                            source=self.name,
                            alert_id=f"sec-{len(alerts):04d}",
                            title=title[:250],
                            date=date,
                            category=category,
                            mapped_tp_ids=tp_ids,
                            url=link,
                            severity=severity,
                            summary="SEC Enforcement Action / Litigation Release",
                        )
                    )
        except Exception as e:
            logger.error(f"Failed to parse SEC alerts: {e}")

        return alerts
