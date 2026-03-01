"""
fincen.py --- FinCEN SAR Statistics PDF source.

Downloads FinCEN SAR (Suspicious Activity Report) statistics PDF,
extracts tables using pdfplumber, and normalises each row into a
``RegulatoryAlert``.
"""

import io
import logging
import re
from typing import List

import pdfplumber
import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class FinCENSource(RegulatorySource):
    """Financial Crimes Enforcement Network --- SAR Statistics PDF."""

    name = "fincen"

    def fetch(self):
        """Download FinCEN Advisories HTML page and return raw text."""
        url = self.config.get("url", "https://www.fincen.gov/resources/advisoriesbulletinsfact-sheets/advisories")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp.text

    def parse(self, raw_data) -> List[RegulatoryAlert]:
        """Parse extracted HTML into RegulatoryAlert objects."""
        if not raw_data:
            return []

        alerts: List[RegulatoryAlert] = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_data, "html.parser")
            
            # FinCEN advisories are currently in a table
            for tr in soup.find_all("tr"):
                tds = tr.find_all("td")
                if len(tds) >= 2:
                    date_td = tds[0]
                    title_td = tds[1]
                    
                    # Extract date
                    time_el = date_td.find("time")
                    date = time_el.text.strip() if time_el else date_td.text.strip()
                    if not date: continue
                    
                    # Extract title and link
                    a = title_td.find("a")
                    if not a: continue
                    title = a.text.strip()
                    link = a["href"]
                    if link.startswith("/"):
                        link = "https://www.fincen.gov" + link

                    category = "Advisory"
                    tp_ids = self.map_category_to_tps(category)
                    severity = "high" if tp_ids else "medium"

                    alerts.append(
                        RegulatoryAlert(
                            source=self.name,
                            alert_id=f"fincen-{len(alerts):04d}",
                            title=title,
                            date=date,
                            category=category,
                            mapped_tp_ids=tp_ids,
                            url=link,
                            severity=severity,
                            summary="FinCEN Advisory Notification",
                        )
                    )
        except Exception as e:
            logger.error(f"Failed to parse FinCEN alerts: {e}")

        return alerts
