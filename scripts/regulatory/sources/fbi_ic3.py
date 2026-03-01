"""
fbi_ic3.py --- FBI IC3 Annual Internet Crime Report PDF source.

Downloads the FBI IC3 report PDF, extracts text using pdfplumber,
and parses tabular lines (category / victims / loss) into
``RegulatoryAlert`` objects.
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

# Pattern: category (words/slashes/spaces)  2+ spaces  victims (digits,comma)  whitespace  optional-$ loss (digits,comma)
# Use [ \t] instead of \s to avoid matching across newlines.
_LINE_PATTERN = re.compile(
    r"^([\w/ \t]+?)[ \t]{2,}([\d,]+)[ \t]+\$?([\d,]+)",
    re.MULTILINE,
)


class FBIC3Source(RegulatorySource):
    """FBI Internet Crime Complaint Center --- Annual Report PDF."""

    name = "fbi_ic3"

    def fetch(self):
        """Download IC3 Alerts HTML page and return raw text."""
        url = self.config.get("url", "https://www.ic3.gov/Home/IndustryAlerts")
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
            import re
            soup = BeautifulSoup(raw_data, "html.parser")
            
            # The IC3 lists alerts in blockquotes, standard lists, or row divs on the /CSA page
            for a in soup.find_all("a", href=True):
                text = a.text.strip()
                href = a["href"]
                
                # We want /CSA/YYYY/XXXX.pdf links
                if "/CSA/" in href and href.lower().endswith(".pdf"):
                    parent_text = a.parent.text.strip() if a.parent else text
                    # Look for dates like "Thu, 19 Feb 2026"
                    date_match = re.search(r"([A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4})", parent_text)
                    date = date_match.group(1) if date_match else ""
                    
                    title = text
                    
                    category = "Industry Alert"
                    tp_ids = self.map_category_to_tps(category)
                    severity = "high" if tp_ids else "medium"
                    
                    if href.startswith("/"):
                        href = "https://www.ic3.gov" + href

                    alerts.append(
                        RegulatoryAlert(
                            source=self.name,
                            alert_id=f"ic3-{len(alerts):04d}",
                            title=title,
                            date=date,
                            category=category,
                            mapped_tp_ids=tp_ids,
                            url=href,
                            severity=severity,
                            summary="FBI IC3 Notification",
                        )
                    )
        except Exception as e:
            logger.error(f"Failed to parse FBI IC3 alerts: {e}")

        # Remove duplicates
        seen = set()
        unique = []
        for x in alerts:
            # dedupe by title, avoiding wipeout of main array
            if x.title not in seen:
                seen.add(x.title)
                unique.append(x)
        return unique
