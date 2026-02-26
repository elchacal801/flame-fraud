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
        """Download PDF and extract text from all pages.

        Returns
        -------
        str
            Concatenated text from every page of the PDF.
        """
        url = self.config["url"]
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()

        parts: List[str] = []
        with pdfplumber.open(io.BytesIO(resp.content)) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    parts.append(text)
        return "\n".join(parts)

    def parse(self, raw_data) -> List[RegulatoryAlert]:
        """Parse extracted text into RegulatoryAlert objects.

        Parameters
        ----------
        raw_data : str
            Concatenated page text from ``fetch()``.

        Returns
        -------
        list[RegulatoryAlert]
        """
        if not raw_data:
            return []

        alerts: List[RegulatoryAlert] = []
        matches = _LINE_PATTERN.findall(raw_data)

        for idx, (category_raw, victims, loss) in enumerate(matches, start=1):
            category = category_raw.strip()
            tp_ids = self.map_category_to_tps(category)
            severity = "high" if tp_ids else "medium"

            alerts.append(
                RegulatoryAlert(
                    source=self.name,
                    alert_id=f"ic3-{idx:04d}",
                    title=f"IC3: {category}",
                    date="",
                    category=category,
                    mapped_tp_ids=tp_ids,
                    url=self.config.get("url", ""),
                    severity=severity,
                    summary=f"Victims: {victims}, Loss: ${loss}",
                )
            )

        return alerts
