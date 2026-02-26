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
        """Download PDF and extract tables from all pages.

        Returns
        -------
        list[list[list[str]]]
            List of tables; each table is a list of rows, each row a
            list of cell strings.
        """
        url = self.config["url"]
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()

        tables = []
        with pdfplumber.open(io.BytesIO(resp.content)) as pdf:
            for page in pdf.pages:
                page_tables = page.extract_tables()
                if page_tables:
                    tables.extend(page_tables)
        return tables

    def parse(self, raw_data) -> List[RegulatoryAlert]:
        """Parse extracted table data into RegulatoryAlert objects.

        Parameters
        ----------
        raw_data : list[list[list[str]]]
            List of tables from ``fetch()``.  Each table is a list of
            rows; each row is a list of cell values.

        Returns
        -------
        list[RegulatoryAlert]
        """
        if not raw_data:
            return []

        alerts: List[RegulatoryAlert] = []
        idx = 0

        for table in raw_data:
            # Skip tables with fewer than 2 rows (header + at least one data row)
            if len(table) < 2:
                continue

            # Skip header row, process data rows
            for row in table[1:]:
                idx += 1

                category = str(row[0]) if row[0] is not None else ""
                raw_count = str(row[1]) if len(row) > 1 and row[1] is not None else ""

                # Strip non-digit characters to get the count
                count = re.sub(r"\D", "", raw_count)

                tp_ids = self.map_category_to_tps(category)
                severity = "high" if tp_ids else "medium"

                summary = f"SAR filings: {count}" if count else ""

                alerts.append(
                    RegulatoryAlert(
                        source=self.name,
                        alert_id=f"fincen-sar-{idx:04d}",
                        title=f"FinCEN SAR: {category}",
                        date="",
                        category=category,
                        mapped_tp_ids=tp_ids,
                        url=self.config.get("url", ""),
                        severity=severity,
                        summary=summary,
                    )
                )

        return alerts
