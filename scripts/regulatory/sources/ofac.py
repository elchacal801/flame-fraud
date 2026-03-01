"""
ofac.py — OFAC SDN List XML source.

Fetches the OFAC Specially Designated Nationals (SDN) list in XML format
and normalises each entry into a ``RegulatoryAlert``.
"""

import logging
import xml.etree.ElementTree as ET
from typing import List

from defusedxml.ElementTree import fromstring as _safe_fromstring

import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class OFACSource(RegulatorySource):
    """Office of Foreign Assets Control — SDN List XML."""

    name = "ofac"

    def fetch(self):
        """GET the OFAC SDN XML and return raw bytes."""
        url = self.config["sdn_url"]
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        return resp.content

    def parse(self, raw_data: bytes) -> List[RegulatoryAlert]:
        """Parse OFAC SDN XML into a list of RegulatoryAlert objects.

        Handles both namespaced and non-namespaced XML.
        """
        alerts: List[RegulatoryAlert] = []
        root = _safe_fromstring(raw_data)

        # Detect namespace — the root tag may be {ns}sdnList or just sdnList
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        pub_info = root.find(f"{ns}publshInformation")
        publish_date = ""
        if pub_info is not None:
            publish_date = self._text(pub_info, f"{ns}Publish_Date", "")

        for entry in root.findall(f"{ns}sdnEntry"):
            uid = self._text(entry, f"{ns}uid")
            first = self._text(entry, f"{ns}firstName")
            last = self._text(entry, f"{ns}lastName")
            sdn_type = self._text(entry, f"{ns}sdnType")

            # Collect programs
            programs = []
            prog_list = entry.find(f"{ns}programList")
            if prog_list is not None:
                for prog in prog_list.findall(f"{ns}program"):
                    if prog.text:
                        programs.append(prog.text.strip())

            category = "SDN List Addition"
            tp_ids = self.map_category_to_tps(category)
            title = f"OFAC SDN: {first} {last} ({sdn_type})"
            summary = f"SDN entry — type: {sdn_type}, programs: {', '.join(programs)}"

            alerts.append(
                RegulatoryAlert(
                    source=self.name,
                    alert_id=f"ofac-{uid}",
                    title=title,
                    date=publish_date,
                    category=category,
                    mapped_tp_ids=tp_ids,
                    url="",
                    severity="high",
                    summary=summary,
                )
            )

        return alerts

    @staticmethod
    def _text(element: ET.Element, tag: str, default: str = "") -> str:
        """Safely extract text from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
