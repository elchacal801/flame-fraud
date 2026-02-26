"""
test_regulatory_sources_structured.py — Tests for structured regulatory sources.

Covers: CFPBSource, OCCSource, SECSource, OFACSource.
Each source is tested for correct .name attribute, proper alert parsing
from mock data, and TP mapping behaviour.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add scripts dir to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.models import RegulatoryAlert
from regulatory.sources.cfpb import CFPBSource
from regulatory.sources.occ import OCCSource
from regulatory.sources.sec import SECSource
from regulatory.sources.ofac import OFACSource


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_config(extra=None):
    """Build a minimal config dict with optional overrides."""
    config = {
        "enabled": True,
        "category_mapping": {},
    }
    if extra:
        config.update(extra)
    return config


# ===========================================================================
# CFPBSource tests
# ===========================================================================

CFPB_API_RESPONSE = {
    "hits": {
        "hits": [
            {
                "_source": {
                    "complaint_id": "12345",
                    "product": "Credit reporting",
                    "date_received": "2026-02-01",
                    "issue": "Incorrect information on your report",
                    "complaint_what_happened": "My credit report shows an account that is not mine.",
                }
            },
            {
                "_source": {
                    "complaint_id": "67890",
                    "product": "Mortgage",
                    "date_received": "2026-02-10",
                    "issue": "Applying for a mortgage or refinancing an existing mortgage",
                    "complaint_what_happened": "",
                }
            },
        ]
    }
}


class TestCFPBSource:
    def test_name(self):
        """CFPBSource.name should be 'cfpb'."""
        src = CFPBSource(_make_config({"base_url": "https://api.example.com"}))
        assert src.name == "cfpb"

    @patch("regulatory.sources.cfpb.requests.get")
    def test_fetch_calls_api(self, mock_get):
        """fetch() should GET from base_url with expected params."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = CFPB_API_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        src = CFPBSource(_make_config({"base_url": "https://api.example.com/complaints"}))
        result = src.fetch()

        mock_get.assert_called_once_with(
            "https://api.example.com/complaints",
            params={"size": 100, "sort": "created_date_desc"},
            timeout=30,
        )
        assert result == CFPB_API_RESPONSE

    def test_parse_produces_correct_alerts(self):
        """parse() should produce one alert per hit with correct fields."""
        src = CFPBSource(_make_config({"base_url": "https://api.example.com"}))
        alerts = src.parse(CFPB_API_RESPONSE)

        assert len(alerts) == 2

        a0 = alerts[0]
        assert a0.source == "cfpb"
        assert a0.alert_id == "cfpb-12345"
        assert a0.title == "Incorrect information on your report"
        assert a0.date == "2026-02-01"
        assert a0.category == "Credit reporting"
        assert a0.severity == "medium"
        assert a0.summary == "My credit report shows an account that is not mine."

        a1 = alerts[1]
        assert a1.alert_id == "cfpb-67890"
        assert a1.category == "Mortgage"

    def test_parse_maps_tp_ids(self):
        """parse() should map product to TP IDs via category_mapping."""
        config = _make_config({
            "base_url": "https://api.example.com",
            "category_mapping": {
                "Credit reporting": ["TP-0051"],
                "Mortgage": ["TP-0002"],
            },
        })
        src = CFPBSource(config)
        alerts = src.parse(CFPB_API_RESPONSE)

        assert alerts[0].mapped_tp_ids == ["TP-0051"]
        assert alerts[1].mapped_tp_ids == ["TP-0002"]

    def test_parse_no_mapping(self):
        """When no category_mapping matches, mapped_tp_ids is empty."""
        src = CFPBSource(_make_config({"base_url": "https://api.example.com"}))
        alerts = src.parse(CFPB_API_RESPONSE)
        assert alerts[0].mapped_tp_ids == []


# ===========================================================================
# OCCSource tests
# ===========================================================================

def _make_occ_feed():
    """Build a mock feedparser result for OCC."""
    feed = MagicMock()
    entry1 = MagicMock()
    entry1.id = "https://occ.gov/bulletin-2026-01"
    entry1.title = "OCC Bulletin 2026-01: BSA/AML Compliance"
    entry1.published = "2026-01-15"
    entry1.link = "https://occ.gov/bulletin-2026-01"
    entry1.get.side_effect = lambda k, default="": {
        "summary": "Guidance on BSA/AML compliance expectations.",
    }.get(k, default)
    entry1.tags = [MagicMock(term="bsa-aml")]

    entry2 = MagicMock()
    entry2.id = "https://occ.gov/enforcement-2026-01"
    entry2.title = "Enforcement Action Against National Bank"
    entry2.published = "2026-02-01"
    entry2.link = "https://occ.gov/enforcement-2026-01"
    entry2.get.side_effect = lambda k, default="": {
        "summary": "OCC takes enforcement action.",
    }.get(k, default)
    entry2.tags = []

    feed.entries = [entry1, entry2]
    return feed


class TestOCCSource:
    def test_name(self):
        """OCCSource.name should be 'occ'."""
        src = OCCSource(_make_config({"feed_url": "https://occ.gov/feed"}))
        assert src.name == "occ"

    @patch("regulatory.sources.occ.feedparser.parse")
    def test_fetch_calls_feedparser(self, mock_parse):
        """fetch() should call feedparser.parse with the feed_url."""
        mock_parse.return_value = _make_occ_feed()
        src = OCCSource(_make_config({"feed_url": "https://occ.gov/feed"}))
        result = src.fetch()
        mock_parse.assert_called_once_with("https://occ.gov/feed")

    @patch("regulatory.sources.occ.feedparser.parse")
    def test_parse_produces_correct_alerts(self, mock_parse):
        """parse() should produce correct alerts from feed entries."""
        feed = _make_occ_feed()
        mock_parse.return_value = feed
        src = OCCSource(_make_config({"feed_url": "https://occ.gov/feed"}))
        raw = src.fetch()
        alerts = src.parse(raw)

        assert len(alerts) == 2

        a0 = alerts[0]
        assert a0.source == "occ"
        assert a0.alert_id.startswith("occ-")
        assert a0.title == "OCC Bulletin 2026-01: BSA/AML Compliance"
        assert a0.date == "2026-01-15"
        assert a0.url == "https://occ.gov/bulletin-2026-01"

        # entry2 has "enforcement" in title
        a1 = alerts[1]
        assert a1.category == "Enforcement Action"

    @patch("regulatory.sources.occ.feedparser.parse")
    def test_category_from_tags(self, mock_parse):
        """Category should come from entry tags when present."""
        feed = _make_occ_feed()
        mock_parse.return_value = feed
        src = OCCSource(_make_config({"feed_url": "https://occ.gov/feed"}))
        raw = src.fetch()
        alerts = src.parse(raw)

        # entry1 has tags: [bsa-aml]
        assert alerts[0].category == "bsa-aml"

    @patch("regulatory.sources.occ.feedparser.parse")
    def test_severity_with_tp_mapping(self, mock_parse):
        """Severity should be 'medium' when TP-mapped, 'low' otherwise."""
        feed = _make_occ_feed()
        mock_parse.return_value = feed
        config = _make_config({
            "feed_url": "https://occ.gov/feed",
            "category_mapping": {
                "bsa-aml": ["TP-0001"],
            },
        })
        src = OCCSource(config)
        raw = src.fetch()
        alerts = src.parse(raw)

        # entry1 has category "bsa-aml" which maps to TP-0001
        assert alerts[0].severity == "medium"
        assert alerts[0].mapped_tp_ids == ["TP-0001"]

        # entry2 has category "Enforcement Action" which has no mapping
        assert alerts[1].severity == "low"
        assert alerts[1].mapped_tp_ids == []


# ===========================================================================
# SECSource tests
# ===========================================================================

def _make_sec_feed():
    """Build a mock feedparser result for SEC."""
    feed = MagicMock()
    entry1 = MagicMock()
    entry1.id = "https://sec.gov/litigation/lr/2026-001"
    entry1.title = "SEC Charges XYZ Corp with Securities Fraud"
    entry1.published = "2026-01-20"
    entry1.link = "https://sec.gov/litigation/lr/2026-001"
    entry1.get.side_effect = lambda k, default="": {
        "summary": "SEC files fraud charges.",
    }.get(k, default)

    entry2 = MagicMock()
    entry2.id = "https://sec.gov/litigation/ap/2026-002"
    entry2.title = "Administrative Proceeding Against ABC Fund"
    entry2.published = "2026-02-05"
    entry2.link = "https://sec.gov/litigation/ap/2026-002"
    entry2.get.side_effect = lambda k, default="": {
        "summary": "Administrative proceeding initiated.",
    }.get(k, default)

    feed.entries = [entry1, entry2]
    return feed


class TestSECSource:
    def test_name(self):
        """SECSource.name should be 'sec'."""
        src = SECSource(_make_config({"feed_url": "https://sec.gov/feed"}))
        assert src.name == "sec"

    @patch("regulatory.sources.sec.feedparser.parse")
    def test_fetch_calls_feedparser(self, mock_parse):
        """fetch() should call feedparser.parse with the feed_url."""
        mock_parse.return_value = _make_sec_feed()
        src = SECSource(_make_config({"feed_url": "https://sec.gov/feed"}))
        result = src.fetch()
        mock_parse.assert_called_once_with("https://sec.gov/feed")

    @patch("regulatory.sources.sec.feedparser.parse")
    def test_parse_produces_correct_alerts(self, mock_parse):
        """parse() should produce correct alerts from feed entries."""
        feed = _make_sec_feed()
        mock_parse.return_value = feed
        src = SECSource(_make_config({"feed_url": "https://sec.gov/feed"}))
        raw = src.fetch()
        alerts = src.parse(raw)

        assert len(alerts) == 2

        a0 = alerts[0]
        assert a0.source == "sec"
        assert a0.alert_id.startswith("sec-")
        assert a0.title == "SEC Charges XYZ Corp with Securities Fraud"
        assert a0.date == "2026-01-20"
        assert a0.category == "Litigation Release"

        a1 = alerts[1]
        assert a1.category == "Administrative Proceeding"

    @patch("regulatory.sources.sec.feedparser.parse")
    def test_severity_with_tp_mapping(self, mock_parse):
        """Severity should be 'high' when TP-mapped, 'medium' otherwise."""
        feed = _make_sec_feed()
        mock_parse.return_value = feed
        config = _make_config({
            "feed_url": "https://sec.gov/feed",
            "category_mapping": {
                "Litigation Release": ["TP-0031"],
            },
        })
        src = SECSource(config)
        raw = src.fetch()
        alerts = src.parse(raw)

        assert alerts[0].severity == "high"
        assert alerts[0].mapped_tp_ids == ["TP-0031"]

        assert alerts[1].severity == "medium"
        assert alerts[1].mapped_tp_ids == []


# ===========================================================================
# OFACSource tests
# ===========================================================================

OFAC_SDN_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML">
  <publshInformation>
    <Publish_Date>02/20/2026</Publish_Date>
  </publshInformation>
  <sdnEntry>
    <uid>12345</uid>
    <firstName>John</firstName>
    <lastName>DOE</lastName>
    <sdnType>Individual</sdnType>
    <programList>
      <program>SDGT</program>
    </programList>
  </sdnEntry>
  <sdnEntry>
    <uid>67890</uid>
    <firstName>ACME</firstName>
    <lastName>CORP</lastName>
    <sdnType>Entity</sdnType>
    <programList>
      <program>CYBER2</program>
    </programList>
  </sdnEntry>
</sdnList>
"""

OFAC_SDN_XML_NO_NS = b"""<?xml version="1.0" encoding="utf-8"?>
<sdnList>
  <sdnEntry>
    <uid>99999</uid>
    <firstName>Jane</firstName>
    <lastName>SMITH</lastName>
    <sdnType>Individual</sdnType>
    <programList>
      <program>IRAN</program>
    </programList>
  </sdnEntry>
</sdnList>
"""


class TestOFACSource:
    def test_name(self):
        """OFACSource.name should be 'ofac'."""
        src = OFACSource(_make_config({"sdn_url": "https://ofac.example.com/SDN.XML"}))
        assert src.name == "ofac"

    @patch("regulatory.sources.ofac.requests.get")
    def test_fetch_returns_bytes(self, mock_get):
        """fetch() should GET from sdn_url and return raw bytes."""
        mock_resp = MagicMock()
        mock_resp.content = OFAC_SDN_XML
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        src = OFACSource(_make_config({"sdn_url": "https://ofac.example.com/SDN.XML"}))
        result = src.fetch()

        mock_get.assert_called_once_with(
            "https://ofac.example.com/SDN.XML",
            timeout=60,
        )
        assert result == OFAC_SDN_XML

    def test_parse_namespaced_xml(self):
        """parse() should correctly handle namespaced XML."""
        src = OFACSource(_make_config({"sdn_url": "https://ofac.example.com/SDN.XML"}))
        alerts = src.parse(OFAC_SDN_XML)

        assert len(alerts) == 2

        a0 = alerts[0]
        assert a0.source == "ofac"
        assert a0.alert_id == "ofac-12345"
        assert a0.title == "OFAC SDN: John DOE (Individual)"
        assert a0.severity == "high"
        assert a0.category == "SDN List Addition"

        a1 = alerts[1]
        assert a1.alert_id == "ofac-67890"
        assert a1.title == "OFAC SDN: ACME CORP (Entity)"

    def test_parse_non_namespaced_xml(self):
        """parse() should handle XML without namespace prefix."""
        src = OFACSource(_make_config({"sdn_url": "https://ofac.example.com/SDN.XML"}))
        alerts = src.parse(OFAC_SDN_XML_NO_NS)

        assert len(alerts) == 1
        assert alerts[0].alert_id == "ofac-99999"
        assert alerts[0].title == "OFAC SDN: Jane SMITH (Individual)"

    def test_parse_maps_tp_ids(self):
        """parse() should map SDN List Addition via category_mapping."""
        config = _make_config({
            "sdn_url": "https://ofac.example.com/SDN.XML",
            "category_mapping": {
                "SDN List Addition": ["TP-0001", "TP-0080"],
            },
        })
        src = OFACSource(config)
        alerts = src.parse(OFAC_SDN_XML)

        assert alerts[0].mapped_tp_ids == ["TP-0001", "TP-0080"]
        assert alerts[1].mapped_tp_ids == ["TP-0001", "TP-0080"]

    def test_parse_summary_contains_programs(self):
        """Summary should contain program list information."""
        src = OFACSource(_make_config({"sdn_url": "https://ofac.example.com/SDN.XML"}))
        alerts = src.parse(OFAC_SDN_XML)

        assert "SDGT" in alerts[0].summary
        assert "CYBER2" in alerts[1].summary
