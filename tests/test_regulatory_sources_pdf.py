"""
test_regulatory_sources_pdf.py --- Tests for PDF-based regulatory sources.

Covers: FinCENSource, FBIC3Source.
Tests focus on parse() with pre-extracted data (no real PDFs needed).
fetch() is tested via mocking pdfplumber.
"""

import re
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add scripts dir to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.models import RegulatoryAlert
from regulatory.sources.fincen import FinCENSource
from regulatory.sources.fbi_ic3 import FBIC3Source


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
# FinCENSource tests
# ===========================================================================

# Mock table data: list of tables, each table is list of rows, each row is list of cells
FINCEN_TABLES = [
    [
        ["Category", "Count", "Notes"],
        ["synthetic-identity", "12,345", "SAR filings up"],
        ["money-laundering", "8,901", "Steady trend"],
        ["elder-fraud", "3,456", "Increasing"],
    ],
]

FINCEN_TABLES_WITH_SHORT = [
    # Table with only a header row (should be skipped)
    [
        ["Header Only"],
    ],
    # Table with data rows
    [
        ["Category", "Count"],
        ["identity-theft", "500"],
    ],
]

FINCEN_TABLES_NON_DIGIT_COUNT = [
    [
        ["Category", "Count"],
        ["ransomware", "$1,234 (est.)"],
        ["corruption", "N/A"],
    ],
]


class TestFinCENSource:
    def test_name(self):
        """FinCENSource.name should be 'fincen'."""
        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        assert src.name == "fincen"

    def test_parse_produces_correct_alerts(self):
        """parse() should produce one alert per data row with correct fields."""
        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        alerts = src.parse(FINCEN_TABLES)

        assert len(alerts) == 3

        a0 = alerts[0]
        assert a0.source == "fincen"
        assert a0.alert_id == "fincen-sar-0001"
        assert a0.title == "FinCEN SAR: synthetic-identity"
        assert a0.category == "synthetic-identity"
        assert a0.summary == "SAR filings: 12345"
        assert a0.severity == "medium"  # no TP mapping configured

        a1 = alerts[1]
        assert a1.alert_id == "fincen-sar-0002"
        assert a1.title == "FinCEN SAR: money-laundering"
        assert a1.summary == "SAR filings: 8901"

        a2 = alerts[2]
        assert a2.alert_id == "fincen-sar-0003"
        assert a2.title == "FinCEN SAR: elder-fraud"
        assert a2.summary == "SAR filings: 3456"

    def test_parse_empty_tables(self):
        """parse() should return empty list when input is empty."""
        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        alerts = src.parse([])
        assert alerts == []

    def test_parse_skips_short_tables(self):
        """parse() should skip tables with fewer than 2 rows."""
        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        alerts = src.parse(FINCEN_TABLES_WITH_SHORT)

        # Only the second table should produce alerts (1 data row)
        assert len(alerts) == 1
        assert alerts[0].title == "FinCEN SAR: identity-theft"

    def test_parse_strips_non_digits_from_count(self):
        """parse() should strip non-digit characters from count cells."""
        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        alerts = src.parse(FINCEN_TABLES_NON_DIGIT_COUNT)

        assert len(alerts) == 2
        assert alerts[0].summary == "SAR filings: 1234"
        # "N/A" has no digits -- summary should omit count
        assert alerts[1].summary == ""

    def test_parse_severity_high_when_tp_mapped(self):
        """severity should be 'high' when category maps to TP IDs."""
        config = _make_config({
            "url": "https://fincen.gov/sar.pdf",
            "category_mapping": {
                "synthetic-identity": ["TP-0012", "TP-0034"],
                "elder-fraud": ["TP-0005"],
            },
        })
        src = FinCENSource(config)
        alerts = src.parse(FINCEN_TABLES)

        # synthetic-identity is mapped -> high
        assert alerts[0].severity == "high"
        assert alerts[0].mapped_tp_ids == ["TP-0012", "TP-0034"]

        # money-laundering is NOT mapped -> medium
        assert alerts[1].severity == "medium"
        assert alerts[1].mapped_tp_ids == []

        # elder-fraud is mapped -> high
        assert alerts[2].severity == "high"
        assert alerts[2].mapped_tp_ids == ["TP-0005"]

    @patch("regulatory.sources.fincen.pdfplumber")
    @patch("regulatory.sources.fincen.requests.get")
    def test_fetch_downloads_and_extracts_tables(self, mock_get, mock_pdfplumber):
        """fetch() should download PDF and extract tables via pdfplumber."""
        # Mock the HTTP response
        mock_resp = MagicMock()
        mock_resp.content = b"%PDF-fake-content"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        # Mock pdfplumber pages with tables
        mock_page1 = MagicMock()
        mock_page1.extract_tables.return_value = [
            [["Category", "Count"], ["fraud", "100"]]
        ]
        mock_page2 = MagicMock()
        mock_page2.extract_tables.return_value = [
            [["Category", "Count"], ["theft", "200"]]
        ]

        mock_pdf = MagicMock()
        mock_pdf.pages = [mock_page1, mock_page2]
        mock_pdf.__enter__ = MagicMock(return_value=mock_pdf)
        mock_pdf.__exit__ = MagicMock(return_value=False)
        mock_pdfplumber.open.return_value = mock_pdf

        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        result = src.fetch()

        mock_get.assert_called_once_with("https://fincen.gov/sar.pdf", timeout=60)
        assert len(result) == 2
        assert result[0] == [["Category", "Count"], ["fraud", "100"]]
        assert result[1] == [["Category", "Count"], ["theft", "200"]]

    def test_parse_handles_none_cells(self):
        """parse() should handle None values in table cells gracefully."""
        tables = [
            [
                ["Category", "Count"],
                [None, "100"],
                ["valid-cat", None],
            ],
        ]
        src = FinCENSource(_make_config({"url": "https://fincen.gov/sar.pdf"}))
        alerts = src.parse(tables)

        # Both rows should be processed without errors
        assert len(alerts) == 2
        assert alerts[0].category == ""
        assert alerts[1].summary == ""


# ===========================================================================
# FBIC3Source tests
# ===========================================================================

FBI_IC3_TEXT = """\
2025 Internet Crime Report

Crime Type                  Victims     Loss
Business Email Compromise   21,489      $2,946,681,772
Ransomware                  3,729       $59,634,900
Romance Scam                19,050      $735,882,714
Investment Fraud            38,028      $6,573,249,878
"""

FBI_IC3_TEXT_EXTRA_WHITESPACE = """\
Crime Type                Victims        Loss
Tech Support Fraud        17,622         $924,512,409
Identity Theft            51,629         $278,085,558
"""


class TestFBIC3Source:
    def test_name(self):
        """FBIC3Source.name should be 'fbi_ic3'."""
        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        assert src.name == "fbi_ic3"

    def test_parse_produces_correct_alerts(self):
        """parse() should produce one alert per matching line."""
        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        alerts = src.parse(FBI_IC3_TEXT)

        assert len(alerts) == 4

        a0 = alerts[0]
        assert a0.source == "fbi_ic3"
        assert a0.alert_id == "ic3-0001"
        assert a0.title == "IC3: Business Email Compromise"
        assert a0.category == "Business Email Compromise"
        assert a0.summary == "Victims: 21,489, Loss: $2,946,681,772"
        assert a0.severity == "medium"  # no TP mapping configured

        a1 = alerts[1]
        assert a1.alert_id == "ic3-0002"
        assert a1.title == "IC3: Ransomware"
        assert a1.summary == "Victims: 3,729, Loss: $59,634,900"

        a2 = alerts[2]
        assert a2.alert_id == "ic3-0003"
        assert a2.title == "IC3: Romance Scam"

        a3 = alerts[3]
        assert a3.alert_id == "ic3-0004"
        assert a3.title == "IC3: Investment Fraud"
        assert a3.summary == "Victims: 38,028, Loss: $6,573,249,878"

    def test_parse_empty_text(self):
        """parse() should return empty list when input is empty string."""
        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        alerts = src.parse("")
        assert alerts == []

    def test_parse_severity_high_when_tp_mapped(self):
        """severity should be 'high' when category maps to TP IDs."""
        config = _make_config({
            "url": "https://ic3.gov/report.pdf",
            "category_mapping": {
                "Business Email Compromise": ["TP-0010", "TP-0011"],
                "Investment Fraud": ["TP-0031"],
            },
        })
        src = FBIC3Source(config)
        alerts = src.parse(FBI_IC3_TEXT)

        # BEC is mapped -> high
        assert alerts[0].severity == "high"
        assert alerts[0].mapped_tp_ids == ["TP-0010", "TP-0011"]

        # Ransomware is NOT mapped -> medium
        assert alerts[1].severity == "medium"
        assert alerts[1].mapped_tp_ids == []

        # Romance Scam is NOT mapped -> medium
        assert alerts[2].severity == "medium"

        # Investment Fraud is mapped -> high
        assert alerts[3].severity == "high"
        assert alerts[3].mapped_tp_ids == ["TP-0031"]

    def test_parse_extra_whitespace(self):
        """parse() should handle extra whitespace between columns."""
        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        alerts = src.parse(FBI_IC3_TEXT_EXTRA_WHITESPACE)

        assert len(alerts) == 2
        assert alerts[0].title == "IC3: Tech Support Fraud"
        assert alerts[0].summary == "Victims: 17,622, Loss: $924,512,409"

        assert alerts[1].title == "IC3: Identity Theft"
        assert alerts[1].summary == "Victims: 51,629, Loss: $278,085,558"

    @patch("regulatory.sources.fbi_ic3.pdfplumber")
    @patch("regulatory.sources.fbi_ic3.requests.get")
    def test_fetch_downloads_and_extracts_text(self, mock_get, mock_pdfplumber):
        """fetch() should download PDF and extract text via pdfplumber."""
        # Mock the HTTP response
        mock_resp = MagicMock()
        mock_resp.content = b"%PDF-fake-content"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        # Mock pdfplumber pages with text
        mock_page1 = MagicMock()
        mock_page1.extract_text.return_value = "Page 1 text\n"
        mock_page2 = MagicMock()
        mock_page2.extract_text.return_value = "Page 2 text\n"

        mock_pdf = MagicMock()
        mock_pdf.pages = [mock_page1, mock_page2]
        mock_pdf.__enter__ = MagicMock(return_value=mock_pdf)
        mock_pdf.__exit__ = MagicMock(return_value=False)
        mock_pdfplumber.open.return_value = mock_pdf

        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        result = src.fetch()

        mock_get.assert_called_once_with("https://ic3.gov/report.pdf", timeout=60)
        assert result == "Page 1 text\n\nPage 2 text\n"

    def test_parse_no_matching_lines(self):
        """parse() should return empty list when no lines match the pattern."""
        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        alerts = src.parse("This is just plain text with no tabular data.")
        assert alerts == []

    @patch("regulatory.sources.fbi_ic3.pdfplumber")
    @patch("regulatory.sources.fbi_ic3.requests.get")
    def test_fetch_handles_none_page_text(self, mock_get, mock_pdfplumber):
        """fetch() should handle pages where extract_text returns None."""
        mock_resp = MagicMock()
        mock_resp.content = b"%PDF-fake"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        mock_page1 = MagicMock()
        mock_page1.extract_text.return_value = None
        mock_page2 = MagicMock()
        mock_page2.extract_text.return_value = "Some text"

        mock_pdf = MagicMock()
        mock_pdf.pages = [mock_page1, mock_page2]
        mock_pdf.__enter__ = MagicMock(return_value=mock_pdf)
        mock_pdf.__exit__ = MagicMock(return_value=False)
        mock_pdfplumber.open.return_value = mock_pdf

        src = FBIC3Source(_make_config({"url": "https://ic3.gov/report.pdf"}))
        result = src.fetch()

        assert result == "Some text"
