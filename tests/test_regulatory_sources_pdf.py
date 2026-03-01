"""
test_regulatory_sources_pdf.py --- Tests for FinCEN and FBI IC3 sources.

Covers: FinCENSource, FBIC3Source.
Tests focus on parse() with pre-extracted HTML strings.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.models import RegulatoryAlert
from regulatory.sources.fincen import FinCENSource
from regulatory.sources.fbi_ic3 import FBIC3Source


def _make_config(extra=None):
    config = {"enabled": True, "category_mapping": {}}
    if extra:
        config.update(extra)
    return config


FINCEN_HTML = """
<table>
  <tr>
    <td><time>2026-02-15</time></td>
    <td><a href="/advisory/fake.pdf">FinCEN Advisory on Money Laundering</a></td>
  </tr>
  <tr>
    <td>2026-02-10</td>
    <td><a href="/advisory/fake2.pdf">FinCEN Advisory on Ransomware</a></td>
  </tr>
  <tr>
    <td><time>Invalid Date</time></td>
    <td>No Link Here</td>
  </tr>
</table>
"""

class TestFinCENSource:
    def test_name(self):
        src = FinCENSource(_make_config())
        assert src.name == "fincen"

    def test_parse_produces_correct_alerts(self):
        src = FinCENSource(_make_config())
        alerts = src.parse(FINCEN_HTML)
        assert len(alerts) == 2
        
        assert alerts[0].title == "FinCEN Advisory on Money Laundering"
        assert alerts[0].date == "2026-02-15"
        assert alerts[0].url == "https://www.fincen.gov/advisory/fake.pdf"
        assert alerts[0].category == "Advisory"
        assert alerts[0].severity == "medium"

        assert alerts[1].title == "FinCEN Advisory on Ransomware"
        assert alerts[1].date == "2026-02-10"
        assert alerts[1].url == "https://www.fincen.gov/advisory/fake2.pdf"

    def test_parse_severity_high_when_tp_mapped(self):
        config = _make_config({"category_mapping": {"Advisory": ["TP-0001"]}})
        src = FinCENSource(config)
        alerts = src.parse(FINCEN_HTML)
        assert alerts[0].severity == "high"
        assert alerts[0].mapped_tp_ids == ["TP-0001"]

    def test_parse_empty_html(self):
        src = FinCENSource(_make_config())
        assert src.parse("") == []

    @patch("regulatory.sources.fincen.requests.get")
    def test_fetch_downloads_html(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = FINCEN_HTML
        mock_get.return_value = mock_resp

        src = FinCENSource(_make_config({"url": "https://test.gov"}))
        result = src.fetch()

        mock_get.assert_called_once()
        assert result == FINCEN_HTML


FBI_IC3_HTML = """
<div>
  <ul>
    <li>
      Thu, 19 Feb 2026
      <a href="/CSA/2026/260219.pdf">FBI Alert on BEC</a>
    </li>
    <li>
      Wed, 18 Feb 2026
      <a href="/Media/2026/non-csa.pdf">Should be ignored</a>
    </li>
  </ul>
</div>
"""

class TestFBIC3Source:
    def test_name(self):
        src = FBIC3Source(_make_config())
        assert src.name == "fbi_ic3"

    def test_parse_produces_correct_alerts(self):
        src = FBIC3Source(_make_config())
        alerts = src.parse(FBI_IC3_HTML)
        assert len(alerts) == 1
        
        a = alerts[0]
        assert a.title == "FBI Alert on BEC"
        assert a.date == "Thu, 19 Feb 2026"
        assert a.url == "https://www.ic3.gov/CSA/2026/260219.pdf"
        assert a.category == "Industry Alert"
        assert a.severity == "medium"

    def test_parse_severity_high_when_tp_mapped(self):
        config = _make_config({"category_mapping": {"Industry Alert": ["TP-0010"]}})
        src = FBIC3Source(config)
        alerts = src.parse(FBI_IC3_HTML)
        assert alerts[0].severity == "high"
        assert alerts[0].mapped_tp_ids == ["TP-0010"]

    def test_parse_empty_html(self):
        src = FBIC3Source(_make_config())
        assert src.parse("") == []

    @patch("regulatory.sources.fbi_ic3.requests.get")
    def test_fetch_downloads_html(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = FBI_IC3_HTML
        mock_get.return_value = mock_resp

        src = FBIC3Source(_make_config({"url": "https://test.gov"}))
        result = src.fetch()

        mock_get.assert_called_once()
        assert result == FBI_IC3_HTML
