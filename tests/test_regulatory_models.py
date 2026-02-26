"""
test_regulatory_models.py — Tests for regulatory alert models and config loading.

Covers: RegulatoryAlert dataclass creation, CSV serialization,
YAML config loading, and error handling for missing config files.
"""

import tempfile
from datetime import date
from pathlib import Path

import pytest
import yaml

# Add scripts dir to path for imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.models import RegulatoryAlert, CSV_COLUMNS, load_source_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_alert():
    """Create a sample RegulatoryAlert for testing."""
    return RegulatoryAlert(
        source="fincen",
        alert_id="FIN-2026-A001",
        title="Advisory on Fraud Involving Synthetic Identities",
        date=date(2026, 2, 15),
        category="synthetic-identity",
        mapped_tp_ids=["TP-0012", "TP-0034"],
        url="https://www.fincen.gov/news/advisories/2026-A001",
        severity="high",
        summary="FinCEN advisory on rising synthetic identity fraud.",
    )


@pytest.fixture
def single_tp_alert():
    """Alert with a single mapped TP ID."""
    return RegulatoryAlert(
        source="cfpb",
        alert_id="CFPB-2026-001",
        title="Supervisory Highlights on Elder Fraud",
        date=date(2026, 1, 10),
        category="elder-fraud",
        mapped_tp_ids=["TP-0005"],
        url="https://www.consumerfinance.gov/highlights/2026-001",
        severity="medium",
        summary="CFPB report on elder fraud trends.",
    )


@pytest.fixture
def no_tp_alert():
    """Alert with no mapped TP IDs."""
    return RegulatoryAlert(
        source="sec",
        alert_id="SEC-2026-LR001",
        title="SEC Litigation Release on Ponzi Scheme",
        date=date(2026, 3, 1),
        category="investment-fraud",
        mapped_tp_ids=[],
        url="https://www.sec.gov/litigation/lr/2026-001",
        severity="low",
        summary="SEC action against Ponzi scheme operator.",
    )


@pytest.fixture
def valid_config_file(tmp_path):
    """Create a temporary valid YAML config file."""
    config = {
        "sources": {
            "fincen": {
                "enabled": True,
                "url": "https://www.fincen.gov/news/advisories",
                "category_mapping": {
                    "synthetic-identity": ["TP-0012", "TP-0034"],
                    "money-laundering": ["TP-0001"],
                },
            },
            "cfpb": {
                "enabled": False,
                "feed_url": "https://www.consumerfinance.gov/feed/",
                "category_mapping": {
                    "elder-fraud": ["TP-0005"],
                },
            },
        }
    }
    fp = tmp_path / "test_sources.yaml"
    fp.write_text(yaml.dump(config, default_flow_style=False), encoding="utf-8")
    return fp


# ---------------------------------------------------------------------------
# RegulatoryAlert creation tests
# ---------------------------------------------------------------------------

class TestRegulatoryAlertCreation:
    def test_alert_fields(self, sample_alert):
        """All fields should be accessible on the dataclass instance."""
        assert sample_alert.source == "fincen"
        assert sample_alert.alert_id == "FIN-2026-A001"
        assert sample_alert.title == "Advisory on Fraud Involving Synthetic Identities"
        assert sample_alert.date == date(2026, 2, 15)
        assert sample_alert.category == "synthetic-identity"
        assert sample_alert.mapped_tp_ids == ["TP-0012", "TP-0034"]
        assert sample_alert.url == "https://www.fincen.gov/news/advisories/2026-A001"
        assert sample_alert.severity == "high"
        assert sample_alert.summary == "FinCEN advisory on rising synthetic identity fraud."

    def test_alert_with_empty_tp_ids(self, no_tp_alert):
        """An alert with no mapped TPs should have an empty list."""
        assert no_tp_alert.mapped_tp_ids == []
        assert no_tp_alert.source == "sec"


# ---------------------------------------------------------------------------
# to_csv_row() serialization tests
# ---------------------------------------------------------------------------

class TestToCsvRow:
    def test_csv_row_multiple_tps(self, sample_alert):
        """Multiple TP IDs should be joined with | delimiter."""
        row = sample_alert.to_csv_row()
        assert isinstance(row, list)
        assert len(row) == len(CSV_COLUMNS)
        # mapped_tp_ids is at index 5
        tp_field = row[5]
        assert tp_field == "TP-0012|TP-0034"

    def test_csv_row_single_tp(self, single_tp_alert):
        """A single TP ID should appear without delimiter."""
        row = single_tp_alert.to_csv_row()
        tp_field = row[5]
        assert tp_field == "TP-0005"
        assert "|" not in tp_field

    def test_csv_row_no_tps(self, no_tp_alert):
        """An alert with no TPs should have empty string for tp field."""
        row = no_tp_alert.to_csv_row()
        tp_field = row[5]
        assert tp_field == ""

    def test_csv_row_field_order(self, sample_alert):
        """CSV row fields should match CSV_COLUMNS order."""
        row = sample_alert.to_csv_row()
        assert row[0] == "fincen"                    # source
        assert row[1] == "FIN-2026-A001"              # alert_id
        assert row[2] == "Advisory on Fraud Involving Synthetic Identities"  # title
        assert row[3] == "2026-02-15"                 # date (ISO format string)
        assert row[4] == "synthetic-identity"         # category
        assert row[5] == "TP-0012|TP-0034"            # mapped_tp_ids
        assert row[6] == "https://www.fincen.gov/news/advisories/2026-A001"  # url
        assert row[7] == "high"                       # severity
        assert row[8] == "FinCEN advisory on rising synthetic identity fraud."  # summary

    def test_csv_columns_list(self):
        """CSV_COLUMNS should contain all expected column names."""
        expected = [
            "source", "alert_id", "title", "date", "category",
            "mapped_tp_ids", "url", "severity", "summary",
        ]
        assert CSV_COLUMNS == expected


# ---------------------------------------------------------------------------
# load_source_config() tests
# ---------------------------------------------------------------------------

class TestLoadSourceConfig:
    def test_load_valid_config(self, valid_config_file):
        """Loading a valid YAML config should return the parsed dict."""
        config = load_source_config(valid_config_file)
        assert "sources" in config
        assert "fincen" in config["sources"]
        assert config["sources"]["fincen"]["enabled"] is True
        assert config["sources"]["cfpb"]["enabled"] is False
        assert config["sources"]["fincen"]["category_mapping"]["synthetic-identity"] == [
            "TP-0012", "TP-0034"
        ]

    def test_load_missing_file_raises_error(self, tmp_path):
        """Loading a non-existent config file should raise FileNotFoundError."""
        missing = tmp_path / "does_not_exist.yaml"
        with pytest.raises(FileNotFoundError):
            load_source_config(missing)

    def test_load_config_returns_dict(self, valid_config_file):
        """The return value should be a dictionary."""
        config = load_source_config(valid_config_file)
        assert isinstance(config, dict)
