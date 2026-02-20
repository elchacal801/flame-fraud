"""
test_export_stix.py — Tests for FLAME export_flame_stix.py

Tests detection rule extraction, section parsing, phase mapping,
and deterministic ID generation.
"""

from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from export_flame_stix import (
    extract_detection_section,
    extract_detection_rules,
    map_cfpf_phases,
    deterministic_id,
)


# ---------------------------------------------------------------------------
# extract_detection_section tests
# ---------------------------------------------------------------------------

class TestExtractDetectionSection:
    def test_section_found(self):
        body = """\
## Summary

Summary text.

## Detection Approaches

### Rule 1

```spl
index=main sourcetype=wire_transfer amount>50000
```

## Controls & Mitigations

Some controls.
"""
        section = extract_detection_section(body)
        assert "Rule 1" in section
        assert "index=main" in section
        assert "Controls & Mitigations" not in section

    def test_section_not_found(self):
        body = "## Summary\n\nJust a summary.\n\n## References\n\n- Ref 1"
        section = extract_detection_section(body)
        assert section == ""

    def test_section_at_end_of_body(self):
        body = """\
## Summary

Summary.

## Detection Approaches

```sql
SELECT * FROM transactions WHERE amount > 10000
```
"""
        section = extract_detection_section(body)
        assert "SELECT * FROM transactions" in section


# ---------------------------------------------------------------------------
# extract_detection_rules tests
# ---------------------------------------------------------------------------

class TestExtractDetectionRules:
    def test_spl_rule_extracted(self):
        body = """\
## Detection Approaches

**Suspicious Wire Transfer**

```spl
index=main sourcetype=wire_transfer amount>50000
| stats count by src_user
```

## References
"""
        rules = extract_detection_rules("TP-0001", body)
        assert len(rules) == 1
        assert rules[0]["type"] == "spl"
        assert "index=main" in rules[0]["content"]
        assert rules[0]["title"] == "Suspicious Wire Transfer"

    def test_sql_rule_extracted(self):
        body = """\
## Detection Approaches

### Account Anomaly Query

```sql
SELECT account_id, COUNT(*) as txn_count
FROM transactions
WHERE amount > 10000
GROUP BY account_id
HAVING txn_count > 5
```

## Controls
"""
        rules = extract_detection_rules("TP-0003", body)
        assert len(rules) == 1
        assert rules[0]["type"] == "sql"
        assert "Account Anomaly Query" in rules[0]["title"]

    def test_sigma_rule_extracted(self):
        body = """\
## Detection Approaches

```sigma
title: Bulk Direct Deposit Change
logsource:
    product: hr_portal
detection:
    selection:
        action: direct_deposit_change
    condition: selection
```

## Controls
"""
        rules = extract_detection_rules("TP-0004", body)
        assert len(rules) == 1
        assert rules[0]["type"] == "sigma"

    def test_yaml_normalized_to_sigma(self):
        body = """\
## Detection Approaches

```yaml
title: Test Sigma
detection:
    selection:
        field: value
    condition: selection
```

## Controls
"""
        rules = extract_detection_rules("TP-TEST", body)
        assert len(rules) == 1
        assert rules[0]["type"] == "sigma"

    def test_kql_rule_extracted(self):
        """Verify the kql fix — this was previously silently skipped."""
        body = """\
## Detection Approaches

**Email Rule Detection**

```kql
SecurityAlert
| where AlertName contains "InboxRule"
| where Description contains "wire" or Description contains "closing"
```

## Controls
"""
        rules = extract_detection_rules("TP-0006", body)
        assert len(rules) == 1
        assert rules[0]["type"] == "kql"
        assert "SecurityAlert" in rules[0]["content"]

    def test_pseudocode_extracted_but_typed(self):
        body = """\
## Detection Approaches

```pseudocode
IF new_device AND high_value_action WITHIN 24h THEN ALERT
```

## Controls
"""
        rules = extract_detection_rules("TP-TEST", body)
        assert len(rules) == 1
        assert rules[0]["type"] == "pseudocode"

    def test_untagged_code_blocks_skipped(self):
        """Untagged code blocks (plain ```) should not be extracted."""
        body = """\
## Detection Approaches

```
This is an untagged block that should be skipped
```

## Controls
"""
        rules = extract_detection_rules("TP-TEST", body)
        assert len(rules) == 0

    def test_multiple_rules_extracted(self):
        body = """\
## Detection Approaches

**Rule One**

```spl
index=main sourcetype=auth action=login_failure
```

**Rule Two**

```sql
SELECT * FROM failed_logins WHERE count > 10
```

## Controls
"""
        rules = extract_detection_rules("TP-TEST", body)
        assert len(rules) == 2
        assert rules[0]["type"] == "spl"
        assert rules[1]["type"] == "sql"

    def test_no_detection_section(self):
        body = "## Summary\n\nJust a summary."
        rules = extract_detection_rules("TP-TEST", body)
        assert rules == []

    def test_fallback_title(self):
        """When no title context found, should use fallback."""
        body = """\
## Detection Approaches

```sql
SELECT 1
```

## Controls
"""
        rules = extract_detection_rules("TP-0099", body)
        assert len(rules) == 1
        assert rules[0]["title"] == "TP-0099 detection rule (sql)"


# ---------------------------------------------------------------------------
# map_cfpf_phases tests
# ---------------------------------------------------------------------------

class TestMapCfpfPhases:
    def test_all_phases(self):
        phases = map_cfpf_phases(["P1", "P2", "P3", "P4", "P5"])
        assert len(phases) == 5
        assert phases[0] == {"kill_chain_name": "cfpf", "phase_name": "P1-reconnaissance"}
        assert phases[4] == {"kill_chain_name": "cfpf", "phase_name": "P5-monetization"}

    def test_partial_phases(self):
        phases = map_cfpf_phases(["P2", "P4"])
        assert len(phases) == 2
        assert phases[0]["phase_name"] == "P2-initial-access"
        assert phases[1]["phase_name"] == "P4-execution"

    def test_invalid_phase_skipped(self):
        phases = map_cfpf_phases(["P1", "P99", "P5"])
        assert len(phases) == 2

    def test_empty_phases(self):
        phases = map_cfpf_phases([])
        assert phases == []


# ---------------------------------------------------------------------------
# deterministic_id tests
# ---------------------------------------------------------------------------

class TestDeterministicId:
    def test_idempotent(self):
        """Same inputs should produce same output."""
        id1 = deterministic_id("attack-pattern", "flame-TP-0001")
        id2 = deterministic_id("attack-pattern", "flame-TP-0001")
        assert id1 == id2

    def test_different_seeds_different_ids(self):
        id1 = deterministic_id("attack-pattern", "flame-TP-0001")
        id2 = deterministic_id("attack-pattern", "flame-TP-0002")
        assert id1 != id2

    def test_format(self):
        result = deterministic_id("attack-pattern", "test-seed")
        assert result.startswith("attack-pattern--")
        # UUID format: 8-4-4-4-12 hex chars
        uuid_part = result.split("--")[1]
        assert len(uuid_part) == 36
