# Sigma Correlation Rules Testing

Automated testing for Sigma correlation rules conversion to OpenSearch PPL queries.

## Test Status

- Conversion: 8/8 passed
- Validation: 8/8 passed

## Usage

```bash
python tests/correlation_testing/test_correlations.py
```

## Directory Structure

```
correlation_testing/
├── test_correlations.py    # Automated testing script
├── sigma_rules/             # Correlation rule definitions (YAML)
├── ppl_refs/                # Reference PPL queries (for validation)
└── out/                     # Generated PPL queries (auto-created)
```

## Correlation Types

### 1. event_count
Counts events in time window.``

### 2. value_count
Counts distinct field values using HyperLogLog++.

### 3. temporal
Multiple event types close in time (any order).

### 4. temporal_ordered
Events in specific order (uses same implementation as temporal).

## Implemented Rules

| Rule | Type | Timespan | MITRE ATT&CK |
|------|------|----------|--------------|
| brute_force_detection | event_count | 5m | T1110 |
| password_spraying | value_count | 30m | T1110.003 |
| privileged_group_enumeration | value_count | 15m | T1087 |
| successful_brute_force | temporal | 10m | T1110 |
| account_manipulation | temporal | 5m | T1136, T1098 |
| data_exfiltration | temporal | 10m | T1041, T1048 |
| lateral_movement_detection | temporal | 2m | T1021, T1569 |
| suspicious_network_connection | temporal | 60s | T1059, T1071 |

## References

- [Sigma Correlations Spec](https://sigmahq.io/docs/meta/correlations.html)
- [OpenSearch PPL Commands](https://github.com/opensearch-project/sql/tree/main/docs/user/ppl/cmd)
- [Multisearch Command](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/multisearch.md)
