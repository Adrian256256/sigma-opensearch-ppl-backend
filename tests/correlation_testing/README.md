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
Counts events in time window.

**PPL**:
```ppl
source=index-* | where conditions AND @timestamp >= now() - timespan 
| stats count() as event_count by fields 
| where event_count >= threshold
```

### 2. value_count
Counts distinct field values using HyperLogLog++.

**PPL**:
```ppl
source=index-* | where conditions AND @timestamp >= now() - timespan 
| stats dc(field) as value_count by fields 
| where value_count >= threshold
```

### 3. temporal
Multiple event types close in time (any order).

**PPL**:
```ppl
| multisearch 
  [search source=index1-* | where conditions1 AND @timestamp >= now() - timespan] 
  [search source=index2-* | where conditions2 AND @timestamp >= now() - timespan]
| stats count() as event_count by fields 
| where event_count >= threshold
```

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

## OpenSearch PPL Syntax

### Multisearch Command

**Correct**:
```ppl
| multisearch [search source=... | where ...] [search source=... | where ...]
```

- Each subsearch in square brackets
- Start with `search` keyword
- No commas between subsearches

### Time Filters

Must be in WHERE clause before aggregation.

**Correct**:
```ppl
source=index-* | where EventID=4625 AND @timestamp >= now() - 5m | stats count()
```

**Incorrect**:
```ppl
source=index-* | where EventID=4625 | stats count() | where @timestamp >= now() - 5m
```

### Time Format

Natural units: `5m`, `30m`, `2h`, `60s`

## Adding New Rules

1. Create YAML file in `sigma_rules/` with base rules and correlation rule
2. Create reference query in `ppl_refs/<rule_name>.txt`
3. Run `python tests/correlation_testing/test_correlations.py`
4. Verify conversion and validation pass

## References

- [Sigma Correlations Spec](https://sigmahq.io/docs/meta/correlations.html)
- [OpenSearch PPL Commands](https://github.com/opensearch-project/sql/tree/main/docs/user/ppl/cmd)
- [Multisearch Command](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/multisearch.md)
