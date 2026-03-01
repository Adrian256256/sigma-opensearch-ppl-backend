# Tests

Test suite for OpenSearch PPL backend validation.

## Test Suites

### `custom_attribute_testing/` (12 tests)
Tests custom attributes in Sigma YAML rules:
- Custom index patterns (`opensearch_ppl_index`)
- Time filters (`opensearch_ppl_min_time`, `opensearch_ppl_max_time`)
- Correlation rules (event_count, value_count, temporal)
- Mixed time filters (correlation + detection level)

### `option_testing/` (11 tests)
Tests backend initialization options:
- `custom_logsource`: Override index patterns
- `min_time` / `max_time`: Global time filters
- Regular detection rules with backend options
- Correlation rules with backend options

### `correlation_testing/`
Tests correlation rule conversion with various correlation types.

### `automated_tests/`
Automated validation suite for PPL syntax correctness.

## Running Tests

```bash
# Run test checker (compares output vs refs)
python tests/custom_attribute_testing/test_checker.py
python tests/option_testing/test_checker.py

# Validate PPL syntax in OpenSearch (requires local OpenSearch on port 9200)
python tests/custom_attribute_testing/validate_refs_in_opensearch.py
python tests/option_testing/validate_refs_in_opensearch.py
```

## Test Results

All **23 test queries** have valid PPL syntax (validated against OpenSearch 3.4+).
