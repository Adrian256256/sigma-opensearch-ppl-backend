# Test Suite for Sigma to OpenSearch PPL Backend

This directory contains tests for verifying the conversion of Sigma rules into PPL queries for OpenSearch.

## Structure

- `test_sigma_to_ppl.py` - Main tests for Sigma -> PPL conversion
- `test_file_based.py` - Tests based on YAML files with Sigma rules
- `test_rules/` - Directory with example Sigma rules for testing
- `conftest.py` - Pytest configuration and fixtures

## Running Tests

To run all tests:

```bash
pytest tests/
```

To run a specific test:

```bash
pytest tests/test_sigma_to_ppl.py::TestSigmaToPPLConversion::test_simple_rule_conversion
```

For detailed output:

```bash
pytest tests/ -v
```

## Test Types

### 1. Basic Conversion Tests
- Simple rule conversion
- Complex rule conversion with multiple conditions
- Keyword rule conversion

### 2. Validation Tests
- PPL structure validation
- Syntax validation
- Special character escaping validation

### 3. Edge Case Tests
- Empty collections
- Rules with wildcards
- Numeric comparisons
- Logical operators (AND, OR)

### 4. File-Based Tests
- Tests loading Sigma rules from YAML files
- Conversion verification for all rules in a directory

## Adding New Tests

To add new tests:

1. Add a Sigma rule to `test_rules/` (optional)
2. Create a new test in one of the test files
3. Use the fixtures from `conftest.py` for backend and rules

## Dependencies

The tests require:
- `pytest`
- `pysigma`
- The backend implemented in `sigma/backends/opensearch_ppl/opensearch_ppl.py`