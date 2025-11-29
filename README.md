# Sigma to OpenSearch PPL Backend

Backend for converting Sigma rules into PPL (Piped Processing Language) queries for OpenSearch.

## Description

This project provides a backend for the pySigma library that converts Sigma detection rules into PPL queries optimized for OpenSearch. PPL is a data processing language that enables complex and efficient queries on data indexed in OpenSearch.

## Project Structure

```
sigma-opensearch-ppl-backend/
├── sigma_backend/
│   ├── __init__.py
│   └── backends/
│       ├── __init__.py
│       └── opensearch_ppl/
│           ├── __init__.py
│           └── opensearch_ppl.py          # Backend implementation
├── tests/
│   ├── __init__.py
│   ├── test_sigma_to_ppl.py              # Main conversion tests
│   ├── test_rules/                       # Test Sigma rules
│   │   ├── __init__.py
│   │   ├── simple_rule.yml
│   │   ├── complex_rule.yml
│   │   ├── wildcard_rule.yml
│   │   └── numeric_comparison_rule.yml
│   └── README.md                         # Test documentation
├── .gitignore                            # Files ignored by Git
├── pytest.ini                            # Pytest configuration
├── requirements.txt                      # Python dependencies
└── README.md                             # Project documentation
```

## Installation

### Dependencies

Install required dependencies:

```bash
pip install -r requirements.txt
```

Main dependencies:
- `pysigma` - Library for processing Sigma rules
- `pytest` - Testing framework
- `pyyaml` - YAML file parsing

## Tests

The project includes a comprehensive test suite for verifying correct conversion of Sigma rules into PPL queries.

### Test Structure

#### 1. Main Tests (`test_sigma_to_ppl.py`)

Tests for basic conversion and complex cases:

- **Basic conversion tests:**
  - `test_simple_rule_conversion` - Simple rule conversion
  - `test_complex_rule_conversion` - Rules with multiple conditions
  - `test_rule_with_keywords` - Rules with keywords
  - `test_multiple_rules_conversion` - Converting multiple rules simultaneously

- **Tests for operators and conditions:**
  - `test_condition_operators` - Testing logical operators (AND, OR)
  - `test_wildcard_values` - Testing wildcard patterns
  - `test_numeric_comparisons` - Testing numeric comparisons (gt, lt, etc.)

- **Validation tests:**
  - `test_ppl_query_structure` - PPL structure validation
  - `test_ppl_syntax_validity` - PPL syntax validation
  - `test_ppl_escaping` - Special character escaping validation
  - `test_field_mapping` - Field mapping verification

- **Edge case tests:**
  - `test_empty_collection` - Handling empty collections

#### 2. Test Rules (`test_rules/`)

The directory contains example Sigma rules for testing:

- **simple_rule.yml** - Simple rule with a single condition
- **complex_rule.yml** - Complex rule with multiple selections and logical operators
- **wildcard_rule.yml** - Rule testing wildcard patterns
- **numeric_comparison_rule.yml** - Rule with numeric comparisons

### Running Tests

#### Run all tests:

```bash
pytest tests/
```

#### Run with detailed output:

```bash
pytest tests/ -v
```

#### Run a specific test:

```bash
pytest tests/test_sigma_to_ppl.py::TestSigmaToPPLConversion::test_simple_rule_conversion
```

#### Run tests with coverage:

```bash
pytest tests/ --cov=sigma --cov-report=html
```

### What Tests Verify

The tests verify the following aspects:

1. **Correct conversion:** Sigma rules are converted into valid PPL queries
2. **PPL structure:** Generated queries have the correct structure for OpenSearch
3. **Valid syntax:** PPL queries have correct syntax (balanced parentheses, etc.)
4. **Field mapping:** Fields from Sigma rules are correctly mapped to PPL
5. **Logical operators:** AND, OR operators are converted correctly
6. **Wildcards:** Wildcard patterns are processed correctly
7. **Numeric comparisons:** Comparison operators (gt, lt, etc.) work correctly
8. **Edge cases:** Proper handling of edge cases (empty collections, etc.)

## Usage

### Backend usage example:

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl import OpenSearchPPLBackend

# Load a Sigma rule
with open('rule.yml', 'r') as f:
    sigma_collection = SigmaCollection.from_yaml(f.read())

# Create the backend
backend = OpenSearchPPLBackend()

# Convert to PPL
ppl_query = backend.convert(sigma_collection)

print(ppl_query)
```

## Development

### Adding New Tests

To add new tests:

1. Add a Sigma rule to `tests/test_rules/` (optional)
2. Create a new test in `tests/test_sigma_to_ppl.py`
3. Use the backend for conversion and verify the result

## Status

- ✅ Project structure
- ✅ Complete test suite
- ✅ Example Sigma rules
- ✅ Pytest configuration
- ⏳ Backend implementation (in development)


