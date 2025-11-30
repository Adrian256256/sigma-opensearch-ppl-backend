# Test Suite for Sigma to OpenSearch PPL Backend

This directory contains a comprehensive test suite for verifying the conversion of Sigma rules into PPL queries for OpenSearch.

## Overview

The test suite ensures that:
- Sigma rules are correctly converted to valid PPL queries
- All operators and modifiers are properly handled
- Edge cases are covered
- The generated PPL queries have correct syntax and structure

## Directory Structure

```
tests/
├── __init__.py
├── test_sigma_to_ppl.py              # Main conversion tests
├── test_rules/                       # Example Sigma rules for testing
│   ├── __init__.py
│   ├── simple_rule.yml               # Simple single-condition rule
│   ├── complex_rule.yml              # Multi-condition rule with logic
│   ├── wildcard_rule.yml             # Rule with wildcard patterns
│   └── numeric_comparison_rule.yml   # Rule with numeric operators
└── README.md                         # This file
```

## Test Categories

### 1. Supported Features Tests (`TestSigmaToPPLConversion`) ✅

These tests verify the fundamental conversion functionality that **works correctly**:

#### Simple Rule Conversion
- **`test_simple_rule_conversion`**: Converts a basic Sigma rule with a single condition
- **`test_complex_rule_conversion`**: Converts rules with multiple conditions and selections
- **`test_multiple_rules_conversion`**: Processes multiple rules in a single collection

#### Operator and Condition Tests
- **`test_condition_operators`**: Verifies logical operators (AND, OR, NOT)
- **`test_wildcard_rule_conversion`**: Tests wildcard pattern handling (* and ?)
- **`test_numeric_comparison_rule_conversion`**: Tests numeric comparison operators (gt, lt, gte, lte)

#### Validation Tests
- **`test_ppl_query_structure`**: Validates the overall structure of generated PPL queries
- **`test_field_mapping`**: Checks correct mapping of Sigma fields to PPL fields
- **`test_empty_collection`**: Handles empty Sigma collections gracefully
- **`test_all_rules_in_directory`**: Tests all YAML files in test_rules/

### 2. PPL Query Validation Tests (`TestPPLQueryValidation`) ✅

- **`test_ppl_syntax_validity`**: Ensures generated queries have valid PPL syntax (balanced parentheses, etc.)
- **`test_ppl_escaping`**: Verifies proper escaping of special characters

### 3. **NEW:** Unsupported Features Tests (`TestUnsupportedFeatures`) ❌

These tests document **known limitations** of the backend. They are marked with `@pytest.mark.xfail` to indicate expected failures.

#### ❌ Features NOT Supported (XFAIL)

1. **`test_aggregation_count`** - Aggregation with count() operations
   - Cannot generate `stats count()` commands
   - Threshold detection not available

2. **`test_aggregation_group_by`** - Aggregation with GROUP BY
   - Group by operations not implemented
   - Cannot generate `stats ... by field` commands

3. **`test_correlation_rule`** - Correlation between multiple events
   - Event correlation not supported
   - Temporal ordering (`followed by`) not available

4. **`test_timeframe_filtering`** - Time-based filtering
   - Timeframe constraints not converted
   - `@timestamp` filtering not generated

5. **`test_field_transformation`** - Field transformations with eval
   - Cannot generate `eval` commands
   - base64, urldecode modifiers may not work

6. **`test_near_proximity_search`** - Proximity/NEAR modifier
   - Near modifier not implemented
   - Proximity patterns not generated

7. **`test_field_alias_lookup`** - External lookups and aliases
   - External lookups not supported
   - CSV/database enrichment not available

#### ⚠️  Features with Partial Support (XPASS)

8. **`test_complex_negation`** - Complex NOT conditions
   - Simple NOT works fine
   - Complex multi-value NOT **surprisingly works** (XPASS)
   - May need more testing for edge cases

9. **`test_regex_modifier`** - Regular expression modifiers
   - Basic regex **appears to work** (XPASS)
   - Complex patterns may have issues
   - Needs more comprehensive testing

10. **`test_cidr_notation`** - CIDR notation for IP ranges
    - Test **passes unexpectedly** (XPASS)
    - May not generate correct CIDR logic
    - Needs investigation

#### Edge Case Tests
- **`test_empty_collection`**: Handles empty Sigma rule collections gracefully
- Additional edge cases as needed

### 2. Test Rules (`test_rules/`)

Example Sigma rules used for testing different scenarios:

#### `simple_rule.yml`
Basic rule with a single selection condition. Used to test fundamental conversion logic.

```yaml
title: Simple Process Detection
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
```

#### `complex_rule.yml`
Advanced rule with multiple selections and logical operators. Tests complex condition handling.

```yaml
title: Complex Detection Rule
detection:
    selection1:
        EventID: 1
    selection2:
        Image|endswith: '.exe'
    condition: selection1 and selection2
```

#### `wildcard_rule.yml`
Rule testing wildcard pattern conversion (* and ? operators).

```yaml
title: Wildcard Pattern Test
detection:
    selection:
        CommandLine|contains: '*suspicious*'
    condition: selection
```

#### `numeric_comparison_rule.yml`
Rule testing numeric comparison operators (greater than, less than, etc.).

```yaml
title: Numeric Comparison Test
detection:
    selection:
        Count|gt: 10
    condition: selection
```

## Running Tests

### Run All Tests

```bash
pytest tests/
```

### Run with Verbose Output

```bash
pytest tests/ -v
```

### Run a Specific Test

```bash
pytest tests/test_sigma_to_ppl.py::TestSigmaToPPLConversion::test_simple_rule_conversion
```

### Run a Specific Test File

```bash
pytest tests/test_sigma_to_ppl.py
```

### Run Tests with Coverage

```bash
pytest tests/ --cov=sigma_backend --cov-report=html
```

This generates an HTML coverage report in `htmlcov/index.html`.

### Run Tests in Parallel (faster)

```bash
pytest tests/ -n auto
```

Requires `pytest-xdist` package.

## Test Verification Criteria

The test suite verifies the following aspects of the conversion:

### 1. Correct Conversion
- Sigma rules are accurately converted into valid PPL queries
- All rule elements (selections, conditions, keywords) are processed
- Multiple rules in a collection are handled correctly

### 2. PPL Structure
- Generated queries follow PPL syntax (`source=... | where ...`)
- Proper use of pipe operators for chaining commands
- Correct query structure for OpenSearch compatibility

### 3. Valid Syntax
- Balanced parentheses and brackets
- Proper quoting of string values
- Correct operator syntax (AND, OR, NOT, etc.)
- Valid field references

### 4. Field Mapping
- Sigma field names are correctly mapped to OpenSearch/PPL fields
- Custom field mappings are applied when configured
- Field modifiers (contains, endswith, etc.) are converted properly

### 5. Logical Operators
- AND operators connect conditions correctly
- OR operators create proper alternatives
- NOT operators negate conditions appropriately
- Complex nested conditions are handled

### 6. Wildcards
- `*` (any characters) is converted to PPL wildcard syntax
- `?` (single character) is properly handled
- Wildcard positions (start, middle, end) work correctly

### 7. Numeric Comparisons
- `gt` (greater than) → `>`
- `lt` (less than) → `<`
- `gte` (greater than or equal) → `>=`
- `lte` (less than or equal) → `<=`

### 8. Edge Cases
- Empty collections return empty strings or appropriate defaults
- Null values are handled gracefully
- Invalid rules produce meaningful error messages

## Adding New Tests

### Step-by-Step Guide

1. **Create or use a test Sigma rule** (optional)
   
   Add a new YAML file to `test_rules/` if you need a specific test case:
   
   ```yaml
   # test_rules/my_new_rule.yml
   title: My New Test Rule
   detection:
       selection:
           FieldName: 'value'
       condition: selection
   ```

2. **Write the test function**
   
   Add a new test to `test_sigma_to_ppl.py`:
   
   ```python
   def test_my_new_feature():
       # Arrange
       backend = OpenSearchPPLBackend()
       sigma_rule = {...}  # Your rule definition
       collection = SigmaCollection.from_yaml(sigma_rule)
       
       # Act
       result = backend.convert(collection)
       
       # Assert
       assert "expected_output" in result
       assert result  # Not empty
   ```

3. **Run your test**
   
   ```bash
   pytest tests/test_sigma_to_ppl.py::test_my_new_feature -v
   ```

4. **Verify it works**
   
   Ensure the test passes and covers the intended functionality.

### Best Practices for Writing Tests

- **Use descriptive names**: `test_wildcard_at_end_of_string` is better than `test_wildcard1`
- **Follow AAA pattern**: Arrange, Act, Assert
- **Test one thing**: Each test should verify a single behavior
- **Use assertions effectively**: Check both positive and negative cases
- **Add comments**: Explain why the test exists, especially for edge cases
- **Keep tests independent**: Tests should not depend on each other

### Example Test Structure

```python
def test_feature_name():
    """
    Test description: What this test verifies and why.
    """
    # Arrange: Set up test data
    backend = OpenSearchPPLBackend()
    sigma_rule = {
        'title': 'Test Rule',
        'detection': {
            'selection': {'field': 'value'},
            'condition': 'selection'
        }
    }
    
    # Act: Perform the action
    result = backend.convert(SigmaCollection.from_yaml(sigma_rule))
    
    # Assert: Verify the results
    assert result is not None
    assert 'expected_pattern' in result
    assert result.count('|') >= 1  # Has pipe operators
```

## Test Dependencies

The test suite requires:

- **pytest** - Testing framework
- **pysigma** - Sigma rule processing library
- **pyyaml** - YAML file parsing
- **sigma_backend** - The backend implementation being tested

Optional but recommended:
- **pytest-cov** - Code coverage reporting
- **pytest-xdist** - Parallel test execution

## Continuous Integration

These tests should be run:
- Before committing code
- In CI/CD pipeline on every push
- Before merging pull requests
- On a schedule to catch regressions

## Troubleshooting

### Tests Fail After Changes

1. Check if the backend implementation changed
2. Verify Sigma rule format is correct
3. Review error messages for specifics
4. Run individual tests to isolate the issue

### Import Errors

Make sure you're running tests from the project root:
```bash
cd /path/to/sigma-opensearch-ppl-backend
pytest tests/
```

### Coverage Not Generated

Install pytest-cov:
```bash
pip install pytest-cov
```

## Future Test Additions

Planned test categories to add:

- [ ] Performance tests for large rule sets
- [ ] Integration tests with real OpenSearch instance
- [ ] Fuzzing tests for robustness
- [ ] Regression tests for known bugs
- [ ] Benchmark tests for conversion speed

---

For more information about the project, see the [main README](../README.md).