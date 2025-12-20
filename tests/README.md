# Tests

This directory contains comprehensive test suites for the Sigma to OpenSearch PPL backend converter. The tests validate rule conversion, field mapping, logical operations, modifiers and special features.

## Directory Structure

### `automated_tests/`
**Automated test suite** for verifying the backend conversion functionality.

- **Purpose**: Validates that Sigma rules are correctly converted to OpenSearch PPL queries
- **Test Files**: `test_checker.py` - pytest-based automated tests
- **Structure**:
  - `rules/` - Sigma rule files (`.yml`)
  - `refs/` - Expected OpenSearch PPL queries (`.txt`)
- **Coverage**:
  - Basic detection rules
  - Wildcard patterns and modifiers
  - String modifiers (base64, windash, cased, etc.)
  - Field operations (exists, fieldref)
  - Numeric comparisons (gt, gte, lt, lte)
  - Logical operators (AND, OR, NOT, nested conditions)
  - Special features and edge cases

**Running automated tests**:
```bash
pytest tests/automated_tests/test_checker.py
```

All features documented in the `tables/` directory are verified by these automated tests.

### `correlation_testing/`
**Correlation rules testing** for advanced detection patterns.

- **Purpose**: Test and demonstrate Sigma correlation capabilities
- **Status**: Not yet implemented - correlation backend support
- **Structure**:
  - `sigma_rules/` - Sigma correlation rule files
  - `ppl_refs/` - Expected PPL correlation queries (in development)
- **Correlation Types**:
  - `event_count` - Detect event frequency patterns
  - `value_count` - Count distinct field values
  - `temporal` - Detect events occurring close together
  - `ordered_temporal` - Detect events in specific sequence

### `manual_test/`
**Manual testing utilities** for interactive development and debugging.

- **Purpose**: Quick testing and experimentation during development
- **Scripts**:
  - `test_textquery_backend.py` - Test basic backend conversion
  - `test_ecs_pipeline.py` - Test with ECS field mapping
- **Structure**:
  - `example_rules/` - Sample Sigma rules for testing

**Running manual tests**:
```bash
python tests/manual_test/test_textquery_backend.py
python tests/manual_test/test_ecs_pipeline.py
```

## Running Tests

### Run all automated tests:
```bash
pytest tests/automated_tests/
```

### Run specific test file:
```bash
pytest tests/automated_tests/test_checker.py
```

### Run with verbose output:
```bash
pytest tests/automated_tests/ -v
```

### Run manual tests:
```bash
python tests/manual_test/test_textquery_backend.py
python tests/manual_test/test_ecs_pipeline.py
```