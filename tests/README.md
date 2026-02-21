# Tests

This directory contains comprehensive test suites for the Sigma to OpenSearch PPL backend converter. The tests validate rule conversion, field mapping, logical operations, modifiers, special features, and custom attributes.

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
- **Test Script**: `test_correlations.py` - Correlation rules test suite
- **Structure**:
  - `sigma_rules/` - Sigma correlation rule files
  - `ppl_refs/` - Expected PPL correlation queries
- **Correlation Types**:
  - `event_count` - Detect event frequency patterns
  - `value_count` - Count distinct field values
  - `temporal` - Detect events occurring close together
  - `temporal_ordered` - Detect events in specific sequence

**Running correlation tests**:
```bash
./tests/correlation_testing/test_correlations.py
```

**See [correlation_testing/README.md](correlation_testing/README.md) for detailed documentation.**

### `custom_attribute_testing/`
**Custom attributes testing** for per-rule backend configuration.

- **Purpose**: Test custom attributes feature that allows configuring backend behavior directly in Sigma rule YAML
- **Test Script**: `test_custom_attributes.py` - Custom attributes test suite
- **Structure**:
  - `custom_attributes_example.yml` - Example rule with all custom attributes
- **Features Tested**:
  - `opensearch_ppl_index` - Override index pattern per rule
  - `opensearch_ppl_time_field` - Custom timestamp field per rule
  - `opensearch_ppl_min_time` - Minimum time filter per rule
  - `opensearch_ppl_max_time` - Maximum time filter per rule
- **Test Coverage**:
  - Individual attribute validation
  - Priority system (YAML > Backend options > Defaults)
  - Integration of multiple attributes
  - Backward compatibility

**Running custom attribute tests**:
```bash
# Using pytest
pytest tests/custom_attribute_testing/test_custom_attributes.py -v

# Manual run with detailed output
python tests/custom_attribute_testing/test_custom_attributes.py
```

**See [custom_attribute_testing/README.md](custom_attribute_testing/README.md) for detailed documentation.**

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

### `option_testing/`
**Backend options testing** for customizable query generation.

- **Purpose**: Test and demonstrate backend-specific options (similar to Splunk's `-O` flag)
- **Test Script**: `test_backend_options.py` - Comprehensive backend options test suite
- **Features Tested**:
  - `custom_logsource` - Override auto-generated index patterns
- **Use Cases**:
  - Custom index naming conventions
  - Non-standard timestamp fields
  - Multi-tenancy scenarios

**Running option tests**:
```bash
python tests/option_testing/test_backend_options.py
```

**See [option_testing/README.md](option_testing/README.md) for detailed documentation.**

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

### Run correlation tests:
```bash
./tests/correlation_testing/test_correlations.py
```

### Run custom attribute tests:
```bash
pytest tests/custom_attribute_testing/test_custom_attributes.py -v
```

### Run manual tests:
```bash
python tests/manual_test/test_textquery_backend.py
python tests/manual_test/test_ecs_pipeline.py
```