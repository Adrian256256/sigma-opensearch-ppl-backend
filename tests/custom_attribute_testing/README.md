# Custom Attributes Testing

This folder contains tests for the **custom attributes** feature in the OpenSearch PPL backend.

## Overview

Custom attributes allow users to configure backend behavior directly in Sigma rule YAML files, without needing to pass options through CLI or API. This feature is inspired by [pySigma-backend-loki](https://github.com/grafana/pySigma-backend-loki/blob/main/sigma/backends/loki/loki.py#L343-L347).

## Files

### `test_custom_attributes.py`

Comprehensive test suite that validates the custom attributes functionality:

**Test Coverage:**
- `test_custom_index_attribute()` - Verifies custom index pattern override
- `test_custom_time_field_attribute()` - Tests custom timestamp field configuration
- `test_custom_min_max_time_attributes()` - Validates time range filters
- `test_custom_attributes_priority_over_backend_options()` - Ensures YAML attributes take precedence over CLI options
- `test_all_custom_attributes_together()` - Tests all attributes working simultaneously
- `test_no_custom_attributes_uses_defaults()` - Confirms default behavior when no custom attributes are set
- `test_partial_custom_attributes()` - Validates partial configuration scenarios

**Run Tests:**
```bash
# Using pytest
pytest tests/custom_attribute_testing/test_custom_attributes.py -v

# Run manually (includes verbose output)
python tests/custom_attribute_testing/test_custom_attributes.py
```

### `custom_attributes_example.yml`

Example Sigma rule demonstrating all available custom attributes:

```yaml
custom:
  opensearch_ppl_index: "my-custom-index-*"
  opensearch_ppl_time_field: "event.created"
  opensearch_ppl_min_time: "-30d"
  opensearch_ppl_max_time: "now"
```

## Supported Custom Attributes

| Attribute | Description | Priority |
|-----------|-------------|----------|
| `opensearch_ppl_index` | Override index pattern | YAML > Backend option > Logsource mapping |
| `opensearch_ppl_time_field` | Specify timestamp field | YAML > Default (`@timestamp`) |
| `opensearch_ppl_min_time` | Minimum time filter | YAML > Backend option |
| `opensearch_ppl_max_time` | Maximum time filter | YAML > Backend option |

## Example Usage

**Sigma Rule with Custom Attributes:**
```yaml
title: Suspicious PowerShell Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
custom:
  opensearch_ppl_index: "windows-security-*"
  opensearch_ppl_min_time: "-7d"
```

**Generated Query:**
```
source=windows-security-* | where LIKE(Image, %\powershell.exe) AND (@timestamp >= now() - 7d)
```

## Testing Strategy

The test suite follows a comprehensive approach:

1. **Individual Feature Tests** - Each custom attribute tested in isolation
2. **Priority Tests** - Verifies custom attributes override backend options
3. **Integration Tests** - All attributes working together
4. **Default Behavior Tests** - Ensures backward compatibility
5. **Edge Cases** - Partial configurations and mixed settings

## Expected Behavior

**Priority System:**
1. Custom attributes in rule YAML (highest)
2. Backend options (CLI/API parameters)
3. Default values (lowest)

**Backward Compatibility:**
- Rules without custom attributes work as before
- Backend options still function when custom attributes are not set
- Default logsource mapping applies when neither custom attribute nor backend option is provided

## Documentation

For complete documentation on custom attributes, see:
- **Backend README**: `sigma_backend/backends/opensearch_ppl/README.md` (Custom Attributes section)
- **Main README**: `README.md` (mentions custom attributes in features)

## Related Implementation

**Core Implementation Files:**
- `sigma_backend/backends/opensearch_ppl/opensearch_ppl.py`:
  - `OpenSearchPPLCustomAttributes` enum
  - `_get_index_pattern()` method
  - `_get_time_field()` method
  - `_get_min_time()` method
  - `_get_max_time()` method
