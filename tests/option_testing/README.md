# Backend Options Testing

This directory contains tests for backend-specific options functionality in the OpenSearch PPL backend.

## Overview

Backend options allow you to customize query generation behavior without modifying the Sigma rules themselves. This is similar to how Splunk backend handles options via `-O` or `--backend-option` parameters.

## Available Backend Options

### `custom_logsource`

Override the automatically generated index pattern with a custom one.

**Use Cases:**
- Your OpenSearch indices don't follow the standard naming convention
- You want to search across multiple index patterns
- Testing queries against specific indices
- Multi-tenant deployments

**Example:**
```python
backend = OpenSearchPPLBackend(custom_logsource="my-custom-logs-*")
```

**Default Behavior (without option):**
- Automatically generates index pattern from logsource fields
- Format: `{product}-{category}-{service}-*`
- Example: `windows-process_creation-*`

## Running Tests

### Quick Test

```bash
# From project root
cd tests/option_testing
python3 test_backend_options.py
```

### With Virtual Environment

```bash
# Activate venv first
source ../../.venv/bin/activate

# Run tests
python3 test_backend_options.py
```

## Test Coverage

The test script (`test_backend_options.py`) includes 3 test cases:

### Test 1: Default Logsource
Tests automatic index pattern generation from logsource fields.

**Input:** Rule with `logsource: {product: windows, category: process_creation}`  
**Expected:** `source=windows-process_creation-*`

### Test 2: Custom Logsource Override
Tests overriding the index pattern with `custom_logsource` option.

**Input:** Same rule + `custom_logsource="my-custom-logs-*"`  
**Expected:** `source=my-custom-logs-*`

### Test 3: Multiple Custom Logsources
Tests using different custom logsources with the same rule.

**Demonstrates:** How to generate multiple queries for different indices from one rule.

## Usage Examples

### Programmatic Usage

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend

# Load Sigma rule
collection = SigmaCollection.from_yaml("""
title: Suspicious PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
""")

# Example 1: Default behavior (auto-generate index)
backend = OpenSearchPPLBackend()
query = backend.convert(collection)
# Result: source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe")

# Example 2: Custom logsource
backend = OpenSearchPPLBackend(custom_logsource="my-windows-logs-*")
query = backend.convert(collection)
# Result: source=my-windows-logs-* | where LIKE(Image, "%\\powershell.exe")

# Example 3: Multiple indices (multi-tenant)
for tenant in ["tenant-a", "tenant-b", "tenant-c"]:
    backend = OpenSearchPPLBackend(custom_logsource=f"{tenant}-logs-*")
    query = backend.convert(collection)
    # Generate query for each tenant's index
```

### Command Line Usage (with sigma CLI)

When this backend is registered with the sigma CLI tool:

```bash
# Default behavior
sigma convert -t opensearch-ppl rule.yml

# With custom logsource
sigma convert -t opensearch-ppl -O custom_logsource=my-logs-* rule.yml

# Convert entire directory with custom logsource
sigma convert -t opensearch-ppl \
    -O custom_logsource=production-logs-* \
    -o output/ \
    rules/
```

## Implementation Details

### How It Works

1. **Initialization:** Backend options are passed to `__init__()` as keyword arguments
   ```python
   def __init__(self, processing_pipeline=None, collect_errors=False, **backend_options):
       super().__init__(processing_pipeline, collect_errors=collect_errors, **backend_options)
       self._custom_logsource = backend_options.get("custom_logsource", None)
   ```

2. **Index Pattern Generation:** The `_get_index_pattern()` method checks for custom logsource first
   ```python
   def _get_index_pattern(self, rule):
       # Check if custom logsource provided
       if self._custom_logsource:
           return self._custom_logsource
       
       # Otherwise generate from logsource
       # ... auto-generation logic ...
   ```

3. **Usage:** The custom index pattern is used when building the final PPL query
   ```python
   ppl_query = f"source={index_pattern} | where {query}"
   ```
