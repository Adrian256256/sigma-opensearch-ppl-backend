# Backend Options Testing

This directory contains tests for backend-specific options functionality in the OpenSearch PPL backend.

## Overview

Backend options allow you to customize query generation behavior without modifying the Sigma rules themselves. This is similar to how Splunk backend handles options via `-O` or `--backend-option` parameters.

## Directory Structure

```
option_testing/
├── rules/              # Test Sigma rules (one per test case)
├── refs/               # Expected reference outputs
├── out/                # Actual outputs from test runs
├── test_checker.py     # Automated test runner
└── README.md           # This file
```

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

### `min_time` and `max_time`

Add time filters to queries to restrict the search time window.

**Use Cases:**
- Historical analysis within specific time ranges
- Incident response (search only during incident time window)
- Performance optimization (reduce data scanned)
- Compliance reporting (specific time periods)
- Testing with time-bounded datasets

**Examples:**
```python
# Relative time (last 30 days)
backend = OpenSearchPPLBackend(min_time="-30d", max_time="now")

# Absolute timestamps
backend = OpenSearchPPLBackend(
    min_time="2024-01-01T00:00:00",
    max_time="2024-12-31T23:59:59"
)

# Only minimum time (events after date)
backend = OpenSearchPPLBackend(min_time="-7d")

# Only maximum time (events before date)
backend = OpenSearchPPLBackend(max_time="now")
```

**Time Format Options:**
- **Relative time**: `-30d` (30 days ago), `-7d` (7 days ago), `-24h` (24 hours ago), `-1h` (1 hour ago)
- **Absolute time**: ISO 8601 timestamps like `"2024-01-01T00:00:00"`
- **Current time**: `"now"` for current timestamp

**Default Behavior (without options):**
- No time filters are added to queries
- Searches across all available data

**Query Output:**
```ppl
# Without time filters
source=windows-* | where CommandLine="evil.exe"

# With time filters
source=windows-* | where (CommandLine="evil.exe") AND (@timestamp >= now() - 30d AND @timestamp <= now())
```

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

The test script (`test_backend_options.py`) includes 9 test cases:

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

### Test 4: Default Time Filters
Tests that queries remain unchanged when no time filters are provided.

**Input:** Rule without time options  
**Expected:** No time filters added to query

### Test 5: Relative Time Filters
Tests adding relative time filters (e.g., last 30 days).

**Input:** `min_time="-30d"`, `max_time="now"`  
**Expected:** `(@timestamp >= now() - 30d AND @timestamp <= now())`

### Test 6: Absolute Time Filters
Tests adding absolute timestamp filters.

**Input:** `min_time="2024-01-01T00:00:00"`, `max_time="2024-01-31T23:59:59"`  
**Expected:** Absolute timestamps in query

### Test 7: Only Minimum Time Filter
Tests adding only minimum time constraint.

**Input:** `min_time="-7d"`  
**Expected:** Only `@timestamp >= now() - 7d` filter

### Test 8: Only Maximum Time Filter
Tests adding only maximum time constraint.

**Input:** `max_time="now"`  
**Expected:** Only `@timestamp <= now()` filter

### Test 9: Combined Options
Tests combining custom logsource with time filters.

**Input:** `custom_logsource="security-logs-*"`, `min_time="-24h"`, `max_time="now"`  
**Expected:** Both custom index and time filters applied

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

# Example 3: With time filters (relative)
backend = OpenSearchPPLBackend(min_time="-30d", max_time="now")
query = backend.convert(collection)
# Result: source=windows-process_creation-* | where (LIKE(Image, "%\\powershell.exe")) AND (@timestamp >= now() - 30d AND @timestamp <= now())

# Example 4: With time filters (absolute)
backend = OpenSearchPPLBackend(
    min_time="2024-01-01T00:00:00",
    max_time="2024-12-31T23:59:59"
)
query = backend.convert(collection)
# Result: Time-bounded query with absolute timestamps

# Example 5: Combined options
backend = OpenSearchPPLBackend(
    custom_logsource="security-logs-*",
    min_time="-7d",
    max_time="now"
)
query = backend.convert(collection)
# Result: Custom index + time filters

# Example 6: Multiple indices (multi-tenant)
for tenant in ["tenant-a", "tenant-b", "tenant-c"]:
    backend = OpenSearchPPLBackend(
        custom_logsource=f"{tenant}-logs-*",
        min_time="-24h",
        max_time="now"
    )
    query = backend.convert(collection)
    # Generate query for each tenant's index with time filters
```

