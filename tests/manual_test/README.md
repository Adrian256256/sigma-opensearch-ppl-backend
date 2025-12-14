# Manual Testing Guide

This directory contains tools and utilities for manually testing the Sigma to OpenSearch PPL backend conversion.

## Overview

Manual testing allows you to:
- Quickly test your backend implementation with real Sigma rules
- Verify PPL query generation for specific use cases
- Debug conversion issues interactively
- Experiment with different rule patterns

## Quick Start

### Testing the TextQuery Backend

Run the TextQuery backend testing script:

```bash
python manual_test/test_textquery_backend.py
```

Or with your virtual environment:

```bash
.venv/bin/python manual_test/test_textquery_backend.py
```

### Testing with ECS Field Mapping

Run the ECS pipeline testing script:

```bash
python manual_test/test_ecs_pipeline.py
```

Or with your virtual environment:

```bash
.venv/bin/python manual_test/test_ecs_pipeline.py
```

## Directory Structure

```
manual_test/
├── test_textquery_backend.py         # Testing script for TextQuery backend
├── test_ecs_pipeline.py              # Testing script for ECS field mapping
├── example_rules/                    # Example Sigma rules
└── README.md                         # This file
```

## Testing Scripts

### `test_textquery_backend.py` - TextQuery Backend

Tests the pySigma TextQueryBackend implementation (`opensearch_ppl_textquery.py`).

### `test_ecs_pipeline.py` - ECS Field Mapping

Tests the backend with ECS (Elastic Common Schema) field mapping pipeline enabled.

### Configuration

At the top of the testing script, you'll find configuration variables:

```python
# List of rule files to test
EXAMPLE_RULES_TO_TEST = [
    "powershell_suspicious.yml",
    "network_suspicious.yml",
]

# Set to True to test ALL rules in example_rules/
TEST_ALL_EXAMPLE_RULES = False
```

### How It Works

1. **Loads Sigma rules** from the `example_rules/` directory
2. **Converts each rule** using the OpenSearch PPL backend
3. **Displays the output** including:
   - Rule name and content
   - Generated PPL query
   - Any errors that occur

### Testing Specific Rules

Edit the `EXAMPLE_RULES_TO_TEST` list:

```python
EXAMPLE_RULES_TO_TEST = [
    "my_rule.yml",
    "another_rule.yml",
]
```

Then run:

```bash
.venv/bin/python manual_test/test_textquery_backend.py
```

### Testing All Rules

Set the flag to `True`:

```python
TEST_ALL_EXAMPLE_RULES = True
```

This will automatically discover and test all `.yml` files in `example_rules/`.

## Adding Your Own Rules

1. **Create a new YAML file** in `example_rules/`:

```bash
touch manual_test/example_rules/my_custom_rule.yml
```

2. **Write your Sigma rule**:

```yaml
title: My Custom Detection Rule
status: test
description: Testing custom detection logic
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\suspicious.exe'
        CommandLine|contains: 'malicious'
    condition: selection
```

3. **Add it to the test list** in the testing script:

```python
EXAMPLE_RULES_TO_TEST = [
    "powershell_suspicious.yml",
    "network_suspicious.yml",
    "my_custom_rule.yml",  # Your new rule
]
```

4. **Run the tests**:

```bash
.venv/bin/python manual_test/test_textquery_backend.py
```

## See Also

- [Main README](../README.md) - Project overview
- [Test Suite Documentation](../tests/README.md) - Automated testing guide
- [OpenSearch PPL Documentation](https://opensearch.org/docs/latest/search-plugins/sql/ppl/)

