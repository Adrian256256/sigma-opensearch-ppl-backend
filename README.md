# Sigma to OpenSearch PPL Backend

Backend for converting Sigma rules into PPL (Piped Processing Language) queries for OpenSearch.

## Description

This project provides a backend for the pySigma library that converts Sigma detection rules into PPL queries optimized for OpenSearch. PPL is a data processing language that enables complex and efficient queries on data indexed in OpenSearch.

### Key Features

- **Sigma Rule Support**: Converts standard Sigma detection rules to PPL format
- **OpenSearch Optimized**: Generates PPL queries optimized for OpenSearch performance
- **Comprehensive Testing**: Full test suite ensuring correct conversion
- **Extensible Architecture**: Easy to extend with new features and operators

## What is Sigma?

[Sigma](https://github.com/SigmaHQ/sigma) is a generic and open signature format for SIEM systems. It allows security professionals to write detection rules once and convert them to various SIEM query languages.

## What is PPL?

Piped Processing Language (PPL) is OpenSearch's query language that uses a pipe syntax to chain commands for data processing and analysis. It provides a more intuitive way to query and manipulate data compared to traditional query DSL.

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
├── manual_test/
│   ├── manual_test.py                    # Manual testing script
│   ├── example_rules/                    # Additional example rules
│   │   ├── powershell_suspicious.yml
│   │   └── network_suspicious.yml
│   └── README.md                         # Manual testing guide
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

## Usage

### Basic Example

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

### Example Sigma Rule

```yaml
title: Suspicious Process Execution
status: experimental
description: Detects suspicious process execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: selection
```

This will be converted to a PPL query like:
```
source=windows | where Image like '%\\cmd.exe' and CommandLine like '%whoami%'
```

## Testing

The project includes both automated and manual testing capabilities.

### Automated Tests

For comprehensive automated testing, see [tests/README.md](tests/README.md).

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=sigma_backend --cov-report=html
```

### Manual Testing

For quick testing and experimentation with example Sigma rules, see [manual_test/README.md](manual_test/README.md).

```bash
# Test example rules and see PPL output
python manual_test/manual_test.py

# Interactive testing utility
python manual_test/interactive_test.py
```

## Architecture

### Backend Components

- **OpenSearchPPLBackend**: Main backend class that handles conversion
- **Rule Converter**: Converts individual Sigma rules to PPL
- **Field Mapper**: Maps Sigma field names to OpenSearch fields
- **Operator Handler**: Converts Sigma operators to PPL syntax

### Conversion Flow

```
Sigma Rule (YAML) → SigmaCollection → OpenSearchPPLBackend → PPL Query (String)
```

## Development

### Project Status

- ✅ Project structure
- ✅ Complete test suite
- ✅ Example Sigma rules
- ✅ Pytest configuration
- ⏳ Backend implementation (in development)
