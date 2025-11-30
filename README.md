# Sigma to OpenSearch PPL Backend

Backend for converting Sigma rules into PPL (Piped Processing Language) queries for OpenSearch.

## Description

This project provides a backend for the pySigma library that converts Sigma detection rules into PPL queries optimized for OpenSearch. PPL is a data processing language that enables complex and efficient queries on data indexed in OpenSearch.

### Key Features

- **Full Sigma Support**: Converts standard Sigma detection rules with all modifiers
- **OpenSearch Optimized**: Generates PPL queries optimized for OpenSearch performance
- **Comprehensive Testing**: Full test suite ensuring correct conversion
- **Extensible Architecture**: Easy to extend with custom index mappings and output formats

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
│           ├── opensearch_ppl.py              # Legacy manual implementation
│           ├── opensearch_ppl_textquery.py    # Main TextQueryBackend implementation
│           └── README.md                      # Backend documentation
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
│   ├── test_simple_backend.py            # Simple backend test script
│   ├── test_textquery_backend.py         # TextQueryBackend test script
│   ├── example_rules/                    # Additional example rules
│   │   ├── powershell_suspicious.yml
│   │   ├── network_suspicious.yml
│   │   └── suspicious_system_user.yml
│   └── README.md                         # Manual testing documentation
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

### Quick Start

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend

# Load a Sigma rule
with open('rule.yml', 'r') as f:
    sigma_collection = SigmaCollection.from_yaml(f.read())

# Create the backend
backend = OpenSearchPPLBackend()

# Convert to PPL
ppl_query = backend.convert(sigma_collection)

print(ppl_query)
# Output: ['source = windows-process_creation-* | where EventID=1 AND Image like "*\\\\powershell.exe"']
```

### Example Sigma Rule

```yaml
title: Suspicious PowerShell Command
status: test
description: Detects suspicious PowerShell execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - 'Invoke-Expression'
    condition: selection
```

This will be converted to:
```
source = windows-process_creation-* | where Image like "*\powershell.exe" AND (CommandLine like "*-EncodedCommand*" OR CommandLine like "*Invoke-Expression*")
```

## Testing

### Quick Test

Run the test script to see the backend in action:

```bash
python manual_test/test_textquery_backend.py
```

### Automated Tests

For comprehensive automated testing, see [tests/README.md](tests/README.md).

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v
```

### Manual Testing

For quick testing and experimentation with example Sigma rules, see [manual_test/README.md](manual_test/README.md).

```bash
# Test example rules with simple backend
python manual_test/test_simple_backend.py

# Test example rules with TextQuery backend
python manual_test/test_textquery_backend.py
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
