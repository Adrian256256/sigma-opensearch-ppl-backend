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
│           ├── opensearch_ppl_textquery.py    # Main TextQueryBackend implementation
│           └── README.md                      # Backend documentation
├── ecs_mapping/
│   ├── __init__.py
│   ├── yaml_loader.py                    # YAML pipeline loader
│   ├── ecs_mapping.yml                   # ECS field mappings (YAML)
│   └── README.md                         # ECS mapping documentation
├── manual_test/
│   ├── test_textquery_backend.py         # TextQueryBackend test script
│   ├── test_ecs_pipeline.py              # ECS pipeline test script
│   ├── example_rules/                    # Additional example rules
│   └── README.md                         # Manual testing documentation
├── tests/
│   ├── test_checker.py                   # Automated test checker
│   ├── rules/                            # Test Sigma rules
│   └── refs/                             # Expected PPL outputs
├── .gitignore                            # Files ignored by Git
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
# Output: ['source = windows-process_creation-* | where EventID=1 AND LIKE(Image, "%\\\\powershell.exe")']
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
source = windows-process_creation-* | where LIKE(Image, "%\powershell.exe") AND (LIKE(CommandLine, "%-EncodedCommand%") OR LIKE(CommandLine, "%Invoke-Expression%"))
```

## ECS Field Mapping

This backend supports **Elastic Common Schema (ECS)** field mapping through a YAML-based processing pipeline. This ensures compatibility with OpenSearch indices that follow the ECS schema.

### Quick Example

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend
from ecs_mapping import load_ecs_pipeline_from_yaml

# Load ECS pipeline from YAML
ecs_pipeline = load_ecs_pipeline_from_yaml()

# Initialize backend with ECS pipeline
backend = OpenSearchPPLBackend(processing_pipeline=ecs_pipeline)

# Convert Sigma rule - field names will be automatically mapped to ECS
collection = SigmaCollection.from_yaml(sigma_rule)
ppl_query = backend.convert(collection)
```

**Field Mapping Example:**
- `CommandLine` → `process.command_line`
- `ProcessName` → `process.name`
- `User` → `user.name`
- `DestinationIp` → `destination.ip`

📖 **For detailed ECS mapping documentation, see [ecs_mapping/README.md](ecs_mapping/README.md)**

## Testing

### Manual Testing

For quick testing and experimentation with example Sigma rules, see [manual_test/README.md](manual_test/README.md).

```bash
# Test example rules with TextQuery backend
python manual_test/test_textquery_backend.py

# Test ECS field mapping pipeline
python manual_test/test_ecs_pipeline.py
```

### Conversion Flow

```
Sigma Rule (YAML) → SigmaCollection → [ECS Pipeline] → OpenSearchPPLBackend → PPL Query (String)
```

