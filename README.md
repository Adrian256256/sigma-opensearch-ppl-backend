# Sigma to OpenSearch PPL Backend

Backend for converting Sigma rules into PPL (Piped Processing Language) queries for OpenSearch.

## Table of Contents

- [Description](#description)
  - [Key Features](#key-features)
- [What is Sigma?](#what-is-sigma)
- [What is PPL?](#what-is-ppl)
- [Project Structure](#project-structure)
  - [Quick Links to Project Components](#quick-links-to-project-components)
- [Installation](#installation)
  - [Dependencies](#dependencies)
- [Usage](#usage)
  - [Quick Start](#quick-start)
  - [Example Sigma Rule](#example-sigma-rule)
- [ECS Field Mapping](#ecs-field-mapping)
  - [Quick Example](#quick-example)
- [Testing](#testing)
  - [Manual Testing](#manual-testing)
  - [Automated Testing](#automated-testing)
  - [Correlation Testing](#correlation-testing)

---

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
│           ├── opensearch_ppl_textquery.py       # Main TextQueryBackend implementation
│           ├── opensearch_ppl_correlations.py    # Correlation rules backend
│           ├── modifiers.py                      # Custom field modifiers
│           └── README.md                         # Backend documentation
├── ecs_mapping/
│   ├── __init__.py
│   ├── yaml_loader.py                    # YAML pipeline loader
│   ├── ecs_mapping.yml                   # ECS field mappings (YAML)
│   └── README.md                         # ECS mapping documentation
├── checker_missing_ecs_fields/
│   ├── checker.py                        # ECS field verification tool
│   ├── ecs_verification_results.csv      # Verification results
│   ├── sigma_fields.csv                  # Unique Sigma fields catalog
│   ├── sigma_fields_with_paths.csv       # Sigma fields with rule paths
│   ├── sigma-master/                     # Sigma rules repository
│   └── README.md                         # ECS checker documentation
├── tables/
│   ├── custom_modifiers.csv              # Custom modifiers reference
│   ├── detection_rules.csv               # Detection rules catalog
│   ├── logical_operations.csv            # Logical operations reference
│   ├── modifiers_testing.csv             # Modifiers testing data
│   ├── special_features.csv              # Special features reference
│   └── README.md                         # Tables documentation
├── tests/
│   ├── automated_tests/
│   │   ├── test_checker.py               # Automated test checker
│   │   ├── rules/                        # Test Sigma rules
│   │   ├── refs/                         # Expected PPL outputs
│   │   └── README.md                     # Automated testing documentation
│   ├── manual_test/
│   │   ├── test_textquery_backend.py     # TextQueryBackend test script
│   │   ├── test_ecs_pipeline.py          # ECS pipeline test script
│   │   ├── example_rules/                # Additional example rules
│   │   └── README.md                     # Manual testing documentation
│   ├── correlation_testing/
│   │   ├── test_correlations.py          # Correlation rules test script
│   │   ├── sigma_rules/                  # Correlation test Sigma rules
│   │   ├── ppl_refs/                     # Expected correlation PPL outputs
│   │   └── README.md                     # Correlation testing documentation
│   └── README.md                         # Testing overview documentation
├── .gitignore                            # Files ignored by Git
├── requirements.txt                      # Python dependencies
└── README.md                             # Project documentation
```

### Quick Links to Project Components

#### [`sigma_backend/`](./sigma_backend/)
Core backend implementation for Sigma to PPL conversion.

- [`backends/opensearch_ppl/`](./sigma_backend/backends/opensearch_ppl/)
  - [`opensearch_ppl_textquery.py`](./sigma_backend/backends/opensearch_ppl/opensearch_ppl_textquery.py) - Main TextQueryBackend implementation
  - [`opensearch_ppl_correlations.py`](./sigma_backend/backends/opensearch_ppl/opensearch_ppl_correlations.py) - Correlation rules backend
  - [`modifiers.py`](./sigma_backend/backends/opensearch_ppl/modifiers.py) - Custom field modifiers
  - [`README.md`](./sigma_backend/backends/opensearch_ppl/README.md) - Backend documentation

#### [`ecs_mapping/`](./ecs_mapping/)
Elastic Common Schema (ECS) field mapping for Sigma rules.

- [`yaml_loader.py`](./ecs_mapping/yaml_loader.py) - YAML pipeline loader
- [`ecs_mapping.yml`](./ecs_mapping/ecs_mapping.yml) - ECS field mappings (YAML)
- [`README.md`](./ecs_mapping/README.md) - ECS mapping documentation

#### [`checker_missing_ecs_fields/`](./checker_missing_ecs_fields/)
Tools for extracting and verifying Sigma fields against ECS.

- [`checker.py`](./checker_missing_ecs_fields/checker.py) - ECS field verification tool
- [`ecs_verification_results.csv`](./checker_missing_ecs_fields/ecs_verification_results.csv) - Verification results
- [`sigma_fields.csv`](./checker_missing_ecs_fields/sigma_fields.csv) - Unique Sigma fields catalog
- [`sigma_fields_with_paths.csv`](./checker_missing_ecs_fields/sigma_fields_with_paths.csv) - Sigma fields with rule paths
- [`README.md`](./checker_missing_ecs_fields/README.md) - ECS checker documentation

#### [`tables/`](./tables/)
Reference tables for modifiers, operations, and detection rules.

- [`custom_modifiers.csv`](./tables/custom_modifiers.csv) - Custom modifiers reference
- [`detection_rules.csv`](./tables/detection_rules.csv) - Detection rules catalog
- [`logical_operations.csv`](./tables/logical_operations.csv) - Logical operations reference
- [`modifiers_testing.csv`](./tables/modifiers_testing.csv) - Modifiers testing data
- [`special_features.csv`](./tables/special_features.csv) - Special features reference
- [`README.md`](./tables/README.md) - Tables documentation

#### [`tests/`](./tests/)
Comprehensive test suite for the backend.

- [`automated_tests/`](./tests/automated_tests/)
  - [`test_checker.py`](./tests/automated_tests/test_checker.py) - Automated test checker
  - [`rules/`](./tests/automated_tests/rules/) - Test Sigma rules
  - [`refs/`](./tests/automated_tests/refs/) - Expected PPL outputs
  - [`README.md`](./tests/automated_tests/README.md) - Automated testing documentation

- [`manual_test/`](./tests/manual_test/)
  - [`test_textquery_backend.py`](./tests/manual_test/test_textquery_backend.py) - TextQueryBackend test script
  - [`test_ecs_pipeline.py`](./tests/manual_test/test_ecs_pipeline.py) - ECS pipeline test script
  - [`example_rules/`](./tests/manual_test/example_rules/) - Additional example rules
  - [`README.md`](./tests/manual_test/README.md) - Manual testing documentation

- [`correlation_testing/`](./tests/correlation_testing/)
  - [`test_correlations.py`](./tests/correlation_testing/test_correlations.py) - Correlation rules test script
  - [`sigma_rules/`](./tests/correlation_testing/sigma_rules/) - Correlation test Sigma rules
  - [`ppl_refs/`](./tests/correlation_testing/ppl_refs/) - Expected correlation PPL outputs
  - [`README.md`](./tests/correlation_testing/README.md) - Correlation testing documentation

- [`README.md`](./tests/README.md) - Testing overview documentation

#### Other Files

- [`.gitignore`](./.gitignore) - Files ignored by Git
- [`requirements.txt`](./requirements.txt) - Python dependencies
- [`README.md`](./README.md) - Project documentation


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

**For detailed ECS mapping documentation, see [ecs_mapping/README.md](ecs_mapping/README.md)**

## Testing

### Manual Testing

For quick testing and experimentation with example Sigma rules, see [tests/manual_test/README.md](tests/manual_test/README.md).

```bash
# Test example rules with TextQuery backend
python tests/manual_test/test_textquery_backend.py

# Test ECS field mapping pipeline
python tests/manual_test/test_ecs_pipeline.py
```

### Automated Testing

For automated testing with the test checker, see [tests/automatic_tests/README.md](tests/automated_tests/README.md).

```bash
# Run automated tests
python tests/automatic_tests/test_checker.py
```

### Correlation Testing

For correlation rule testing, see [tests/correlation_testing/README.md](tests/correlation_testing/README.md).
