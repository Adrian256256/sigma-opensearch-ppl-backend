# Sigma to OpenSearch PPL Backend

Backend for converting Sigma rules into PPL (Piped Processing Language) queries for OpenSearch.

## Table of Contents

- [Description](#description)
  - [Key Features](#key-features)
- [What is Sigma?](#what-is-sigma)
- [What is PPL?](#what-is-ppl)
- [Project Structure](#project-structure)
  - [Quick Links to Project Components](#quick-links-to-project-components)
    - [CLI](#cli)
    - [Backend](#sigma_backend)
    - [ECS Mapping](#ecs_mapping)
    - [ECS Fields Info](#ecs_fields_info)
    - [Inside OpenSearch Testing](#inside_opensearch_testing)
    - [Tables](#tables)
    - [Tests](#tests)
- [Installation](#installation)
  - [Dependencies](#dependencies)
- [Usage](#usage)
  - [Quick Start](#quick-start)
  - [Example Sigma Rule](#example-sigma-rule)
- [ECS Field Mapping](#ecs-field-mapping)
  - [Quick Example](#quick-example)
- [Testing](#testing)
  - [Automated Testing](#automated-testing)
  - [Correlation Testing](#correlation-testing)
  - [Custom Attributes Testing](#custom-attributes-testing)
  - [Option Testing](#option-testing)

---

## Description

This project provides a backend for the pySigma library that converts Sigma detection rules into PPL queries optimized for OpenSearch. PPL is a data processing language that enables complex and efficient queries on data indexed in OpenSearch.

### Key Features

- **Full Sigma Support**: Converts standard Sigma detection rules with all modifiers
- **OpenSearch Optimized**: Generates PPL queries optimized for OpenSearch performance
- **Comprehensive Testing**: Full test suite ensuring correct conversion
- **Extensible Architecture**: Easy to extend with custom index mappings and output formats
- **Custom Attributes**: Configure backend behavior directly in Sigma rule YAML (see [Custom Attributes Guide](./docs/CUSTOM_ATTRIBUTES.md))

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
│           ├── opensearch_ppl.py                 # Unified backend (includes custom modifiers & custom attributes)
│           └── README.md                         # Backend documentation
├── cli/
│   ├── sigma-ppl                         # Command-line conversion tool
│   ├── rule.yaml                         # Example Sigma rule
│   └── README.md                         # CLI documentation
├── ecs_mapping/
│   ├── __init__.py
│   ├── yaml_loader.py                    # YAML pipeline loader
│   ├── ecs_mapping.yml                   # ECS field mappings (YAML)
│   ├── categories/                       # Per-category ECS mapping YAMLs
│   └── README.md                         # ECS mapping documentation
├── ecs_fields_info/
│   ├── checker.py                        # ECS field verification tool
│   ├── add_ecs_links.py                  # ECS link enrichment tool
│   ├── count_field_frequency.py          # Field frequency analysis
│   ├── ecs_verification_results.csv      # Verification results
│   ├── sigma_fields.csv                  # Unique Sigma fields catalog
│   ├── sigma_fields_with_paths.csv       # Sigma fields with rule paths
│   ├── sigma_fields_frequency.csv        # Field usage frequency
│   ├── sigma-master/                     # Sigma rules repository
│   └── README.md                         # ECS checker documentation
├── inside_opensearch_testing/
│   ├── windows_dataset_testing/
│   │   ├── correlation_rules/            # Correlation rules used for testing
│   │   ├── evtx_to_opensearch.py         # EVTX to OpenSearch converter
│   │   ├── evtx_attack_samples_bulk.ndjson # Converted EVTX dataset
│   │   ├── EVTX-ATTACK-SAMPLES/          # Windows event logs dataset
│   │   └── README.md                     # Windows dataset testing documentation
│   └── log_generator/
│       ├── generate_logs.py              # Synthetic log generator
│       ├── bulk_ready.ndjson             # Generated bulk logs
│       ├── TESTING_QUERIES.md            # Example test queries
│       └── README.md                     # Log generator documentation
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
│   │   ├── validate_ppl_syntax.py        # PPL syntax validation script
│   │   ├── validate_refs_in_opensearch.py # Validate refs against OpenSearch
│   │   ├── rules/                        # Test Sigma rules
│   │   ├── refs/                         # Expected PPL outputs
│   │   ├── out/                          # Conversion output files
│   │   └── README.md                     # Automated testing documentation
│   ├── correlation_testing/
│   │   ├── test_correlations.py          # Correlation rules test script
│   │   ├── validate_refs_in_opensearch.py # Validate refs against OpenSearch
│   │   ├── sigma_rules/                  # Correlation test Sigma rules
│   │   ├── ppl_refs/                     # Expected correlation PPL outputs
│   │   ├── out/                          # Conversion output files
│   │   └── README.md                     # Correlation testing documentation
│   ├── custom_attribute_testing/
│   │   ├── test_checker.py               # Custom attributes test suite
│   │   ├── validate_refs_in_opensearch.py # Validate refs against OpenSearch
│   │   ├── rules/                        # Test Sigma rules with custom attributes
│   │   ├── refs/                         # Expected PPL outputs
│   │   ├── out/                          # Conversion output files
│   │   └── README.md                     # Custom attributes testing documentation
│   ├── option_testing/
│   │   ├── test_checker.py               # Option testing checker
│   │   ├── validate_refs_in_opensearch.py # Validate refs against OpenSearch
│   │   ├── rules/                        # Test Sigma rules for options
│   │   ├── refs/                         # Expected PPL outputs
│   │   ├── out/                          # Conversion output files
│   │   └── README.md                     # Option testing documentation
│   └── README.md                         # Testing overview documentation
├── .gitignore                            # Files ignored by Git
├── requirements.txt                      # Python dependencies
└── README.md                             # Project documentation
```

### Quick Links to Project Components

#### [`cli/`](./cli/)
Command-line interface for converting Sigma rules.

- [`sigma-ppl`](./cli/sigma-ppl) - CLI conversion tool
- [`rule.yaml`](./cli/rule.yaml) - Example Sigma rule
- [`README.md`](./cli/README.md) - CLI documentation

#### [`sigma_backend/`](./sigma_backend/)
Core backend implementation for Sigma to PPL conversion.

- [`backends/opensearch_ppl/`](./sigma_backend/backends/opensearch_ppl/)
  - [`opensearch_ppl.py`](./sigma_backend/backends/opensearch_ppl/opensearch_ppl.py) - Unified backend with custom modifiers and custom attributes support
  - [`README.md`](./sigma_backend/backends/opensearch_ppl/README.md) - Backend documentation

#### [`ecs_mapping/`](./ecs_mapping/)
Elastic Common Schema (ECS) field mapping for Sigma rules.

- [`yaml_loader.py`](./ecs_mapping/yaml_loader.py) - YAML pipeline loader
- [`ecs_mapping.yml`](./ecs_mapping/ecs_mapping.yml) - ECS field mappings (YAML)
- [`categories/`](./ecs_mapping/categories/) - Per-category ECS mapping YAMLs
- [`README.md`](./ecs_mapping/README.md) - ECS mapping documentation

#### [`ecs_fields_info/`](./ecs_fields_info/)
Tools for extracting and verifying Sigma fields against ECS.

- [`checker.py`](./ecs_fields_info/checker.py) - ECS field verification tool
- [`add_ecs_links.py`](./ecs_fields_info/add_ecs_links.py) - ECS link enrichment tool
- [`count_field_frequency.py`](./ecs_fields_info/count_field_frequency.py) - Field frequency analysis
- [`ecs_verification_results.csv`](./ecs_fields_info/ecs_verification_results.csv) - Verification results
- [`sigma_fields.csv`](./ecs_fields_info/sigma_fields.csv) - Unique Sigma fields catalog
- [`sigma_fields_with_paths.csv`](./ecs_fields_info/sigma_fields_with_paths.csv) - Sigma fields with rule paths
- [`sigma_fields_frequency.csv`](./ecs_fields_info/sigma_fields_frequency.csv) - Field usage frequency
- [`README.md`](./ecs_fields_info/README.md) - ECS checker documentation

#### [`inside_opensearch_testing/`](./inside_opensearch_testing/)
Real-world dataset testing and synthetic log generation for validating Sigma rules in OpenSearch.

##### [`windows_dataset_testing/`](./inside_opensearch_testing/windows_dataset_testing/)
Windows event logs testing with EVTX-ATTACK-SAMPLES dataset (~31,911 Windows events mapped to MITRE ATT&CK).

- [`evtx_to_opensearch.py`](./inside_opensearch_testing/windows_dataset_testing/evtx_to_opensearch.py) - EVTX to OpenSearch converter
- [`evtx_attack_samples_bulk.ndjson`](./inside_opensearch_testing/windows_dataset_testing/evtx_attack_samples_bulk.ndjson) - Converted EVTX dataset
- [`EVTX-ATTACK-SAMPLES/`](./inside_opensearch_testing/windows_dataset_testing/EVTX-ATTACK-SAMPLES/) - Windows event logs dataset
- [`README.md`](./inside_opensearch_testing/windows_dataset_testing/README.md) - Windows dataset testing documentation with validated Sigma rules

##### [`log_generator/`](./inside_opensearch_testing/log_generator/)
Synthetic log generation for testing detection rules.

- [`generate_logs.py`](./inside_opensearch_testing/log_generator/generate_logs.py) - Synthetic log generator
- [`bulk_ready.ndjson`](./inside_opensearch_testing/log_generator/bulk_ready.ndjson) - Generated bulk logs
- [`TESTING_QUERIES.md`](./inside_opensearch_testing/log_generator/TESTING_QUERIES.md) - Example test queries
- [`README.md`](./inside_opensearch_testing/log_generator/README.md) - Log generator documentation

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
  - [`validate_ppl_syntax.py`](./tests/automated_tests/validate_ppl_syntax.py) - PPL syntax validation script
  - [`validate_refs_in_opensearch.py`](./tests/automated_tests/validate_refs_in_opensearch.py) - Validate refs against OpenSearch
  - [`rules/`](./tests/automated_tests/rules/) - Test Sigma rules
  - [`refs/`](./tests/automated_tests/refs/) - Expected PPL outputs
  - [`out/`](./tests/automated_tests/out/) - Conversion output files
  - [`README.md`](./tests/automated_tests/README.md) - Automated testing documentation

- [`correlation_testing/`](./tests/correlation_testing/)
  - [`test_correlations.py`](./tests/correlation_testing/test_correlations.py) - Correlation rules test script
  - [`validate_refs_in_opensearch.py`](./tests/correlation_testing/validate_refs_in_opensearch.py) - Validate refs against OpenSearch
  - [`sigma_rules/`](./tests/correlation_testing/sigma_rules/) - Correlation test Sigma rules
  - [`ppl_refs/`](./tests/correlation_testing/ppl_refs/) - Expected correlation PPL outputs
  - [`out/`](./tests/correlation_testing/out/) - Conversion output files
  - [`README.md`](./tests/correlation_testing/README.md) - Correlation testing documentation

- [`custom_attribute_testing/`](./tests/custom_attribute_testing/)
  - [`test_checker.py`](./tests/custom_attribute_testing/test_checker.py) - Custom attributes test suite
  - [`validate_refs_in_opensearch.py`](./tests/custom_attribute_testing/validate_refs_in_opensearch.py) - Validate refs against OpenSearch
  - [`rules/`](./tests/custom_attribute_testing/rules/) - Test Sigma rules with custom attributes
  - [`refs/`](./tests/custom_attribute_testing/refs/) - Expected PPL outputs
  - [`out/`](./tests/custom_attribute_testing/out/) - Conversion output files
  - [`README.md`](./tests/custom_attribute_testing/README.md) - Custom attributes testing documentation

- [`option_testing/`](./tests/option_testing/)
  - [`test_checker.py`](./tests/option_testing/test_checker.py) - Option testing checker
  - [`validate_refs_in_opensearch.py`](./tests/option_testing/validate_refs_in_opensearch.py) - Validate refs against OpenSearch
  - [`rules/`](./tests/option_testing/rules/) - Test Sigma rules for options
  - [`refs/`](./tests/option_testing/refs/) - Expected PPL outputs
  - [`out/`](./tests/option_testing/out/) - Conversion output files
  - [`README.md`](./tests/option_testing/README.md) - Option testing documentation

- [`README.md`](./tests/README.md) - Testing overview documentation

#### Other Files

- [`.gitignore`](./.gitignore) - Files ignored by Git
- [`requirements.txt`](./requirements.txt) - Python dependencies
- [`README.md`](./README.md) - Project documentation


## Installation

## Installation

### Dependencies

Install required dependencies:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Main dependencies:
- `pysigma` - Library for processing Sigma rules
- `pytest` - Testing framework
- `pyyaml` - YAML file parsing

## Usage

### Command-Line Interface (Recommended)

The easiest way to convert Sigma rules is using the CLI tool:

```bash
# Basic conversion
./cli/sigma-ppl tests/automated_tests/rules/case_insensitive_match.yml

# Save to file
./cli/sigma-ppl rule.yml -o output.ppl
```

**[Full CLI Documentation](./cli/README.md)**

### Python API

For programmatic usage:

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend

# Load a Sigma rule
with open('rule.yml', 'r') as f:
    sigma_collection = SigmaCollection.from_yaml(f.read())

# Create the backend (supports both regular and correlation rules)
backend = OpenSearchPPLBackend()

# Convert to PPL
ppl_query = backend.convert(sigma_collection)

print(ppl_query)
# Output: ['source = windows-process_creation-* | where EventID=1 AND LIKE(Image, "%\\\\powershell.exe")']
```

### Backend Options

Customize query generation with backend-specific options (similar to Splunk's `-O` flag):

```python
# Custom index pattern (override auto-generated logsource)
backend = OpenSearchPPLBackend(custom_logsource="my-custom-logs-*")

# Time filters - relative (e.g., last 30 days)
backend = OpenSearchPPLBackend(min_time="-30d", max_time="now")

# Time filters - absolute timestamps
backend = OpenSearchPPLBackend(
    min_time="2024-01-01T00:00:00",
    max_time="2024-12-31T23:59:59"
)

# Combined options
backend = OpenSearchPPLBackend(
    custom_logsource="security-logs-*",
    min_time="-7d",
    max_time="now"
)
```

**Available Options:**
- `custom_logsource`: Override auto-generated index pattern
- `min_time`: Minimum time filter (earliest). Examples: `"-30d"`, `"-7d"`, `"-24h"`, `"2024-01-01T00:00:00"`
- `max_time`: Maximum time filter (latest). Examples: `"now"`, `"2024-12-31T23:59:59"`

**Time Filter Formats:**
- **Relative time**: `-30d` (30 days ago), `-7d` (7 days ago), `-24h` (24 hours ago), `-1h` (1 hour ago)
- **Absolute time**: `"2024-01-01T00:00:00"` (ISO 8601 timestamp)
- **Current time**: `"now"` (current timestamp)

**Query Output Examples:**

*Without time filters (default):*
```ppl
source=windows-* | where CommandLine="evil.exe"
```

*With time filters:*
```ppl
source=windows-* | where (CommandLine="evil.exe") AND (@timestamp >= now() - 30d AND @timestamp <= now())
```

**Use Cases:**
- **Custom logsource**: Non-standard index naming, multi-tenant deployments, ECS compatibility
- **Time filters**: Historical analysis, incident response time windows, performance optimization, compliance reporting

**CLI Usage (when registered with sigma):**
```bash
# With backend options
sigma convert -t opensearch-ppl -O custom_logsource=my-logs-* rule.yml

# With time filters
sigma convert -t opensearch-ppl -O min_time=-30d -O max_time=now rule.yml

# Combined options
sigma convert -t opensearch-ppl \
    -O custom_logsource=security-* \
    -O min_time=-7d \
    -O max_time=now \
    rule.yml

# Convert entire directory
sigma convert -t opensearch-ppl \
    -O custom_logsource=security-* \
    -O min_time=-24h \
    -O max_time=now \
    -o output/ \
    rules/
```

**Full documentation: [tests/option_testing/README.md](tests/option_testing/README.md)**

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
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
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
- `CommandLine` - `process.command_line`
- `ProcessName` - `process.name`
- `User` - `user.name`
- `DestinationIp` - `destination.ip`

**For detailed ECS mapping documentation, see [ecs_mapping/README.md](ecs_mapping/README.md)**

## Testing

### Automated Testing

For automated testing with the test checker, see [tests/automated_tests/README.md](tests/automated_tests/README.md).

```bash
# Run automated tests
python tests/automated_tests/test_checker.py
```

### Correlation Testing

For correlation rule testing, see [tests/correlation_testing/README.md](tests/correlation_testing/README.md).

```bash
# Run correlation tests
./tests/correlation_testing/test_correlations.py
```

### Custom Attributes Testing

For custom attributes feature testing, see [tests/custom_attribute_testing/README.md](tests/custom_attribute_testing/README.md).

```bash
# Run custom attributes tests
python tests/custom_attribute_testing/test_checker.py
```

Custom attributes allow configuring backend behavior directly in Sigma rule YAML. See the [backend documentation](sigma_backend/backends/opensearch_ppl/README.md#custom-attributes) for full details.

### Option Testing

For backend options testing, see [tests/option_testing/README.md](tests/option_testing/README.md).

```bash
# Run option tests
python tests/option_testing/test_checker.py
```
