# Inside OpenSearch Testing

This directory contains tools and datasets for testing Sigma rules with real-world and synthetic data in OpenSearch.

## Overview

The testing framework includes three main components:

1. **Windows Dataset Testing** - Real Windows event logs from EVTX-ATTACK-SAMPLES
2. **HTTP Dataset Testing** - Real Apache web server logs with attack samples
3. **Log Generator** - Synthetic log generation for controlled testing

## Directory Structure

```
inside_opensearch_testing/
├── windows_dataset_testing/
│   ├── evtx_to_opensearch.py         # EVTX to OpenSearch converter
│   ├── evtx_attack_samples_bulk.ndjson # Converted EVTX dataset (~31,911 events)
│   ├── EVTX-ATTACK-SAMPLES/          # Windows event logs dataset
│   └── README.md                     # Windows dataset documentation
├── http_dataset_testing/
│   ├── apache_to_opensearch.py       # Apache logs to OpenSearch converter
│   ├── apache_http_logs_bulk.ndjson  # Converted Apache logs
│   ├── apache-http-logs/             # Apache HTTP logs dataset
│   └── README.md                     # HTTP dataset documentation
└── log_generator/
    ├── generate_logs.py              # Synthetic log generator
    ├── bulk_ready.ndjson             # Generated bulk logs
    ├── TESTING_QUERIES.md            # Example test queries
    └── README.md                     # Log generator documentation
```

## Components

### 1. Windows Dataset Testing

Tests Sigma rules against real Windows event logs from the EVTX-ATTACK-SAMPLES dataset.

**Dataset:** ~31,911 Windows events mapped to MITRE ATT&CK techniques
**Source:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

**Key Features:**
- Sysmon events (process creation, network connections, file operations)
- Windows Security logs (authentication, privilege escalation)
- PowerShell logs
- Real attack patterns from MITRE ATT&CK framework

**Use Cases:**
- Testing Windows process creation rules
- Validating PowerShell obfuscation detection
- Testing credential access detection
- Validating lateral movement detection

### 2. HTTP Dataset Testing

Tests Sigma rules against real Apache web server logs with various attack patterns.

**Dataset:** Apache access logs with XSS, SQL injection, and vulnerability scans
**Source:** https://github.com/ocatak/apache-http-logs

**Key Features:**
- Cross-Site Scripting (XSS) attacks
- SQL Injection attempts
- Path traversal attacks
- Command injection patterns
- Vulnerability scanner signatures

**Use Cases:**
- Testing web application attack detection rules
- Validating XSS detection patterns
- Testing SQL injection detection
- Identifying vulnerability scanning activity

### 3. Log Generator

Generates synthetic logs for controlled testing scenarios.

**Key Features:**
- Customizable log generation
- Configurable attack patterns
- Bulk-ready NDJSON output
- Support for multiple log types

**Use Cases:**
- Testing specific Sigma rule patterns
- Creating edge case scenarios
- Generating large datasets for performance testing
- Controlled testing without real attack data

## Quick Start

### Windows Dataset Testing

```bash
cd inside_opensearch_testing/windows_dataset_testing

# Convert EVTX files to OpenSearch format
python evtx_to_opensearch.py

# Import into OpenSearch
tail -n +2 evtx_attack_samples_bulk.ndjson | curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-

# Verify import
curl -X GET "localhost:9200/evtx-attack-samples/_count" | jq '.'
```

### HTTP Dataset Testing

```bash
cd inside_opensearch_testing/http_dataset_testing

# Clone the dataset
git clone https://github.com/ocatak/apache-http-logs.git

# Convert Apache logs to OpenSearch format
python apache_to_opensearch.py

# Import into OpenSearch
tail -n +2 apache_http_logs_bulk.ndjson | curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-

# Verify import
curl -X GET "localhost:9200/apache-http-logs/_count" | jq '.'
```

### Log Generator

```bash
cd inside_opensearch_testing/log_generator

# Generate synthetic logs
python generate_logs.py

# Import into OpenSearch
tail -n +2 bulk_ready.ndjson | curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-
```

## Testing Workflow

1. **Import Dataset** - Choose and import the appropriate dataset into OpenSearch
2. **Convert Sigma Rule** - Use the CLI tool to convert Sigma rules to PPL
3. **Run Query** - Execute the PPL query against the dataset
4. **Validate Results** - Verify that the query returns expected matches
5. **Iterate** - Refine rules and mappings as needed

## Dataset Comparison

| Feature | Windows Dataset | HTTP Dataset | Log Generator |
|---------|----------------|--------------|---------------|
| **Data Type** | Windows Event Logs | Apache Access Logs | Synthetic Logs |
| **Size** | ~31,911 events | Variable | Configurable |
| **Real Data** | ✅ Yes | ✅ Yes | ❌ No |
| **Attack Patterns** | MITRE ATT&CK | XSS, SQLI, Scans | Custom |
| **Best For** | Windows/Sysmon rules | Web application rules | Edge cases |

## Example Sigma Rules

### Windows Rule Example
```yaml
title: PowerShell Token Obfuscation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '`'
  condition: selection
```

### HTTP Rule Example
```yaml
title: SQL Injection Detection
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "' OR '"
      - "UNION SELECT"
  condition: selection
```

## Troubleshooting

### Dataset Not Found
```bash
# Windows dataset
cd windows_dataset_testing/EVTX-ATTACK-SAMPLES
# If empty, the dataset needs to be downloaded

# HTTP dataset
cd http_dataset_testing
git clone https://github.com/ocatak/apache-http-logs.git
```

### OpenSearch Connection Issues
```bash
# Check if OpenSearch is running
curl -X GET "localhost:9200"

# Check index health
curl -X GET "localhost:9200/_cat/indices?v"
```

### Import Errors
```bash
# Delete and recreate index
curl -X DELETE "localhost:9200/evtx-attack-samples"
curl -X DELETE "localhost:9200/apache-http-logs"

# Re-import with verbose output
tail -n +2 file.ndjson | curl -v -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-
```

## Further Reading

- [Windows Dataset Testing README](./windows_dataset_testing/README.md)
- [HTTP Dataset Testing README](./http_dataset_testing/README.md)
- [Log Generator README](./log_generator/README.md)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [OpenSearch PPL Documentation](https://opensearch.org/docs/latest/search-plugins/sql/ppl/index/)
