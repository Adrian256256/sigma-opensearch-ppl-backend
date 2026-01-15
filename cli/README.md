# CLI Tool for Sigma to OpenSearch PPL Conversion

Convert Sigma detection rules to OpenSearch PPL queries from the command line.

## Prerequisites

Ensure the virtual environment is set up with dependencies installed:

```bash
# From project root
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The CLI script automatically activates the virtual environment when executed.

## Quick Start

```bash
# Convert a rule
./cli/sigma-ppl rule.yml

# Save to file
./cli/sigma-ppl rule.yml -o output.ppl
```

## Global Installation

Add to your shell configuration (~/.zshrc or ~/.bashrc):

```bash
alias sigma-ppl="/path/to/sigma-opensearch-ppl-backend/cli/sigma-ppl"
source ~/.zshrc

# Use from anywhere
sigma-ppl ~/rules/my-rule.yml
```

## Usage Examples

### Basic Conversion

```bash
./cli/sigma-ppl tests/automated_tests/rules/lateral_movement_psexec.yml
# Output: ['source=windows-process_creation-* | where LIKE(Image, "%\\PsExec.exe")...']
```

### Save to File

```bash
./cli/sigma-ppl rule.yml -o query.ppl
# Output: Converted to: query.ppl
```

### Batch Conversion

```bash
for rule in tests/automated_tests/rules/*.yml; do
    ./cli/sigma-ppl "$rule" -o "output/$(basename "$rule" .yml).ppl"
done
```

### Pipeline Usage

```bash
# Filter output
./cli/sigma-ppl rule.yml | grep "where"

# Validate conversion
./cli/sigma-ppl rule.yml > /dev/null && echo "Valid"
```

## Syntax

```
sigma-ppl <input_rule.yml> [-o <output_file.ppl>]
```

**Arguments:**
- `input_rule.yml` - Path to Sigma rule (required)
- `-o output.ppl` - Output file path (optional, defaults to stdout)

**Exit codes:**
- `0` - Success
- `1` - Error

## Supported Features

- Field matching, boolean operators (AND, OR, NOT)
- Field modifiers (contains, startswith, endswith, etc.)
- CIDR ranges, regex, case-insensitive matching
- Null checks, complex nested conditions

## Troubleshooting

**Error: "No module named 'sigma'"**

The virtual environment may not be properly set up:

```bash
cd /path/to/sigma-opensearch-ppl-backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Error: "Permission denied"**

Make the script executable:

```bash
chmod +x cli/sigma-ppl
```

**Error: "command not found: sigma-ppl"**

If using the global alias, ensure the full absolute path is set:

```bash
# Add to ~/.zshrc
alias sigma-ppl="/full/absolute/path/to/sigma-opensearch-ppl-backend/cli/sigma-ppl"
source ~/.zshrc
```

---

**Documentation:** [Backend](../sigma_backend/backends/opensearch_ppl/README.md) | [Testing](../tests/README.md) | [Main README](../README.md)
