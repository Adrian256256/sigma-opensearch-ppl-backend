# Sigma to OpenSearch PPL Test Cases

This directory contains Sigma rules and their expected OpenSearch PPL translations for testing the backend converter.

## Directory Structure

- **`rules/`** - Sigma rule files (`.yml`)
- **`refs/`** - Expected OpenSearch PPL queries (`.txt`)

Each rule file in `rules/` has a corresponding PPL query in `refs/` with the same base filename.

## Test Categories

### Basic Detection Rules
- **`windows_process_creation_basic.yml`** - Simple process creation with exact field matching
- **`windows_suspicious_powershell.yml`** - PowerShell detection with endswith and contains modifiers
- **`windows_network_connection_suspicious.yml`** - Network connections to suspicious ports using IN operator
- **`windows_file_creation_sensitive.yml`** - File creation in sensitive directories
- **`linux_suspicious_bash_commands.yml`** - Linux bash command detection

### Wildcard & Modifier Tests
- **`wildcard_pattern_match.yml`** - Wildcard patterns (`*` → `%`, `?` → `_`)
- **`modifier_startswith.yml`** - StartsWith modifier → `LIKE(field, "value%")`
- **`modifier_endswith.yml`** - EndsWith modifier → `LIKE(field, "%value")`
- **`modifier_contains_all.yml`** - Contains|all modifier requiring all values match
- **`case_insensitive_match.yml`** - Case insensitive matching (default behavior)

### String Modifiers
- **`modifier_cased.yml`** - Case-sensitive matching → `LIKE(field, "%value%", true)`
- **`modifier_base64.yml`** - Base64 encoding for values
- **`modifier_base64offset.yml`** - Base64 encoding with 3 offset variations
- **`modifier_wide_base64offset.yml`** - UTF-16LE encoding + base64offset (wide modifier)
- **`modifier_windash.yml`** - Windows dash variations (`-`, `/`, `–`, `—`, `―`)

### Field Operations
- **`modifier_exists_true.yml`** - Field existence check → `isnotnull(field)`
- **`modifier_exists_false.yml`** - Field non-existence check → `isnull(field)`
- **`modifier_fieldref.yml`** - Field-to-field comparison → `field1=field2`

### Numeric Modifiers
- **`modifier_gt.yml`** - Greater than → `field>value`
- **`modifier_gte.yml`** - Greater than or equal → `field>=value`
- **`modifier_lt.yml`** - Less than → `field<value`
- **`modifier_lte.yml`** - Less than or equal → `field<=value`

### Logical Operators
- **`logical_and_condition.yml`** - AND logic between multiple conditions
- **`logical_or_condition.yml`** - OR logic between multiple selections
- **`logical_not_condition.yml`** - NOT logic for filtering
- **`logical_complex_nested.yml`** - Complex nested AND/OR/NOT conditions
- **`logical_multiple_selections.yml`** - Multiple named selections with filters

### Numeric Comparisons
- **`numeric_greater_than.yml`** - Greater than operator (`>`)
- **`numeric_less_than.yml`** - Less than operator (`<`)
- **`numeric_range_check.yml`** - Range checking with `>=` and `<=`
- **`numeric_high_privilege.yml`** - Privilege level detection with numeric comparison
- **`numeric_suspicious_port.yml`** - Port range detection

### Advanced Pattern Matching
- **`regex_pattern_match.yml`** - Regular expressions using `match()` function
- **`cidr_network_range.yml`** - CIDR notation using `cidrmatch()` function
- **`field_null_check.yml`** - Null field checking with `isnull()`
- **`regex_base64_command.yml`** - Complex regex for base64 detection
- **`special_chars_in_path.yml`** - Special character handling in paths
- **`registry_key_modification.yml`** - Registry key detection

### Real-World Detection Scenarios
- **`aggregation_failed_logins.yml`** - Aggregation with stats and count filtering
- **`aggregation_rare_process.yml`** - Rare command using statistical analysis
- **`mimikatz_execution.yml`** - Credential dumping tool detection
- **`lateral_movement_psexec.yml`** - PsExec-based lateral movement
- **`suspicious_wmi_execution.yml`** - WMI-based process execution
- **`scheduled_task_creation.yml`** - Scheduled task persistence
- **`suspicious_service_install.yml`** - Service installation detection
- **`suspicious_dns_query.yml`** - DNS queries to suspicious TLDs

## PPL Syntax Notes

### OpenSearch PPL Official Documentation
- **[PPL Syntax](https://opensearch.org/docs/latest/search-plugins/sql/ppl/syntax/)**
- **[PPL Commands & Functions](https://opensearch.org/docs/latest/search-plugins/sql/ppl/functions/)**
- **[PPL Functions (GitHub)](https://github.com/opensearch-project/sql/tree/main/docs/user/ppl/functions)** - Detailed function documentation

### Key OpenSearch PPL Patterns Used

- **Source**: `source=<product>-<category>-*`
- **Exact match**: `field="value"` or `field=value`
- **Pattern matching**: `LIKE(field, "pattern")` with `%` (multi-char) and `_` (single-char) wildcards
- **Regex**: `match(field, 'regex')`
- **Numeric comparison**: `field>value`, `field<value`, `field>=value`, `field<=value`
- **IN operator**: `field in (val1, val2, val3)`
- **Null checks**: `isnull(field)`, `isnotnull(field)`
- **CIDR**: `cidrmatch(field, "IP/mask")`
- **Aggregation**: `stats count() by field`
- **Logical operators**: `AND`, `OR`, `NOT`

### Important Differences from Sigma

- Sigma `*` wildcard → PPL `%` in LIKE function
- Sigma `?` wildcard → PPL `_` in LIKE function
- Sigma `contains:` → PPL `LIKE(field, "%value%")`
- Sigma `startswith:` → PPL `LIKE(field, "value%")`
- Sigma `endswith:` → PPL `LIKE(field, "%value")`
- Backslashes in strings must be escaped: `\\`

## Sigma Modifiers Support

### Supported Modifiers (15/17 from SigmaHQ documentation)

All modifiers implemented and tested:

| Modifier | Description | PPL Output Example |
|----------|-------------|-------------------|
| `contains` | Contains pattern | `LIKE(field, "%value%")` |
| `startswith` | Starts with pattern | `LIKE(field, "value%")` |
| `endswith` | Ends with pattern | `LIKE(field, "%value")` |
| `all` | All values must match (AND) | `field1=val1 AND field1=val2` |
| `base64` | Base64 encode value | `LIKE(field, "%base64value%")` |
| `base64offset` | Base64 with 3 offsets | `LIKE(field, "%off0%") OR LIKE(field, "%off1%") OR ...` |
| `cased` | Case-sensitive match | `LIKE(field, "%value%", true)` |
| `cidr` | CIDR network matching | `cidrmatch(field, "192.168.0.0/24")` |
| `exists` | Field existence check | `isnotnull(field)` or `isnull(field)` |
| `fieldref` | Field-to-field comparison | `field1=field2` |
| `gt` / `gte` | Greater than (or equal) | `field>10` or `field>=10` |
| `lt` / `lte` | Less than (or equal) | `field<100` or `field<=100` |
| `re` | Regular expression | `match(field, 'regex')` |
| `wide` | UTF-16LE encoding | Combined with base64offset |
| `windash` | Windows dash variations | `LIKE(field, "%-param%") OR LIKE(field, "%/param%") ...` |

### Unsupported Modifiers

**Not supported by pySigma (base library):**
- `utf16` - Not implemented in pySigma
- `utf16le` - Not implemented in pySigma
- `utf16be` - Not implemented in pySigma

## Running Tests

### Syntax Validation

The `validate_ppl_syntax.py` script validates the syntax of all PPL queries in the `refs/` directory by executing them against a local OpenSearch instance. This verifies that the generated queries are syntactically correct without requiring test data.

**Prerequisites:**
- OpenSearch running locally on `http://localhost:9200`
- Default credentials: `admin:admin`

**Usage:**

```bash
# Activate virtual environment
source .venv/bin/activate

# Run syntax validation for all reference queries
python tests/automated_tests/validate_ppl_syntax.py
```

**Output:**
- Tests all `.txt` files in `refs/` directory
- Reports syntax validation status for each query
- Distinguishes between syntax errors and missing indices (IndexNotFoundException)
- Summary statistics at the end
- Exit code 0 if all queries are valid, 1 if any fail

### Rule Testing

```bash
# Run all tests
python tests/test_checker.py

# Run specific test
python tests/test_checker.py -t test_name

# Run with verbose output
python tests/test_checker.py -v

# Show all results (including passed)
python tests/test_checker.py --show-all
```

## References

### Sigma Documentation
- **[Sigma Modifiers](https://sigmahq.io/docs/basics/modifiers.html)** - Official modifier documentation
- **[Sigma Rules Repository](https://github.com/SigmaHQ/sigma)** - Community Sigma rules
- **[pySigma Documentation](https://sigmahq-pysigma.readthedocs.io/)** - Python library documentation

### OpenSearch PPL Documentation
- **[PPL Syntax](https://opensearch.org/docs/latest/search-plugins/sql/ppl/syntax/)** - Official syntax guide
- **[PPL Commands](https://opensearch.org/docs/latest/search-plugins/sql/ppl/commands/)** - Available commands
- **[PPL Functions](https://opensearch.org/docs/latest/search-plugins/sql/ppl/functions/)** - Built-in functions

### Backend Development
- **[pySigma Backend Development](https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html)** - Guide for creating backends
- **[TextQueryBackend Source](https://github.com/SigmaHQ/pySigma/blob/main/sigma/conversion/base.py)** - Base class source code
- **[Example Backends](https://github.com/SigmaHQ/pySigma/tree/main/sigma/backends)** - Reference implementations

