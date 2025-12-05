# Sigma to OpenSearch PPL Test Cases

## Known Issues

### Contains Modifier with List Values

**Known parsing behavior:** 

**Example:**
```yaml
CommandLine|contains:
    - 'sekurlsa'
    - 'logonpasswords'
    - 'lsadump'
```

The backend should process the complete YAML list items (" - 'sekurlsa' ") and not just the string values ("sekurlsa").

> ** DISCLAIMER:** Correlation tests are currently not functional. The backend does not yet have an implementation for correlation rules. I am not sure that correlation rules and reference files of theese rules (`correlation_*.txt`, `correlation_*.yml`) are correct. TODO

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
