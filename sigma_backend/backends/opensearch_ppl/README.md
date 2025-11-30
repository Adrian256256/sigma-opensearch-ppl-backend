# OpenSearch PPL Backend for Sigma

This backend converts Sigma detection rules into PPL (Piped Processing Language) queries for OpenSearch.

## Table of Contents

- [Sigma Rule Data Structure](#sigma-rule-data-structure)
- [Sigma YAML Syntax](#sigma-yaml-syntax)
- [PPL Commands Used in Conversion](#ppl-commands-used-in-conversion)
  - [1. `source` - Data Source Specification](#1-source---data-source-specification)
  - [2. `where` - Event Filtering](#2-where---event-filtering)
  - [3. `fields` - Field Selection](#3-fields---field-selection)
  - [4. `stats` - Aggregations and Statistics](#4-stats---aggregations-and-statistics)
  - [5. `eval` - Creating New Fields](#5-eval---creating-new-fields)
  - [6. `dedup` - Removing Duplicates](#6-dedup---removing-duplicates)
  - [7. `sort` - Sorting Results](#7-sort---sorting-results)
  - [8. `head` / `tail` - Limiting Results](#8-head--tail---limiting-results)
  - [9. Pattern Matching with `like` and `match`](#9-pattern-matching-with-like-and-match)
  - [10. String Functions](#10-string-functions)
- [Structure of Generated PPL Query](#structure-of-generated-ppl-query)
- [Sigma → PPL Mapping](#sigma---ppl-mapping)
- [References](#references)

---

## Sigma Rule Data Structure

After parsing with the Sigma converter, rules are represented as Python dataclass objects:

### Main Structure

```python
SigmaRule
├── title: str                     # Rule title
├── id: UUID                       # Unique identifier
├── logsource: SigmaLogSource      # Source specification
│   ├── product: str               # "windows", "linux", etc.
│   ├── category: str              # "process_creation", "network_connection"
│   └── service: str               # "sysmon", "security"
│
└── detection: SigmaDetections
    ├── detections: Dict[str, SigmaDetection]    # Named selections
    │   └── "selection": SigmaDetection
    │       ├── detection_items: List[SigmaDetectionItem]
    │       │   └── SigmaDetectionItem
    │       │       ├── field: str                    # "EventID", "CommandLine"
    │       │       ├── modifiers: List[Type]         # [SigmaContainsModifier, ...]
    │       │       ├── value: List[SigmaString]      # Values to match
    │       │       └── value_linking: Type           # ConditionOR/ConditionAND
    │       └── item_linking: Type                    # ConditionAND (how items combine)
    │
    └── condition: List[str]                          # ["selection1 and selection2"]
```

### Key Concepts

**1. Accessing Data:**
```python
# Logsource
product = rule.logsource.product              # "windows"

# Detections
detections = rule.detection.detections        # Dict of selections
for name, selection in detections.items():
    for item in selection.detection_items:
        field = item.field                    # "CommandLine"
        modifiers = item.modifiers            # [SigmaContainsModifier]
        values = item.value                   # [SigmaString(...)]
```

**2. SigmaString Values:**
```python
# Values stored as lists with wildcards:
SigmaString.plain = ['System']                # Literal: "System"
SigmaString.plain = [1, 'AUTHORI', 1]        # Wildcard: *AUTHORI*
SigmaString.plain = ['cmd', 2, '.exe']       # Single char: cmd?.exe

# SpecialChars: 1 = * (multi), 2 = ? (single)
```

**3. Modifiers:**
```python
# Check modifier type:
modifier_name = item.modifiers[0].__name__
# Returns: "SigmaContainsModifier", "SigmaEndswithModifier", etc.
```

**4. Reconstructing Values:**
```python
value_str = ""
for part in sigma_string.plain:
    if part == 1:        # WILDCARD_MULTI
        value_str += "*"
    elif part == 2:      # WILDCARD_SINGLE
        value_str += "?"
    else:
        value_str += str(part)
```

---

## Sigma YAML Syntax

### Dash (-) Logic: AND vs OR

| Syntax | Logic | Example |
|--------|-------|---------|
| **No dash** | **AND** between fields | All conditions must match |
| **Dash (-)** | **OR** between items | At least one condition matches |

**Example:**
```yaml
selection:
    IntegrityLevel: System        # No dash
    User|contains: AUTHORI

selection_special:
    - Image|endswith: calc.exe    # Dash = OR
    - CommandLine|contains: -NoP
```
→ `(IntegrityLevel = System AND User contains AUTHORI) AND ((Image endswith calc.exe) OR (CommandLine contains -NoP))`

---

## PPL Commands Used in Conversion

### 1. `source` - Data Source Specification

The `source` command is used to specify the index or data source from which events will be extracted.

**Syntax:**
```ppl
source = index_pattern
```

**Usage in Sigma conversion:**
- Mapped from the `logsource` field of the Sigma rule
- May include the product, category, and service specified in the Sigma rule

**Example:**

*Sigma Rule:*
```yaml
title: Windows Process Creation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
```

*PPL Query:*
```ppl
source = windows-process_creation-*
```

**Logsource Mapping Strategy:**
- Uses original Sigma category/service names for consistency
- Index pattern: `{product}-{category}-{service}-*`
- All components are optional and concatenated with dashes

**More examples:**
```ppl
source = windows-*                        # product only
source = windows-process_creation-*       # product + category
source = windows-sysmon-*                 # product + service
source = windows-process_creation-sysmon-*  # product + category + service
source = firewall-*                       # category only
```

### 2. `where` - Event Filtering

The `where` command is essential for applying detection conditions from Sigma rules.

**Syntax:**
```ppl
source = index | where condition
```

**Supported operators:**
- **Equality:** `field = value`
- **Inequality:** `field != value`
- **Numeric comparisons:** `field > value`, `field >= value`, `field < value`, `field <= value`
- **Logical operators:** `AND`, `OR`, `NOT`
- **Pattern matching:** `like` for wildcards

**Usage in Sigma conversion:**
- Converts Sigma `selection` into `where` conditions
- Supports multiple conditions with logical operators

**Example:**

*Sigma Rule:*
```yaml
title: Suspicious Process Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\cmd.exe'
    CommandLine|contains: 'whoami'
  condition: selection
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 AND Image like "%\\cmd.exe" AND CommandLine like "%whoami%"
```

**More examples:**
```ppl
source = windows-* | where EventID = 1
source = windows-* | where EventID = 1 AND CommandLine like "%test.exe%"
source = windows-* | where (field1 = value1 OR field2 = value2) AND field3 != value3
```

### 3. `fields` - Field Selection

The `fields` command allows specific selection of fields to be returned in results.

**Syntax:**
```ppl
source = index | where condition | fields field1, field2, field3
```

**Usage in Sigma conversion:**
- Can be used to return only relevant fields mentioned in the rule
- Optimizes performance by limiting returned data

**Example:**

*Sigma Rule:*
```yaml
title: Process Creation Monitoring
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
fields:
  - EventID
  - CommandLine
  - User
  - ProcessName
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 | fields EventID, CommandLine, User, ProcessName
```

**More examples:**
```ppl
source = windows-* | where EventID = 1 | fields EventID, CommandLine, User, ProcessName
source = firewall-* | where action = "block" | fields timestamp, src_ip, dst_ip, port
```

### 4. `stats` - Aggregations and Statistics

The `stats` command is used for data aggregation and calculating statistics.

**Syntax:**
```ppl
source = index | where condition | stats count() by field
```

**Aggregation functions:**
- `count()` - counts events
- `sum(field)` - sum of values
- `avg(field)` - average of values
- `min(field)` - minimum value
- `max(field)` - maximum value
- `distinct_count(field)` - counts unique values

**Usage in Sigma conversion:**
- Used for rules requiring aggregations (e.g., count, threshold)
- Supports grouping with `by`

**Example:**

*Sigma Rule:*
```yaml
title: Multiple Failed Login Attempts
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625  # Failed logon
  condition: selection | count(SourceIP) by SourceIP > 5
timeframe: 10m
```

*PPL Query:*
```ppl
source = windows-security-* | where EventID = 4625 | stats count() by SourceIP | where count() > 5
```

**More examples:**
```ppl
source = windows-* | where EventID = 4625 | stats count() by SourceIP
source = windows-* | where ProcessName = "cmd.exe" | stats count() by User
source = network-* | where action = "blocked" | stats distinct_count(dst_ip) by src_ip
```

### 5. `eval` - Creating New Fields

The `eval` command allows creating new fields or modifying existing ones.

**Syntax:**
```ppl
source = index | eval new_field = expression
```

**Usage in Sigma conversion:**
- Field transformations
- Data normalization

**Example:**

*Sigma Rule:*
```yaml
title: Case Insensitive Command Detection
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'  # Case insensitive
  condition: selection
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 | eval CommandLine_lower = lower(CommandLine) | where CommandLine_lower like "%powershell%"
```

**More examples:**
```ppl
source = windows-* | eval CommandLine_lower = lower(CommandLine)
source = windows-* | eval is_suspicious = if(EventID = 4625, 1, 0)
source = web-logs-* | eval full_url = concat(protocol, "://", domain, path)
```

### 6. `dedup` - Removing Duplicates

The `dedup` command removes duplicate records based on specific fields.

**Syntax:**
```ppl
source = index | where condition | dedup field1, field2
```

**Usage in Sigma conversion:**
- Reducing noise in detections
- Eliminating duplicate events

**Example:**

*Sigma Rule:*
```yaml
title: Unique Suspicious Process Executions
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
  condition: selection
  # Only alert once per unique process instance
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 AND Image like "%\\powershell.exe" | dedup ProcessGuid
```

**More examples:**
```ppl
source = windows-* | where EventID = 1 | dedup ProcessGuid
source = network-* | where suspicious = true | dedup src_ip, dst_ip
source = web-logs-* | where status = 404 | dedup client_ip, url
```

### 7. `sort` - Sorting Results

The `sort` command orders results by one or more fields.

**Syntax:**
```ppl
source = index | where condition | sort field [asc|desc]
```

**Usage in Sigma conversion:**
- Ordering results by timestamp
- Prioritizing alerts

**Example:**

*Sigma Rule:*
```yaml
title: Recent Failed Login Attempts
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
  # Show most recent attempts first
```

*PPL Query:*
```ppl
source = windows-security-* | where EventID = 4625 | sort @timestamp desc
```

**More examples:**
```ppl
source = windows-* | where EventID = 4625 | sort @timestamp desc
source = web-logs-* | where status >= 400 | sort response_time desc
source = firewall-* | where action = "block" | sort timestamp asc
```

### 8. `head` / `tail` - Limiting Results

The `head` and `tail` commands limit the number of returned results.

**Syntax:**
```ppl
source = index | where condition | head n
source = index | where condition | tail n
```

**Usage in Sigma conversion:**
- Limiting results for testing
- Returning the first/last N events

**Example:**

*Sigma Rule:*
```yaml
title: Sample Process Creation Events
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
  # Limit to first 100 results for testing
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 | head 100
```

**More examples:**
```ppl
source = windows-* | where EventID = 1 | head 100
source = web-logs-* | where status = 500 | tail 50
source = firewall-* | where action = "alert" | sort @timestamp desc | head 20
```

### 9. Pattern Matching with `like` and `match`

PPL supports pattern matching for text fields.

**Syntax:**
```ppl
where field like "pattern%"
where match(field, 'regex_pattern')
```

**Wildcards in `like`:**
- `%` - any sequence of characters
- `_` - single character

**Usage in Sigma conversion:**
- Converting Sigma wildcards (`*`, `?`)
- Matching complex patterns

**Example:**

*Sigma Rule:*
```yaml
title: PowerShell Execution with Encoded Command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - '-enc'
      - 'JAB'
  condition: selection
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 AND Image like "%\\powershell.exe" AND CommandLine like "%-enc%" AND CommandLine like "%JAB%"
```

**More examples:**
```ppl
source = windows-* | where CommandLine like "%powershell%"          # Contains 'powershell'
source = windows-* | where FileName like "%.exe"                    # Ends with .exe
source = windows-* | where ProcessName like "cmd___.exe"            # cmd + exactly 3 chars + .exe
source = web-logs-* | where url like "/admin/%"                     # Starts with /admin/
source = windows-* | where match(CommandLine, '.*-enc(oded)?.*')    # Regex matching
```

### 10. String Functions

PPL offers various functions for string manipulation.

**Available functions:**
- `lower(field)` - convert to lowercase
- `upper(field)` - convert to uppercase
- `substring(field, start, length)` - extract substring
- `concat(field1, field2)` - concatenate strings
- `trim(field)` - remove whitespace

**Usage in Sigma conversion:**
- Normalizing data for case-insensitive comparisons
- Extracting substrings for analysis

**Example:**

*Sigma Rule:*
```yaml
title: Suspicious Script Execution (Case Insensitive)
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    CommandLine|contains:  # Case insensitive by default in Sigma
      - 'POWERSHELL'
      - 'powershell'
      - 'PowerShell'
  condition: selection
```

*PPL Query:*
```ppl
source = windows-* | where EventID = 1 AND lower(CommandLine) like "%powershell%"
```

**More examples:**
```ppl
source = windows-* | where lower(CommandLine) like "%powershell%"
source = web-logs-* | where upper(method) = "POST"
source = windows-* | eval process_name = substring(Image, 0, 50)
source = logs-* | eval full_message = concat(user, ": ", message)
source = windows-* | where trim(CommandLine) like "powershell%"
```

## Structure of Generated PPL Query

A typical PPL query generated from Sigma follows this structure:

```ppl
source = <index_pattern> 
| where <detection_conditions>
| [stats/eval/fields/sort/etc.]
| [additional_commands]
```

## Sigma → PPL Mapping

| Sigma Concept | PPL Equivalent | Notes |
|---------------|----------------|-------|
| `logsource.product` | `source = <index>` | Mapping to OpenSearch indices |
| `detection.selection` | `where condition` | Filtering conditions |
| `fieldname: value` | `field = value` | Exact equality |
| `fieldname\|contains: value` | `field like "%value%"` | Substring matching |
| `fieldname\|startswith: value` | `field like "value%"` | Prefix matching |
| `fieldname\|endswith: value` | `field like "%value"` | Suffix matching |
| `condition: a and b` | `where a AND b` | Logical conjunction |
| `condition: a or b` | `where a OR b` | Logical disjunction |
| `condition: not a` | `where NOT a` | Logical negation |
| Wildcard `*` | `%` in `like` | Any sequence |
| Wildcard `?` | `_` in `like` | Single character |

## References

- [OpenSearch PPL Documentation](https://opensearch.org/docs/latest/search-plugins/sql/ppl/index/)
- [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
- [Sigma Project](https://github.com/SigmaHQ/sigma)
