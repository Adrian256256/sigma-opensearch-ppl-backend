# OpenSearch PPL Backend for Sigma

A production-ready pySigma backend for converting Sigma detection rules into PPL (Piped Processing Language) queries for OpenSearch.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Implementation](#implementation)
   - [OpenSearchPPLBackend Class](#opensearchpplbackend-class)
   - [Configuration via Class Variables](#configuration-via-class-variables)
   - [Core Methods](#core-methods)
4. [Sigma Modifiers Reference](#sigma-modifiers-reference)
   - [Built-in Encoding Modifiers](#built-in-encoding-modifiers-pysigma)
   - [Custom Modifiers](#custom-modifiers)
   - [UTF-16 Modifiers](#utf-16-modifiers)
   - [How UTF-16 Encoding Works](#how-utf-16-encoding-works)
   - [Why `.encode()` and `.decode()`?](#why-encode-and-decode)
5. [Sigma → PPL Conversion](#sigma--ppl-conversion)
   - [Syntax Mapping](#syntax-mapping)
   - [Conversion Examples](#conversion-examples)
6. [PPL Functions Used](#ppl-functions-used)
7. [Correlation Rules Support](#correlation-rules-support)
   - [Overview](#overview-1)
   - [Supported Correlation Types](#supported-correlation-types)
   - [Transformation Process: Sigma → OpenSearch PPL](#transformation-process-sigma--opensearch-ppl)
     - [Step 1: Rule Detection and Parsing](#step-1-rule-detection-and-parsing)
     - [Step 2: Detection Rules Conversion](#step-2-detection-rules-conversion)
     - [Step 3: Aggregation Construction](#step-3-aggregation-construction)
     - [Step 4: Time Window Application](#step-4-time-window-application)
     - [Step 5: Condition Evaluation](#step-5-condition-evaluation)
     - [Step 6: GROUP BY Field Mapping](#step-6-group-by-field-mapping)
   - [Complete Transformation Example](#complete-transformation-example)
   - [Implementation Architecture](#implementation-architecture)
   - [Technical Implementation Details](#technical-implementation-details)
   - [Usage Examples](#usage-examples)
8. [Usage](#usage)
9. [Project Structure](#project-structure)
10. [References](#references)

---

## Overview

**OpenSearchPPLBackend** is a robust pySigma backend that converts Sigma detection rules into PPL (Piped Processing Language) queries optimized for OpenSearch. Built on pySigma's `TextQueryBackend` class, it provides a production-ready solution for security detection rule conversion.

The backend follows pySigma's best practices by leveraging configuration-based design through class variables, minimizing custom code while maximizing functionality and maintainability.

---

## Features

### Core Capabilities

**Logical Operators**
- Full support for AND, OR, NOT with correct precedence
- Automatic grouping and parentheses handling
- Complex nested conditions

**Sigma Modifiers**
- Pattern matching: `contains`, `startswith`, `endswith`
- Case handling: `cased` for case-sensitive matching
- Comparisons: `gt`, `gte`, `lt`, `lte`
- Special modifiers: `re` (regex), `cidr`, `exists`, `fieldref`
- Encoding: `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide`
- Value modifiers: `all` (for matching all values in a list)

**Wildcard Conversion**
- Sigma `*` → PPL `%` (any sequence)
- Sigma `?` → PPL `_` (single character)
- Automatic escape handling for special characters

**Advanced Features**
- Regular expression support with `match()` function
- CIDR notation for network ranges
- Field existence and null checks
- Field-to-field comparisons
- IN operator for value lists
- Numeric and string comparisons

**Index Management**
- Automatic logsource → index pattern mapping
- Support for product, category, service combinations
- Flexible index naming conventions

---

## Implementation

### OpenSearchPPLBackend Class

Extends `TextQueryBackend` from pySigma, using a configuration-based approach via class variables to minimize custom code requirements.

```python
class OpenSearchPPLBackend(TextQueryBackend):
    """
    OpenSearch PPL backend using pySigma's TextQueryBackend.
    
    Leverages pySigma's built-in conversion infrastructure,
    requiring only configuration through class variables and minimal
    method overrides for PPL-specific behavior.
    """
```

### Configuration via Class Variables

The backend is primarily configured through class variables, eliminating the need for complex method overrides.

#### 1. Logical Operators

```python
# Boolean operators
or_token: ClassVar[str] = "OR"
and_token: ClassVar[str] = "AND"
not_token: ClassVar[str] = "NOT"
eq_token: ClassVar[str] = "="

# Operator precedence (NOT > AND > OR)
precedence: ClassVar[tuple] = (ConditionNOT, ConditionAND, ConditionOR)
group_expression: ClassVar[str] = "({expr})"
```

#### 2. Wildcards and Escaping

PPL uses `%` and `_` for wildcards (instead of `*` and `?` from Sigma):

```python
wildcard_multi: ClassVar[str] = "%"     # Equivalent to * in Sigma
wildcard_single: ClassVar[str] = "_"    # Equivalent to ? in Sigma

str_quote: ClassVar[str] = '"'          # String quotes
escape_char: ClassVar[str] = '\\'       # Escape character
```

#### 3. Pattern Matching Expressions

Uses PPL's `LIKE()` function for pattern matching:

```python
# LIKE() function expressions
startswith_expression: ClassVar[str] = 'LIKE({field}, {value}%)'
endswith_expression: ClassVar[str] = 'LIKE({field}, %{value})'
contains_expression: ClassVar[str] = 'LIKE({field}, %{value}%)'
wildcard_match_expression: ClassVar[str] = 'LIKE({field}, {value})'

# Case-sensitive matching (with 'cased' modifier)
case_sensitive_contains_expression: ClassVar[str] = 'LIKE({field}, %{value}%, true)'
```

#### 4. Comparison Operators

```python
compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
compare_operators: ClassVar[Dict[Any, str]] = {
    SigmaCompareExpression.CompareOperators.LT: "<",
    SigmaCompareExpression.CompareOperators.LTE: "<=",
    SigmaCompareExpression.CompareOperators.GT: ">",
    SigmaCompareExpression.CompareOperators.GTE: ">=",
}
```

#### 5. Special Expressions

```python
# Regular expressions
re_expression: ClassVar[str] = "match({field}, '{regex}')"
re_escape_char: ClassVar[str] = '\\'

# CIDR notation
cidr_expression: ClassVar[str] = 'cidrmatch({field}, "{value}")'

# Field existence
field_exists_expression: ClassVar[str] = "isnotnull({field})"
field_not_exists_expression: ClassVar[str] = "isnull({field})"

# Null checks
field_null_expression: ClassVar[str] = "isnull({field})"

# Field-to-field comparison
field_equals_field_expression: ClassVar[str] = "{field1}={field2}"

# IN operator for efficient multi-value matching
field_in_list_expression: ClassVar[str] = "{field} in ({list})"
convert_or_as_in: ClassVar[bool] = True  # Convert OR chains to IN
list_separator: ClassVar[str] = ", "
```

---

## Sigma Modifiers Reference

### Built-in Encoding Modifiers (pySigma)

Before discussing custom modifiers, it's important to understand the built-in encoding modifiers from pySigma:

#### `base64` Modifier
**Purpose**: Encode string as Base64  
**Source**: pySigma built-in ([line ~213](https://github.com/SigmaHQ/pySigma/blob/main/sigma/modifiers.py#L213-L222))

```python
class SigmaBase64Modifier(SigmaValueModifier[SigmaString, SigmaString]):
    """Encode string as Base64 value."""
    def modify(self, val: SigmaString) -> SigmaString:
        return SigmaString(b64encode(bytes(val)).decode())
```

**Example**:
```yaml
detection:
  selection:
    CommandLine|base64: 'powershell'  # Matches: cG93ZXJzaGVsbA==
```

**Use Case**: Detect Base64-encoded commands in logs (e.g., Linux bash history, web requests).

#### `base64offset` Modifier
**Purpose**: Encode string as Base64 with **3 different offsets** to match it anywhere in encoded data  
**Source**: pySigma built-in ([line ~225](https://github.com/SigmaHQ/pySigma/blob/main/sigma/modifiers.py#L225-L332))

```python
class SigmaBase64OffsetModifier(SigmaValueModifier[SigmaString, SigmaExpansion]):
    """Encode string with different offsets (0, 2, 3 bytes) to match at any position."""
    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)
```

**Why offsets?** Base64 encodes 3 bytes → 4 characters. A substring might start at different positions within these 3-byte blocks:

```
Original: "XYZtest123"
         ---^^^---- "test" starts at offset 0 in this 3-byte block
         
Base64 offset 0: b64encode("test")       → "dGVzdA=="
Base64 offset 1: b64encode(" test")      → "IHRlc3Q="  (padded with 1 space)
Base64 offset 2: b64encode("  test")     → "ICB0ZXN0"  (padded with 2 spaces)
```

**Example**:
```yaml
detection:
  selection:
    CommandLine|base64offset: 'invoke'  # Matches invoke at ANY position in base64 string
```

**Result**: Generates 3 variations to catch the string regardless of where it appears in the encoded data.

**Use Case**: Essential for detecting substrings within Base64-encoded data (e.g., malicious code fragments in encoded payloads).

---

## Custom Modifiers

The backend includes custom Sigma modifiers defined in `modifiers.py` for handling UTF-16 encoding variants commonly found in Windows event logs and obfuscated malware.

### UTF-16 Modifiers

Custom modifiers implemented following the pySigma pattern from [`SigmaWideModifier`](https://github.com/SigmaHQ/pySigma/blob/main/sigma/modifiers.py#L252-L273):

```python
# Available modifiers:
# - wide: UTF-16 Little Endian (pySigma built-in)
# - utf16: UTF-16 Little Endian (alias for 'wide')
# - utf16le: UTF-16 Little Endian (explicit)
# - utf16be: UTF-16 Big Endian (custom)
```

**Differences Between Modifiers**:

| Modifier | Encoding | Source | Functionally |
|----------|----------|--------|--------------|
| `wide` | UTF-16LE | pySigma built-in | **Identical** to `utf16` and `utf16le` |
| `utf16` | UTF-16LE | Custom (this backend) | Alias for `wide` - same implementation |
| `utf16le` | UTF-16LE | Custom (this backend) | Explicit name - same implementation |
| `utf16be` | UTF-16BE | Custom (this backend) | **Different** - Big Endian byte order |

**Why provide multiple LE modifiers?**
- `wide`: Original pySigma modifier name
- `utf16`: More descriptive, clearer intent
- `utf16le`: Explicit about Little Endian (pairs with `utf16be`)

**Usage in Sigma Rules**:
```yaml
detection:
  selection:
    # All three LE modifiers produce the same result:
    CommandLine|wide|base64: 'powershell'      # Original pySigma
    CommandLine|utf16|base64: 'powershell'     # Descriptive alias
    CommandLine|utf16le|base64: 'powershell'   # Explicit endianness
    
    # Big Endian is different:
    ScriptBlock|utf16be|contains: 'malicious'  # Null before char (not after)
```

**Implementation Details**:
- **Pattern**: Based on pySigma's `SigmaWideModifier` (line 305-330 in `modifiers.py`)
- **Base Class**: `SigmaValueModifier[SigmaString, SigmaString]`
- **Method**: Implements `modify()` to encode each string part
- **UTF-16LE**: `item.encode("utf-16le").decode("utf-8")` - null byte after each char
- **UTF-16BE**: `item.encode("utf-16be").decode("latin-1")` - null byte before each char
- **Registration**: Modifiers registered in `modifier_mapping` via `__init__.py`

### How UTF-16 Encoding Works

**UTF-16LE (Little Endian)** - Null byte **after** each character:
```
"test" → 't\x00e\x00s\x00t\x00'
ASCII: 74 65 73 74 → UTF-16LE: 74 00 65 00 73 00 74 00
```

**UTF-16BE (Big Endian)** - Null byte **before** each character:
```
"test" → '\x00t\x00e\x00s\x00t'
ASCII: 74 65 73 74 → UTF-16BE: 00 74 00 65 00 73 00 74
```

**Encoding Process**:
1. **Input**: `SigmaString` object containing the detection value
2. **Iteration**: Loop through each character in the string
3. **Encode**: Apply UTF-16LE or UTF-16BE encoding via Python's `.encode()`
4. **Decode**: Convert bytes back to string representation (UTF-8 for LE, latin-1 for BE)
5. **Output**: New `SigmaString` with encoded content ready for pattern matching

### Why `.encode()` and `.decode()`?

**`.encode(encoding)`** - Converts Python string → bytes:
```python
"test".encode("utf-16le")  # Returns: b't\x00e\x00s\x00t\x00' (bytes object)
```
- Transforms characters into their byte representation
- Required because UTF-16 represents characters as 2-byte sequences
- Creates a **bytes object** (not directly usable as string)

**`.decode(encoding)`** - Converts bytes → Python string:
```python
b't\x00e\x00s\x00t\x00'.decode("utf-8")  # Returns: 't\x00e\x00s\x00t\x00' (string)
```
- Reinterprets the byte sequence as a string
- Uses UTF-8 (for LE) or latin-1 (for BE) to preserve null bytes as characters
- Creates a **string object** that Sigma can process

**Why this two-step process?**
- **Step 1 (encode)**: Get the actual UTF-16 byte representation with null bytes
- **Step 2 (decode)**: Convert back to string so pySigma can use it for pattern matching
- **Result**: A string containing null bytes that will match UTF-16 encoded data in logs

**Example**:
```python
# PowerShell command: "iex"
original = "iex"
utf16_bytes = original.encode("utf-16le")      # b'i\x00e\x00x\x00'
utf16_string = utf16_bytes.decode("utf-8")     # 'i\x00e\x00x\x00'
# Now Sigma can match this pattern in base64-encoded PowerShell commands!
```

**Use Case**: Detect obfuscated commands in logs where strings are encoded (e.g., PowerShell `-EncodedCommand` uses UTF-16LE + Base64).

These modifiers extend pySigma's built-in encoding capabilities and are automatically available when using the backend.

---

## Core Methods

#### `__init__()`

Initializes the backend with an optional processing pipeline:

```python
def __init__(self, processing_pipeline: Optional[object] = None, **kwargs):
    super().__init__(processing_pipeline, **kwargs)
```

#### `_get_index_pattern()`

Extracts and constructs the index pattern from the Sigma rule's logsource:

```python
def _get_index_pattern(self, rule: SigmaRule) -> str:
    """
    Maps Sigma logsource (product, category, service) to OpenSearch index patterns.
    
    Example:
        product='windows', category='process_creation', service='sysmon'
        → 'windows-process_creation-sysmon-*'
    """
    logsource = rule.logsource
    product = getattr(logsource, 'product', None)
    category = getattr(logsource, 'category', None)
    service = getattr(logsource, 'service', None)
    
    index_parts = []
    if product:
        index_parts.append(product)
    if category:
        index_parts.append(category)
    if service:
        index_parts.append(service)
    
    return '-'.join(index_parts) + '-*' if index_parts else '*'
```

#### `finish_query()`

Assembles the final PPL query by adding the `source` command and fixing wildcards:

```python
def finish_query(self, rule: SigmaRule, query: str, state: ConversionState) -> str:
    """
    Finalizes the query by:
    1. Getting the index pattern from logsource
    2. Fixing wildcard positions in LIKE() expressions
    3. Building complete PPL query: source=<index> | where <conditions>
    """
    index_pattern = self._get_index_pattern(rule)
    query = super().finish_query(rule, query, state)
    
    # Fix LIKE expressions: move wildcards inside quotes
    def fix_wildcards(match):
        leading = match.group(1) or ''
        content = match.group(2)
        trailing = match.group(3) or ''
        return f'"{leading}{content}{trailing}"'
    
    query = re.sub(r'(%?)"([^"]*)\"(%?)', fix_wildcards, query)
    
    return f"source={index_pattern} | where {query}"
```

#### `finalize_query_default()` and `finalize_output_default()`

Methods for finalizing queries and output:

```python
def finalize_query_default(self, rule: SigmaRule, query: str, index: int, 
                           state: ConversionState) -> str:
    """Called after condition conversion to add PPL-specific elements."""
    index_pattern = self._get_index_pattern(rule)
    state.processing_state["index"] = index_pattern
    return query

def finalize_output_default(self, queries: list[str]) -> list[str]:
    """Returns the list of generated PPL queries."""
    return queries
```

---

## Sigma → PPL Conversion

### Syntax Mapping

| Sigma Concept | PPL Equivalent | Notes |
|---------------|----------------|-------|
| `logsource.product` | `source=<index>` | Automatic mapping to OpenSearch indices |
| `detection.selection` | `where condition` | Filter conditions |
| `field: value` | `field=value` | Exact equality |
| `field\|contains: value` | `LIKE(field, "%value%")` | Substring matching |
| `field\|startswith: value` | `LIKE(field, "value%")` | Prefix matching |
| `field\|endswith: value` | `LIKE(field, "%value")` | Suffix matching |
| `field\|re: regex` | `match(field, 'regex')` | Regular expressions |
| `condition: a and b` | `where a AND b` | Logical conjunction |
| `condition: a or b` | `where a OR b` | Logical disjunction |
| `condition: not a` | `where NOT a` | Logical negation |
| Wildcard `*` | `%` in LIKE | Any sequence of characters |
| Wildcard `?` | `_` in LIKE | Exactly one character |
| `field\|gt: 100` | `field>100` | Numeric comparisons |
| `field\|cidr: 192.168.0.0/16` | `cidrmatch(field, "192.168.0.0/16")` | CIDR notation |

### Conversion Example:

**Sigma Input**:
```yaml
title: Suspicious PowerShell Command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'bypass'
  condition: selection
```

**PPL Output**:
```ppl
source=windows-process_creation-* | where EventID=1 AND LIKE(Image, "%\\powershell.exe") AND LIKE(CommandLine, "%bypass%")
```

---

## PPL Functions Used

### Pattern Matching

**`LIKE(field, pattern)`** - Wildcard matching:
```ppl
LIKE(CommandLine, "%powershell%")           # Contains
LIKE(Image, "C:\\Windows\\%")               # Starts with
LIKE(Image, "%\\powershell.exe")            # Ends with
LIKE(User, "%AUTHORI%") OR LIKE(User, "%AUTORI%")  # Multiple patterns
```

**`match(field, regex)`** - Regular expressions:
```ppl
match(CommandLine, '.*powershell.*-enc.*')
```

### Field Operations

**`isnotnull(field)`, `isnull(field)`** - Existence checks:
```ppl
isnotnull(User)                             # Field exists
isnull(ParentProcessId)                     # Field is null
```

**`cidrmatch(field, cidr)`** - CIDR checks:
```ppl
cidrmatch(SourceIP, "192.168.0.0/16")
```

### Comparison Operators

```ppl
field = value        # Equal
field != value       # Not equal
field > value        # Greater than
field < value        # Less than
field >= value       # Greater or equal
field <= value       # Less or equal
field in (v1, v2)    # IN operator
```

---

## Correlation Rules Support

The backend includes full support for **Sigma Correlation Rules**, enabling multi-event pattern detection across time windows. This feature is implemented in `opensearch_ppl_correlations.py` and extends the base backend to handle complex detection scenarios that require correlating multiple events.

### Overview

Correlation rules allow detection of attack patterns that span multiple events, such as:
- **Brute force attacks**: Multiple failed logins followed by success
- **Lateral movement**: Sequence of authentication and remote execution events
- **Data exfiltration**: High-volume network transfers over time
- **Password spraying**: Same password tried across multiple accounts

**Reference**: [Sigma Correlation Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#correlation-rules)

### Supported Correlation Types

The backend supports all four Sigma correlation types defined in the specification:

| Type | Description | Use Case | PPL Implementation |
|------|-------------|----------|-------------------|
| `event_count` | Count total events in timespan | Frequency-based detection (e.g., >10 failed logins) | [`stats count()`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/stats.md) |
| `value_count` | Count distinct values in timespan | Cardinality detection (e.g., password used on >5 accounts) | [`stats dc(field)`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/functions/aggregations.md#distinct_count-dc) |
| `temporal` | Match multiple rule types in any order | Time-windowed multi-stage attacks | [`multisearch`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/multisearch.md) + aggregation |
| `temporal_ordered` | Match rules in specific sequence | Sequential attack steps (recon → exploit → exfil) | [`multisearch`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/multisearch.md) with time ordering |

### Transformation Process: Sigma → OpenSearch PPL

The conversion from Sigma correlation rules to OpenSearch PPL follows a structured pipeline that maps Sigma constructs to PPL equivalents.

#### Step 1: Rule Detection and Parsing

The backend first identifies correlation rules by checking for specific attributes:

```python
if hasattr(rule, 'type') and hasattr(rule, 'rules') and hasattr(rule, 'timespan'):
    # This is a correlation rule
    return self.convert_correlation_rule(rule)
```

**Sigma Input Example**:
```yaml
title: Brute Force Attack Detection
correlation:
  type: event_count           # Correlation type
  rules:
    - failed_login_attempt    # References to detection rules
  group-by:
    - user                    # Aggregation fields
    - source_ip
  timespan: 5m               # Time window
  condition:
    gte: 10                   # Threshold condition
```

#### Step 2: Detection Rules Conversion

Each referenced detection rule is converted to a PPL `source` and `where` clause using the base backend.

**Sigma Detection Rule**:
```yaml
name: failed_login_attempt
detection:
  selection:
    EventID: 4625
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
```

**Converted to PPL** (using base backend):
```ppl
source=windows-security-* | where EventID=4625 AND NOT LIKE(SubjectUserName, "%$")
```

**PPL Reference**: 
- [`source` command](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/search.md) - specifies the index pattern
- [`where` command](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/where.md) - filters events based on conditions

#### Step 3: Aggregation Construction

Based on the correlation type, the appropriate aggregation function is applied.

##### Event Count (Frequency Detection)

**Sigma**:
```yaml
correlation:
  type: event_count
  condition:
    gte: 10
```

**PPL Aggregation**:
```ppl
| stats count() as event_count by user, source_ip
| where event_count >= 10
```

**PPL Reference**: 
- [`stats count()`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/functions/aggregations.md#count) - counts number of events
- [`by` clause](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/stats.md#syntax) - groups results by specified fields

##### Value Count (Distinct Counting)

**Sigma**:
```yaml
correlation:
  type: value_count
  condition:
    field: user        # Field to count distinct values
    gte: 5
```

**PPL Aggregation**:
```ppl
| stats dc(user) as value_count by source_ip
| where value_count >= 5
```

**PPL Reference**: 
- [`dc(field)`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/functions/aggregations.md#distinct_count-dc) - returns distinct count (cardinality) of field values using HyperLogLog++ algorithm

##### Temporal Correlation (Multi-Event Detection)

**Sigma**:
```yaml
correlation:
  type: temporal
  rules:
    - failed_login
    - successful_login
  timespan: 10m
```

**PPL Implementation using `multisearch` command**:

OpenSearch PPL does **not** support the SQL `UNION` operator. For combining events from multiple rule matches, use the [`multisearch` command](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/multisearch.md) (available since v3.4):

```ppl
| multisearch [search source=windows-security-* | where EventID=4625 AND @timestamp >= now() - 10m] [search source=windows-security-* | where EventID=4624 AND LogonType=3 AND @timestamp >= now() - 10m]
| stats count() as event_count by user
| where event_count >= 1
```

**Key Points**:
1. **`UNION` does not exist** in OpenSearch PPL syntax
2. **`multisearch`** syntax: `| multisearch [search source=... | where ...] [search source=... | where ...]`
3. Each subsearch must be **enclosed in square brackets `[ ]`** and start with **`search` keyword**
4. Each sub-query requires **explicit time filters** (`@timestamp >= now() - 10m`)
5. Time filters must be applied **before** aggregation for correct results

**Current Implementation Limitation**: The backend may generate queries with `UNION` syntax which is **not valid PPL**. Queries need to be corrected to use `multisearch` instead.

**PPL Reference**: 
- [`multisearch` command documentation](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/multisearch.md) - Execute multiple searches and combine results

#### Step 4: Time Window Application

The `timespan` parameter defines the time window for correlation. This is a **critical component** that filters events to only those occurring within the specified time range.

**Sigma Timespan**:
```yaml
timespan: 5m    # 5 minutes
timespan: 1h    # 1 hour
timespan: 24h   # 24 hours
```

**PPL Time Filter Implementation**:

In OpenSearch PPL, time filtering is done using the [`@timestamp`](https://opensearch.org/docs/latest/field-types/supported-field-types/date/) field with the [`now()`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/functions/datetime.md#now) function:

```ppl
@timestamp >= now() - 15m    # Events from last 15 minutes
@timestamp >= now() - 1h     # Events from last 1 hour
@timestamp >= now() - 24h    # Events from last 24 hours
```

**Complete Example**:
```yaml
# Sigma
timespan: 15m
```
↓
```ppl
# PPL - time filter added to WHERE clause
source=security-* | where EventID=4625 AND @timestamp >= now() - 15m
```

**Key Components**:
- **[`@timestamp`](https://opensearch.org/docs/latest/field-types/supported-field-types/date/)**: Built-in OpenSearch field storing event time (ISO 8601 format)
- **[`now()`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/functions/datetime.md#now)**: PPL function returning current timestamp
- **Time arithmetic**: `now() - 15m` calculates timestamp 15 minutes ago
- **Comparison**: `@timestamp >= ...` filters events after that time

**Conversion Logic**:
```python
def convert_timespan(self, timespan) -> str:
    """Convert Sigma timespan to PPL time format."""
    if hasattr(timespan, 'seconds'):
        seconds = timespan.seconds
    else:
        seconds = int(timespan)
    
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    elif seconds >= 60:
        return f"{seconds // 60}m"
    else:
        return f"{seconds}s"

# Then apply in query:
time_filter = f"@timestamp >= now() - {convert_timespan(timespan)}"
```

**Important Notes**:

1. **Placement**: Time filter must be in the `where` clause **before** aggregation:
   ```ppl
   # CORRECT - filter before stats
   source=logs-* | where @timestamp >= now() - 5m | stats count() by user
   
   # INCORRECT - filter after stats (won't work as expected)
   source=logs-* | stats count() by user | where @timestamp >= now() - 5m
   ```

2. **Multi-Rule Correlation**: Each rule in a temporal correlation should have the time filter:
   ```ppl
   source=security-* | where EventID=4625 AND @timestamp >= now() - 15m
   UNION
   (source=security-* | where EventID=4624 AND @timestamp >= now() - 15m)
   ```

3. **Current Implementation Limitation**: The current backend implementation does **not** automatically inject `@timestamp` filters into the generated queries. The timespan is converted but not applied. This means:
   - Queries will scan all historical data instead of just the time window
   - Performance will be slower
   - Results may include events outside the intended time window
   
   **Workaround**: Time filtering can be applied at query execution time through OpenSearch Dashboards time picker, or the generated queries can be manually enhanced with timestamp filters.

**PPL Reference**: 
- [Date and Time Functions - `now()`](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/functions/datetime.md)
- [Time-based filtering examples](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/where.md)

#### Step 5: Condition Evaluation

Sigma correlation conditions are mapped to PPL `where` clauses.

**Sigma Condition Operators**:
```yaml
condition:
  gte: 10    # Greater than or equal
  gt: 5      # Greater than
  lte: 100   # Less than or equal
  lt: 50     # Less than
  eq: 1      # Equal to
```

**PPL Mapping**:
```python
condition_operators = {
    'gte': '>=',
    'gt': '>',
    'lte': '<=',
    'lt': '<',
    'eq': '='
}
```

**PPL Output**:
```ppl
| where event_count >= 10
| where value_count > 5
| where connection_count <= 100
```

**PPL Reference**: 
- [`where` command comparison operators](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/where.md)

#### Step 6: GROUP BY Field Mapping

The `group-by` fields from Sigma are converted to PPL's `by` clause in the `stats` command.

**Sigma**:
```yaml
group-by:
  - user
  - source_ip
  - destination_host
```

**PPL**:
```ppl
| stats count() as event_count by user, source_ip, destination_host
```

**PPL Reference**: 
- [`stats` with multiple grouping fields](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/stats.md#example-9-calculate-the-count-by-a-gender-and-span)

### Complete Transformation Example

**Sigma Correlation Rule**:
```yaml
title: Password Spraying Detection
correlation:
  type: value_count
  rules:
    - failed_login
  group-by:
    - source_ip
  timespan: 30m
  condition:
    field: user
    gte: 10
---
name: failed_login
detection:
  selection:
    EventID: 4625
  condition: selection
```

**Step-by-Step Transformation**:

1. **Detection Rule Conversion**:
   ```ppl
   source=windows-security-* | where EventID=4625
   ```

2. **Add Aggregation** (distinct count of users):
   ```ppl
   source=windows-security-* | where EventID=4625 
   | stats dc(user) as value_count by source_ip
   ```

3. **Apply Condition** (threshold filter):
   ```ppl
   source=windows-security-* | where EventID=4625 
   | stats dc(user) as value_count by source_ip 
   | where value_count >= 10
   ```

4. **Final PPL Query**:
   ```ppl
   source=windows-security-* | where EventID=4625 | stats dc(user) as value_count by source_ip | where value_count >= 10
   ```

This query detects password spraying by identifying source IPs that attempt to authenticate with 10 or more distinct usernames within a 30-minute window.

### Implementation Architecture

#### Class Structure

```python
class OpenSearchPPLCorrelationBackend(OpenSearchPPLBackend):
    """
    Extends the base OpenSearch PPL backend to support correlation rules.
    
    Key Features:
    - Detects correlation rules via type/rules/timespan attributes
    - Template-based query generation for all correlation types
    - Automatic field mapping and time range conversion
    - Generates complete PPL queries with aggregation
    """
```

#### How Detection Rule Conversion Works

**Critical Understanding**: When processing correlation rules, the backend needs the PPL queries for referenced detection rules. Here's how it works:

**The Flow**:

1. **pySigma Pre-Converts Detection Rules** (before correlation processing):
   ```python
   # AUTOMATIC - done by pySigma library internally
   for rule_ref in correlation_rule.rules:
       detection_rule = rule_ref.rule  # Get the SigmaRule object
       
       # pySigma calls the backend to convert the detection rule
       ppl_query = backend.convert_rule(detection_rule)
       # Result: ['source=windows | where EventID=4625']
       
       # pySigma SAVES the result inside the SigmaRule object
       detection_rule._conversion_result = ppl_query
   ```

2. **Backend Retrieves Pre-Converted Results** (in `convert_correlation_search`):
   ```python
   # Line 218 in opensearch_ppl_correlations.py
   for query in referred_rule.get_conversion_result():
       # This retrieves the already converted query from step 1
       # query = 'source=windows | where EventID=4625'
   ```

**Key Point**: `get_conversion_result()` is a **getter method from pySigma's `SigmaRule` class** - it does NOT perform conversion, it only retrieves results that were already saved by pySigma during an earlier automatic conversion phase.

**Why This Matters**:
- The backend doesn't need to manage detection rule conversion manually
- pySigma handles the orchestration automatically
- The backend only needs to read the pre-converted results and assemble them into correlation queries

**Visual Flow**:
```
┌─────────────────────────────────────────────────────────────┐
│ 1. User calls: backend.convert_rule(correlation_rule)       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. pySigma identifies referenced detection rules            │
│    [failed_login, successful_login]                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. pySigma AUTO-CONVERTS each detection rule                │
│    backend.convert_rule(failed_login)                       │
│    → 'source=windows | where EventID=4625'                  │
│    SAVES to: failed_login._conversion_result                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Backend's convert_correlation_search() is called         │
│    for query in referred_rule.get_conversion_result():      │
│       # Reads the saved result from step 3                  │
│       # Assembles it into correlation query                 │
└─────────────────────────────────────────────────────────────┘
```

#### Key Components

1. **Correlation Detection** (`convert_rule`):
   ```python
   def convert_rule(self, rule: SigmaRule) -> List[str]:
       # Detect correlation rules by checking attributes
       if hasattr(rule, 'type') and hasattr(rule, 'rules') and hasattr(rule, 'timespan'):
           return self.convert_correlation_rule(rule)
       else:
           return super().convert_rule(rule)
   ```

2. **Template System**: Pre-defined PPL query templates for each correlation type
   ```python
   # All correlation types use the same structure (line 62-64)
   default_correlation_query = {
       "default": "{search} | stats {aggregate} | where {condition}"
   }
   
   # Different aggregations for different types
   event_count_aggregation = "count() as event_count by {groupby}"
   value_count_aggregation = "dc({field}) as value_count by {groupby}"
   ```

3. **Three-Phase Query Construction** (`convert_correlation_rule_from_template`):
   ```python
   # Phase 1: Search - get pre-converted detection rules
   search = self.convert_correlation_search(rule)
   
   # Phase 2: Aggregate - count/distinct count with grouping
   aggregate = self.convert_correlation_aggregation_from_template(...)
   
   # Phase 3: Condition - threshold filtering
   condition = self.convert_correlation_condition_from_template(...)
   
   # Assemble final query
   query = template.format(search=search, aggregate=aggregate, condition=condition)
   ```

### Technical Implementation Details

#### Enum Handling

Critical: Correlation types are **enums**, not strings:

```python
from sigma.correlations import SigmaCorrelationType

# CORRECT - enum comparison
if correlation_type == SigmaCorrelationType.VALUE_COUNT:
    # Extract field reference
    
# INCORRECT - string comparison (will always fail)
if correlation_type == "value_count":  # [X] Never matches!
```

#### Timespan Conversion

```python
def convert_timespan(self, timespan) -> str:
    """
    Converts Sigma timespan to PPL time range format.
    
    Input: SigmaCorrelationTimespan object or numeric value
    Output: Time range string (e.g., "5m", "1h", "24h")
    """
    if hasattr(timespan, 'seconds'):
        seconds = timespan.seconds
    else:
        seconds = int(timespan)
    
    # Convert to appropriate unit
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    elif seconds >= 60:
        return f"{seconds // 60}m"
    else:
        return f"{seconds}s"
```

#### Group By Field Mapping

```python
def convert_correlation_aggregation_groupby_from_template(
    self,
    group_by_fields: List[str],
    template_dict: PartialFormatDict
) -> str:
    """
    Generates PPL 'by' clause for aggregations.
    
    Input: ['user', 'source_ip']
    Output: "by user, source_ip"
    """
    if group_by_fields:
        return f"by {', '.join(group_by_fields)}"
    return ""
```

**PPL Reference**: [`stats` command with grouping](https://github.com/opensearch-project/sql/blob/main/docs/user/ppl/cmd/stats.md#example-3-calculate-the-average-of-a-field-by-group)

### Usage Examples

#### Event Count - Brute Force Detection

**Sigma Rule** (`brute_force_detection.yml`):
```yaml
title: Brute Force Attack Detection
correlation:
  type: event_count
  rules:
    - failed_login_attempt
  group-by:
    - user
    - source_ip
  timespan: 5m
  condition:
    gte: 10
```

**Generated PPL Query**:
```ppl
(source=auth-* | where event_type="login_failed") 
| stats count() as event_count by user, source_ip 
| where event_count >= 10
```

**Explanation**: Detects when a user experiences ≥10 failed logins from the same IP within 5 minutes.

#### Value Count - Password Spraying

**Sigma Rule** (`password_spraying.yml`):
```yaml
title: Password Spraying Detection
correlation:
  type: value_count
  rules:
    - failed_login
  group-by:
    - source_ip
  timespan: 30m
  condition:
    field: user
    gte: 5
```

**Generated PPL Query**:
```ppl
(source=auth-* | where event_type="login_failed") 
| stats dc(user) as value_count by source_ip 
| where value_count >= 5
```

**Explanation**: Detects when the same password is tried against ≥5 different user accounts from one IP within 30 minutes (classic password spraying pattern).

#### Temporal - Multi-Stage Attack

**Sigma Rule** (`successful_brute_force.yml`):
```yaml
title: Successful Brute Force
correlation:
  type: temporal
  rules:
    - failed_login
    - successful_login
  group-by:
    - user
  timespan: 10m
  condition:
    gte: 1
```

**Generated PPL Query**:
```ppl
| multisearch [search source=auth-* | where event_type="login_failed" AND @timestamp >= now() - 10m] [search source=auth-* | where event_type="login_success" AND @timestamp >= now() - 10m]
| stats count() as event_count by user 
| where event_count >= 1
```

**Explanation**: Correlates failed and successful login events for the same user within 10 minutes, indicating a successful brute force attack.

#### Temporal Ordered - Lateral Movement

**Sigma Rule** (`lateral_movement_detection.yml`):
```yaml
title: Lateral Movement Detection
correlation:
  type: temporal_ordered
  rules:
    - authentication_event
    - remote_execution
  group-by:
    - user
  timespan: 15m
  condition:
    gte: 1
```

**Generated PPL Query**:
```ppl
| multisearch [search source=security-* | where event_id=4624 AND @timestamp >= now() - 15m] [search source=security-* | where event_id IN (4688, 592) AND @timestamp >= now() - 15m]
| stats count() as event_count by user 
| where event_count >= 1
```

**Explanation**: Detects when authentication is followed by remote execution within 15 minutes (lateral movement indicator).

### Backend Initialization

```python
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLCorrelationBackend
from sigma.collection import SigmaCollection

# Load correlation rules (YAML with 'correlation' section)
rules = SigmaCollection.from_yaml("""
---
title: Brute Force Detection
correlation:
  type: event_count
  rules:
    - failed_login
  group-by:
    - user
  timespan: 5m
  condition:
    gte: 10
""")

# Initialize correlation backend
backend = OpenSearchPPLCorrelationBackend()

# Convert correlation rule
for rule in rules.rules:
    ppl_query = backend.convert_rule(rule)
    print(ppl_query[0])
```

### Testing

The backend includes comprehensive testing infrastructure in `tests/correlation_testing/`:

## Usage

### Installation

```bash
# Clone repository
git clone https://github.com/Adrian256256/sigma-opensearch-ppl-backend.git
cd sigma-opensearch-ppl-backend

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Programmatic Usage

#### Standard Detection Rules

```python
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

# Load Sigma rule
rule_yaml = """
title: Mimikatz Execution Detection
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\mimikatz.exe'
    CommandLine|contains:
      - 'sekurlsa'
      - 'lsadump'
  condition: selection
"""

# Parse and convert
sigma_rules = SigmaCollection.from_yaml(rule_yaml)
backend = OpenSearchPPLBackend()
ppl_queries = backend.convert(sigma_rules)

print(ppl_queries[0])
# Output: source=windows-process_creation-* | where LIKE(Image, "%\\mimikatz.exe") AND (LIKE(CommandLine, "%sekurlsa%") OR LIKE(CommandLine, "%lsadump%"))
```

#### Correlation Rules

For correlation rules that detect relationships between multiple events, use the `OpenSearchPPLCorrelationBackend`:

```python
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_correlations import OpenSearchPPLCorrelationBackend
from sigma.collection import SigmaCollection

# Load correlation rule with base rules
# Note: All rules (base + correlation) must be in the same YAML (separated by ---)
rule_yaml = """
title: Failed Login
name: failed_login
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Successful Login
name: successful_login
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
---
title: Successful Brute Force Detection
correlation:
  type: temporal
  rules:
    - failed_login
    - successful_login
  group-by:
    - IpAddress
    - TargetUserName
  timespan: 10m
"""

# Parse and convert
backend = OpenSearchPPLCorrelationBackend()
collection = SigmaCollection.from_yaml(rule_yaml)

# Backend automatically detects rule type (regular vs correlation)
for rule in collection.rules:
    queries = backend.convert_rule(rule)
    if queries:  # Only correlation rules return queries
        print(f"Rule: {rule.title}")
        print(f"Query: {queries[0]}\n")

# Output:
# Rule: Successful Brute Force Detection
# Query: | multisearch [search source=windows-security-* | where EventID=4625 AND @timestamp >= now() - 10m] [search source=windows-security-* | where EventID=4624 AND @timestamp >= now() - 10m] | stats count() as event_count by IpAddress, TargetUserName | where event_count >= 2
```

**Key points for correlation rules:**
- All rules (base detection rules + correlation rule) must be in the same YAML file, separated by `---`
- pySigma automatically resolves references between rules at parse time
- Backend detects rule type automatically (no need to call different methods)
- Base rules are converted internally; only correlation rules return PPL queries
- Supports all correlation types: `event_count`, `value_count`, `temporal`, `temporal_ordered`

### With Processing Pipeline

```python
from sigma.pipelines.opensearch import opensearch_pipeline

# Initialize backend with pipeline
backend = OpenSearchPPLBackend(processing_pipeline=opensearch_pipeline())
ppl_queries = backend.convert(sigma_rules)
```

### Command Line Usage

```bash
# Convert single rule
sigma convert -t opensearch_ppl rule.yml

# Convert directory of rules
sigma convert -t opensearch_ppl -o output/ rules/

# With specific pipeline
sigma convert -t opensearch_ppl -p opensearch rules/

# Convert with ECS field mapping
python manual_test/test_ecs_pipeline.py your_rule.yml
```

### Example Workflow

```python
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend
from sigma.collection import SigmaCollection
from pathlib import Path

# Load Sigma rules from directory
rules_dir = Path("sigma-rules/windows/process_creation")
sigma_rules = SigmaCollection.load_ruleset([str(rules_dir)])

# Initialize backend
backend = OpenSearchPPLBackend()

# Convert all rules
for rule in sigma_rules.rules:
    try:
        ppl_queries = backend.convert_rule(rule)
        for query in ppl_queries:
            print(f"# {rule.title}")
            print(query)
            print()
    except Exception as e:
        print(f"Error converting {rule.title}: {e}")
```

---

## Project Structure

```
sigma_backend/backends/opensearch_ppl/
├── __init__.py                        # Package initialization, modifier registration
├── opensearch_ppl_textquery.py        # Main backend implementation (base)
├── opensearch_ppl_correlations.py     # Correlation rules backend (extends base)
├── modifiers.py                       # Custom UTF-16 modifiers
└── README.md                          # This documentation file
```

### Files

- **`opensearch_ppl_textquery.py`**: Base backend class with standard Sigma rule conversion logic
- **`opensearch_ppl_correlations.py`**: Correlation rules extension with multi-event detection support
- **`modifiers.py`**: Custom Sigma modifiers for encoding (UTF-16 variants)
- **`__init__.py`**: Exports both backends and registers custom modifiers

---

## References

### OpenSearch PPL
- **Official Documentation**: [OpenSearch PPL](https://opensearch.org/docs/latest/search-plugins/sql/ppl/index/)
- **Commands & Functions**: [PPL Functions](https://opensearch.org/docs/latest/search-plugins/sql/ppl/functions/)
- **PPL Syntax**: [PPL Syntax](https://opensearch.org/docs/latest/search-plugins/sql/ppl/syntax/)
- **GitHub**: [OpenSearch SQL/PPL Docs](https://github.com/opensearch-project/sql/tree/main/docs/user/ppl)
- **Interactive Playground**: [OpenSearch Query Workbench](https://playground.opensearch.org/app/opensearch-query-workbench)

### Sigma & pySigma
- **Sigma Specification**: [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
- **Sigma Modifiers**: [Sigma Modifiers Documentation](https://sigmahq.io/docs/basics/modifiers.html)
- **Sigma Project**: [SigmaHQ GitHub](https://github.com/SigmaHQ/sigma)
- **Sigma Rule Repository**: [Sigma Rules](https://github.com/SigmaHQ/sigma/tree/master/rules)
- **pySigma Library**: [pySigma](https://github.com/SigmaHQ/pySigma)
- **pySigma Documentation**: [pySigma Docs](https://sigmahq-pysigma.readthedocs.io/)
- **TextQueryBackend Guide**: [pySigma TextQueryBackend](https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html)
- **TextQueryBackend Source Code**: [base.py](https://github.com/SigmaHQ/pySigma/blob/main/sigma/conversion/base.py)

### Related
- **Elastic Common Schema**: [ECS Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- **OpenSearch Dashboards**: [Query Workbench](https://opensearch.org/docs/latest/dashboards/query-workbench/)

---
