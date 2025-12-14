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
7. [Usage](#usage)
8. [Project Structure](#project-structure)
9. [References](#references)

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

### Integration with OpenSearch

Once you have PPL queries, you can use them directly in OpenSearch:

```bash
# Using OpenSearch REST API
curl -X POST "localhost:9200/_plugins/_ppl" \
  -H "Content-Type: application/json" \
  -d '{"query": "source=windows-* | where LIKE(Image, \"%powershell.exe%\")"}'

# Using OpenSearch Dashboards Query Workbench
# Navigate to: OpenSearch Dashboards > Query Workbench > PPL
# Paste and execute your PPL query
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
├── __init__.py                      # Package initialization, modifier registration
├── opensearch_ppl_textquery.py      # Main backend implementation
├── modifiers.py                     # Custom UTF-16 modifiers
└── README.md                        # This documentation file
```

### Files

- **`opensearch_ppl_textquery.py`**: Main backend class with all conversion logic
- **`modifiers.py`**: Custom Sigma modifiers for encoding (UTF-16 variants)
- **`__init__.py`**: Exports backend and registers custom modifiers

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
