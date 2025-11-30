# OpenSearch PPL Backend for Sigma

This backend converts Sigma detection rules into PPL (Piped Processing Language) queries for OpenSearch.

## Table of Contents

- [Sigma Rule Data Structure](#sigma-rule-data-structure)
  - [Main Structure](#main-structure)
  - [Key Concepts](#key-concepts)
- [Sigma YAML Syntax](#sigma-yaml-syntax)
  - [Dash (-) Logic: AND vs OR](#dash---logic-and-vs-or)
- [PPL Commands Used in Conversion](#ppl-commands-used-in-conversion)
  - [Core Commands](#core-commands)
  - [Pattern Matching](#pattern-matching)
  - [String Functions](#string-functions)
  - [Additional Commands](#additional-commands)
- [Structure of Generated PPL Query](#structure-of-generated-ppl-query)
- [Sigma → PPL Mapping](#sigma---ppl-mapping)
- [Implementation Architecture](#implementation-architecture)
  - [Backend Implementations](#backend-implementations)
    - [1. `opensearch_ppl.py` - Manual/Legacy Backend](#1-opensearch_pplpy---manuallegacy-backend)
    - [2. `opensearch_ppl_textquery.py` - Production Backend ✅](#2-opensearch_ppl_textquerypy---production-backend-)
  - [Core Components](#core-components)
    - [Configuration via Class Variables](#configuration-via-class-variables)
    - [Key Methods](#key-methods)
  - [Conversion Flow](#conversion-flow)
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

This backend uses the following PPL commands to convert Sigma rules into queries:

### Core Commands

**1. `source` - Index Specification**
```ppl
source = index_pattern
```
Maps Sigma `logsource` to OpenSearch indices using pattern: `{product}-{category}-{service}-*`

Example: `source = windows-process_creation-*`

**2. `where` - Filtering**
```ppl
source = index | where condition
```
Converts Sigma detection conditions. Supports: `=`, `!=`, `>`, `<`, `>=`, `<=`, `AND`, `OR`, `NOT`, `like`

Example: `source = windows-* | where EventID = 1 AND CommandLine like "%whoami%"`

**3. `fields` - Field Selection**
```ppl
source = index | where condition | fields field1, field2
```
Returns only specified fields from Sigma rule.

Example: `source = windows-* | where EventID = 1 | fields EventID, CommandLine, User`

**4. `stats` - Aggregations**
```ppl
source = index | where condition | stats count() by field
```
Functions: `count()`, `sum()`, `avg()`, `min()`, `max()`, `distinct_count()`

Example: `source = windows-* | where EventID = 4625 | stats count() by SourceIP`

### Pattern Matching

**`like` operator:**
- `%` = wildcard (multiple characters)
- `_` = single character

Example: `where CommandLine like "%powershell%"`

**`match()` function for regex:**
```ppl
where match(field, 'regex_pattern')
```

### String Functions

- `lower(field)`, `upper(field)` - case conversion
- `substring(field, start, length)` - extract substring
- `concat(field1, field2)` - concatenate
- `trim(field)` - remove whitespace

Example: `where lower(CommandLine) like "%powershell%"`

### Additional Commands

- `eval` - create/transform fields
- `dedup` - remove duplicates
- `sort` - order results
- `head`/`tail` - limit results

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

---

## Implementation Architecture

### Backend Implementations

**Two implementations available:**

#### 1. `opensearch_ppl.py` - Manual/Legacy Backend
- **Status:** Placeholder (educational purpose)
- Detailed documentation and method templates
- Returns `"where true"` - not functional

#### 2. `opensearch_ppl_textquery.py` - Production Backend ✅
- **Status:** Fully functional, production-ready
- Uses pySigma's `TextQueryBackend` infrastructure
- Configuration-driven via class variables
- Automatic handling: operators, quoting, wildcards, comparisons

### Core Components

#### Configuration via Class Variables

```python
class OpenSearchPPLBackend(TextQueryBackend):
    # Operators
    or_token = "OR"
    and_token = "AND"
    not_token = "NOT"
    
    # String matching templates
    contains_expression = '{field} like "*{value}*"'
    startswith_expression = '{field} like "{value}*"'
    endswith_expression = '{field} like "*{value}"'
    
    # Comparison operators
    compare_operators = {
        CompareOperators.LT: "<",
        CompareOperators.GT: ">",
        # ...
    }
```

#### Key Methods

**`finish_query()`** - Assembles final PPL query:
```python
def finish_query(self, rule, query, state):
    index = self._get_index_pattern(rule)  # Get index from logsource
    return f"source = {index} | where {query}"
```

**`_get_index_pattern()`** - Maps logsource to index:
```python
def _get_index_pattern(self, rule):
    # Extract: product, category, service
    # Build: "product-category-service-*"
    # Example: "windows-process_creation-*"
```

### Conversion Flow

```
Sigma YAML → SigmaCollection → TextQueryBackend Processing → finish_query() → PPL Query
```

**Example:**
```yaml
# Input
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
  condition: selection
```
↓
```
# Output
['source = windows-process_creation-* | where EventID=1 AND Image like "*\\powershell.exe"']
```

---

## References

- [OpenSearch PPL Documentation](https://opensearch.org/docs/latest/search-plugins/sql/ppl/index/)
- [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
- [Sigma Project](https://github.com/SigmaHQ/sigma)
