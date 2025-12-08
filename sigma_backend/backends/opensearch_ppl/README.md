# OpenSearch PPL Backend for Sigma

Backend for converting Sigma detection rules into PPL (Piped Processing Language) queries for OpenSearch.

## Table of Contents

1. [Overview](#overview)
2. [Implementation](#implementation)
   - [OpenSearchPPLBackend Class](#opensearchpplbackend-class)
   - [Configuration via Class Variables](#configuration-via-class-variables)
   - [Core Methods](#core-methods)
3. [Sigma → PPL Conversion](#sigma--ppl-conversion)
   - [Syntax Mapping](#syntax-mapping)
   - [Conversion Example](#conversion-example)
4. [PPL Functions Used](#ppl-functions-used)
5. [Usage](#usage)
6. [References](#references)

---

## Overview

**OpenSearchPPLBackend** is a pySigma backend that converts Sigma detection rules into PPL queries for OpenSearch. The implementation is based on pySigma's `TextQueryBackend` class, providing an elegant and maintainable solution.

**Features**:
- Automatic conversion of logical operators (AND, OR, NOT) with correct precedence
- Full support for Sigma modifiers (contains, startswith, endswith, etc.)
- Wildcard conversion: `*` → `%`, `?` → `_`
- Support for regular expressions, numeric comparisons, CIDR notation
- Field existence and null value checks
- Automatic logsource → index pattern mapping

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

# CIDR notation
cidr_expression: ClassVar[str] = 'cidrmatch({field}, "{value}")'

# Field existence
field_exists_expression: ClassVar[str] = "isnotnull({field})"
field_not_exists_expression: ClassVar[str] = "isnull({field})"

# Null checks
field_null_expression: ClassVar[str] = "isnull({field})"

# Field-to-field comparison
field_equals_field_expression: ClassVar[str] = "{field1}={field2}"

# IN operator
field_in_list_expression: ClassVar[str] = "{field} in ({list})"
convert_or_as_in: ClassVar[bool] = True
```

### Core Methods

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

### Conversion Example

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
```

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
- **pySigma Library**: [pySigma](https://github.com/SigmaHQ/pySigma)
- **pySigma Documentation**: [pySigma Docs](https://sigmahq-pysigma.readthedocs.io/)
