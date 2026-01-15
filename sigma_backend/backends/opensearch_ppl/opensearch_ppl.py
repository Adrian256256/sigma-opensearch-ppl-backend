"""
OpenSearch PPL backend for Sigma rules.

This backend converts Sigma detection rules (both regular and correlation rules)
into PPL (Piped Processing Language) queries for OpenSearch.

Supports:
- Regular Sigma detection rules
- Correlation rules (event_count, value_count, temporal, temporal_ordered)
- All standard Sigma modifiers and features
"""
from typing import ClassVar, Optional, Pattern, Dict, Union, Any
import re

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationTypeLiteral,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaConversionError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT


class OpenSearchPPLBackend(TextQueryBackend):
    """
    OpenSearch PPL backend for both regular and correlation Sigma rules.
    
    This backend leverages pySigma's built-in conversion infrastructure,
    requiring only configuration through class variables and minimal
    method overrides for PPL-specific behavior.
    
    Features:
    - Converts regular Sigma detection rules to PPL queries
    - Supports correlation rules with multiple correlation types
    - Handles all standard Sigma modifiers (contains, startswith, etc.)
    - Supports CIDR notation, regex, field references, and more
    """
    
    # Backend metadata
    name: ClassVar[str] = "OpenSearch PPL Backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain PPL queries",
        "kibana": "Kibana dashboard format (future)",
    }
    requires_pipeline: ClassVar[bool] = False
    
    # Operator precedence (NOT > AND > OR)
    precedence: ClassVar[tuple] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"
    
    # Boolean operators for PPL
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="
    
    # Field quoting - PPL allows unquoted alphanumeric field names
    field_quote: ClassVar[str] = "`"  # Backticks for fields with special chars
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
    field_quote_pattern_negation: ClassVar[bool] = True  # Quote if pattern does NOT match
    
    # String quoting and escaping  
    str_quote: ClassVar[str] = '"'  # Double quotes for string values
    escape_char: ClassVar[str] = '\\'
    wildcard_multi: ClassVar[str] = "%"  # PPL uses % for multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # PPL uses _ for single-character wildcard
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    
    # String matching operators with PPL's LIKE() function
    # PPL uses: LIKE(field, "pattern") with % for wildcards  
    # PPL uses: field = "exact" for exact match
    # Template values will be auto-quoted by str_quote
    startswith_expression: ClassVar[str] = 'LIKE({field}, {value}%)'
    endswith_expression: ClassVar[str] = 'LIKE({field}, %{value})'
    contains_expression: ClassVar[str] = 'LIKE({field}, %{value}%)'
    wildcard_match_expression: ClassVar[str] = 'LIKE({field}, {value})'
    
    # Case-sensitive string matching with 'cased' modifier
    # PPL LIKE function with third parameter set to true enables case-sensitive matching
    # Format: LIKE(field, "pattern", true)
    case_sensitive_match_expression: ClassVar[str] = '{field}={value}'
    case_sensitive_startswith_expression: ClassVar[str] = 'LIKE({field}, {value}%, true)'
    case_sensitive_endswith_expression: ClassVar[str] = 'LIKE({field}, %{value}, true)'
    case_sensitive_contains_expression: ClassVar[str] = 'LIKE({field}, %{value}%, true)'
    
    # CIDR notation support
    # PPL supports: cidrmatch(field, "cidr")
    cidr_expression: ClassVar[str] = 'cidrmatch({field}, "{value}")'
    
    # Regular expressions in PPL
    # PPL supports: field match 'regex' or match(field, 'regex')
    re_expression: ClassVar[str] = "match({field}, '{regex}')"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[tuple] = ("\\", "'")
    
    # Comparison operators for numeric values
    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[Any, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }
    
    # Field existence checks
    field_exists_expression: ClassVar[str] = "isnotnull({field})"
    field_not_exists_expression: ClassVar[str] = "isnull({field})"
    
    # Null value handling - in PPL use isnull() function
    field_null_expression: ClassVar[str] = "isnull({field})"
    
    # Field-to-field comparison (fieldref modifier)
    # PPL supports direct field comparison: field1=field2
    field_equals_field_expression: ClassVar[str] = "{field1}={field2}"
    
    # List expressions (IN operator)
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} in ({list})"
    or_in_operator: ClassVar[str] = "in"
    list_separator: ClassVar[str] = ", "
    
    # Value expressions (for unbound values - not typical in Sigma)
    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    unbound_value_num_expression: ClassVar[str] = '{value}'
    
    # Query expression template - just the condition, we add source in finish_query
    query_expression: ClassVar[str] = "{query}"
    
    ### Correlation support ###
    
    # Correlation methods supported by this backend
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Default method",
    }
    
    # All correlation types use the same query structure:
    # {search} | stats {aggregate} | where {condition}
    default_correlation_query: ClassVar[Dict[str, str]] = {
        "default": "{search} | stats {aggregate} | where {condition}"
    }
    
    # Joiner between multiple rule queries (unused but kept for compatibility)
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " "
    
    # Aggregation expressions for different correlation types
    default_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "count() as event_count by {groupby}"
    }
    
    event_count_aggregation_expression: ClassVar[Dict[str, str]] = default_aggregation_expression
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = default_aggregation_expression
    temporal_ordered_aggregation_expression: ClassVar[Dict[str, str]] = default_aggregation_expression
    
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "dc({field}) as value_count by {groupby}"
    }
    
    # Convert timespan to seconds for PPL (False = use original format like 5m, 30m)
    timespan_seconds: ClassVar[bool] = False
    
    # Group-by expression templates
    groupby_expression: ClassVar[Dict[str, str]] = {"default": "{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}
    
    # Correlation condition expressions
    default_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "event_count {op} {count}",
    }
    
    event_count_condition_expression: ClassVar[Dict[str, str]] = default_condition_expression
    temporal_condition_expression: ClassVar[Dict[str, str]] = default_condition_expression
    temporal_ordered_condition_expression: ClassVar[Dict[str, str]] = default_condition_expression
    
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "value_count {op} {count}",
    }
    
    # Operator mapping for conditions
    correlation_condition_op: ClassVar[Dict[str, str]] = {
        "eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=",
    }
    
    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        **backend_options: Dict,
    ):
        """
        Initialize the OpenSearch PPL backend.
        
        Args:
            processing_pipeline: Optional processing pipeline for rule transformation
            collect_errors: If True, collect errors instead of raising them
            time_field: Name of the timestamp field (default: "@timestamp")
            **backend_options: Additional backend options
        """
        super().__init__(processing_pipeline, collect_errors=collect_errors, **backend_options)
        self._time_field: str = backend_options.get("time_field", "@timestamp")
    
    ### Regular rule conversion methods ###
    
    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize the query by adding the source command.
        
        This method is called after the condition has been converted to add
        PPL-specific elements like the source index pattern.
        
        Args:
            rule: The Sigma rule being converted
            query: The converted condition query
            index: Query index (if rule generates multiple queries)
            state: Conversion state
            
        Returns:
            Complete PPL query with source command
        """
        # Correlation rules are already finalized
        if isinstance(rule, SigmaCorrelationRule):
            return query
        
        # Get index pattern from logsource
        index_pattern = self._get_index_pattern(rule)
        
        # Build complete PPL query
        # The query_expression template is already applied in finish_query
        # We just need to ensure the state has the index
        state.processing_state["index"] = index_pattern
        
        return query
    
    def finalize_output_default(self, queries: list[str]) -> list[str]:
        """
        Finalize the output by returning the list of queries.
        
        Args:
            queries: List of generated PPL queries
            
        Returns:
            List of PPL query strings
        """
        return queries
    
    def _get_index_pattern(self, rule: SigmaRule) -> str:
        """
        Extract OpenSearch index pattern from Sigma logsource.
        
        Maps Sigma logsource (product, category, service) to OpenSearch
        index patterns. This is a simple implementation that can be
        extended with configurable mappings.
        
        Args:
            rule: Sigma rule containing logsource information
            
        Returns:
            OpenSearch index pattern ("windows-process_creation-*")
        """
        logsource = rule.logsource
        product = getattr(logsource, 'product', None)
        category = getattr(logsource, 'category', None)
        service = getattr(logsource, 'service', None)
        
        # Build index pattern from logsource components
        index_parts = []
        
        if product:
            index_parts.append(product)
        
        if category:
            index_parts.append(category)
        
        if service:
            index_parts.append(service)
        
        # Build final index pattern
        if index_parts:
            return '-'.join(index_parts) + '-*'
        else:
            # Fallback to wildcard if no logsource specified
            return '*'
    
    def finish_query(
        self, rule: SigmaRule, query: str, state: ConversionState
    ) -> str:
        """
        Finish the query before finalization.
        
        This is called before finalize_query and is where we can add
        the source command and other PPL-specific structure.
        
        Args:
            rule: The Sigma rule being converted
            query: The converted condition
            state: Conversion state
            
        Returns:
            Query with PPL source command added
        """
        # Get index pattern from logsource
        index_pattern = self._get_index_pattern(rule)
        
        # Handle deferred expressions (if any)
        query = super().finish_query(rule, query, state)
        
        # Fix LIKE expressions: move wildcards inside quotes
        # Handle all patterns in one comprehensive replacement
        def fix_wildcards(match):
            leading = match.group(1) or ''  # % before "
            content = match.group(2)         # content between quotes
            trailing = match.group(3) or ''  # % after "
            return f'"{leading}{content}{trailing}"'
        
        query = re.sub(r'(%?)"([^"]*)\"(%?)', fix_wildcards, query)
        
        # Build complete PPL query with source command
        ppl_query = f"source={index_pattern} | where {query}"
        
        return ppl_query
    
    ### Correlation rule conversion methods ###
    
    def convert_rule(self, rule: SigmaRule, output_format: str = "default", callback=None) -> list[str]:
        """
        Convert a Sigma rule (regular or correlation) to PPL query.
        
        Args:
            rule: The Sigma rule to convert (can be regular or correlation)
            output_format: Output format to use
            callback: Optional callback function
            
        Returns:
            List of generated PPL queries
        """
        # Check if this is a correlation rule
        if hasattr(rule, 'type') and hasattr(rule, 'rules') and hasattr(rule, 'timespan'):
            return self.convert_correlation_rule(rule, method="default")
        else:
            return super().convert_rule(rule, output_format, callback)
    
    def convert_correlation_rule(
        self, rule: SigmaCorrelationRule, method: str = "default"
    ) -> list[str]:
        """
        Convert a Sigma correlation rule to PPL query.
        
        Args:
            rule: The correlation rule to convert
            method: Correlation method to use (default: "default")
            
        Returns:
            List containing the generated PPL query
        """
        return self.convert_correlation_rule_from_template(rule, rule.type, method)
    
    def convert_correlation_rule_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> list[str]:
        """
        Convert correlation rule using templates.
        
        Orchestrates the three phases: Search, Aggregate, Condition.
        
        Args:
            rule: The correlation rule to convert
            correlation_type: Type of correlation (event_count, value_count, etc.)
            method: Correlation method to use
            
        Returns:
            List containing the generated PPL query
        """
        # Get template - all types use default_correlation_query now
        template = self.default_correlation_query
        
        if template is None or method not in template:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported by backend for "
                f"correlation type '{correlation_type}'."
            )
        
        # Generate the three phases
        search = self.convert_correlation_search(rule)
        aggregate = self.convert_correlation_aggregation_from_template(
            rule, correlation_type, method, search
        )
        condition = self.convert_correlation_condition_from_template(
            rule.condition, rule.rules, correlation_type, method, rule
        )
        
        # Build final query from template
        query = template[method].format(
            search=search,
            aggregate=aggregate,
            condition=condition,
        )
        
        return [query]
    
    def convert_correlation_search(self, rule: SigmaCorrelationRule, **kwargs) -> str:
        """
        Convert the search phase of a correlation rule.
        
        For temporal correlations, uses multisearch: | multisearch [search ...] [search ...]
        For simple aggregations (event_count, value_count), generates a single source query.
        
        Args:
            rule: The correlation rule
            **kwargs: Additional arguments
            
        Returns:
            Combined search expression
        """
        timespan = self._format_timespan(rule.timespan)
        is_temporal = rule.type in [SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED]
        
        # Build queries for all referred rules
        queries = []
        for rule_reference in rule.rules:
            referred_rule = rule_reference.rule
            for query in referred_rule.get_conversion_result():
                # Extract source and where parts
                if " | where " in query:
                    parts = query.split(" | where ", 1)
                    source_part = parts[0]
                    where_part = parts[1]
                else:
                    source_part = query if query.startswith("source=") else "source=*"
                    where_part = None
                
                if is_temporal:
                    # Temporal: build subsearch [search source=... | where ... AND @timestamp >= now() - timespan]
                    if where_part:
                        subsearch = f"[search {source_part} | where {where_part} AND {self._time_field} >= now() - {timespan}]"
                    else:
                        subsearch = f"[search {source_part} | where {self._time_field} >= now() - {timespan}]"
                    queries.append(subsearch)
                else:
                    # Simple: single query with time filter in WHERE clause
                    if where_part:
                        queries.append(f"{source_part} | where {where_part} AND {self._time_field} >= now() - {timespan}")
                    else:
                        queries.append(f"{source_part} | where {self._time_field} >= now() - {timespan}")
        
        # Return multisearch for temporal, single query for others
        if is_temporal:
            return "| multisearch " + " ".join(queries)
        else:
            return queries[0] if queries else ""
    
    def _format_timespan(self, timespan) -> str:
        """Format timespan for PPL query ("5m", "30m", "2h")."""
        if hasattr(timespan, 'spec'):
            return str(timespan.spec)
        elif hasattr(timespan, 'total_seconds'):
            seconds = int(timespan.total_seconds())
            if seconds % 3600 == 0:
                return f"{seconds // 3600}h"
            elif seconds % 60 == 0:
                return f"{seconds // 60}m"
            else:
                return f"{seconds}s"
        else:
            return str(timespan)
    
    def convert_correlation_aggregation_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        search: str,
    ) -> str:
        """Convert the aggregation phase of a correlation rule."""
        templates = getattr(self, f"{correlation_type}_aggregation_expression", self.default_aggregation_expression)
        template = templates[method]
        
        # Get field for value_count correlation
        field = ""
        if (correlation_type == "value_count" or 
            correlation_type == SigmaCorrelationType.VALUE_COUNT) and rule.condition:
            if hasattr(rule.condition, 'fieldref') and rule.condition.fieldref:
                field = rule.condition.fieldref
        
        return template.format(
            groupby=self.convert_correlation_aggregation_groupby_from_template(rule.group_by, method),
            field=field,
        )
    
    def convert_correlation_aggregation_groupby_from_template(
        self, group_by: Optional[list[str]], method: str
    ) -> str:
        """Convert group-by fields to PPL format."""
        if not group_by:
            return ""
        
        fields = self.groupby_field_expression_joiner[method].join(
            self.groupby_field_expression[method].format(field=field)
            for field in group_by
        )
        
        return self.groupby_expression[method].format(fields=fields)
    
    def convert_correlation_condition_from_template(
        self,
        condition: Any,
        rules: list,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        rule: SigmaCorrelationRule,
    ) -> str:
        """Convert the condition phase of a correlation rule."""
        templates = getattr(self, f"{correlation_type}_condition_expression", self.default_condition_expression)
        template = templates[method]
        
        # Extract operator and count from condition
        if hasattr(condition, 'op') and hasattr(condition, 'count'):
            op_str = condition.op.name  # Get enum name ('GTE')
            count = condition.count
        elif isinstance(condition, dict):
            op_str = list(condition.keys())[0].upper()
            count = list(condition.values())[0]
        else:
            raise SigmaConversionError(f"Unsupported condition format: {condition}")
        
        # Map operator to PPL format
        op_str_lower = op_str.lower()
        if op_str_lower not in self.correlation_condition_op:
            raise SigmaConversionError(f"Unsupported condition operator: {op_str}")
        
        op = self.correlation_condition_op[op_str_lower]
        
        # Get field if needed for value_count
        field = ""
        if correlation_type == "value_count" and hasattr(condition, 'fieldref'):
            field = condition.fieldref or ""
        
        return template.format(op=op, count=count, field=field)
