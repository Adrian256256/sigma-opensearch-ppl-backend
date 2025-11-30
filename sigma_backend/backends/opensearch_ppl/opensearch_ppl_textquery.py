"""
OpenSearch PPL backend for Sigma rules using TextQueryBackend.

This backend converts Sigma detection rules into PPL (Piped Processing Language)
queries for OpenSearch using the official pySigma TextQueryBackend infrastructure.
"""
from typing import ClassVar, Optional, Pattern, Dict, Union, Any
import re

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT


class OpenSearchPPLBackend(TextQueryBackend):
    """
    OpenSearch PPL backend using pySigma's TextQueryBackend.
    
    This backend leverages pySigma's built-in conversion infrastructure,
    requiring only configuration through class variables and minimal
    method overrides for PPL-specific behavior.
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
    str_quote: ClassVar[str] = ''  # No automatic quoting - we handle it in templates
    escape_char: ClassVar[str] = '\\'
    wildcard_multi: ClassVar[str] = "%"  # PPL uses % for multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # PPL uses _ for single-character wildcard
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    
    # String matching operators with PPL's LIKE() function
    # PPL uses: LIKE(field, "pattern") with % for wildcards
    # PPL uses: field = "exact" for exact match
    startswith_expression: ClassVar[str] = 'LIKE({field}, "{value}%")'
    endswith_expression: ClassVar[str] = 'LIKE({field}, "%{value}")'
    contains_expression: ClassVar[str] = 'LIKE({field}, "%{value}%")'
    wildcard_match_expression: ClassVar[str] = 'LIKE({field}, "{value}")'
    
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
    
    # Null value handling
    field_null_expression: ClassVar[str] = "{field} is null"
    
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
    
    def __init__(self, processing_pipeline: Optional[object] = None, **kwargs):
        """
        Initialize the OpenSearch PPL backend.
        
        Args:
            processing_pipeline: Optional processing pipeline for rule transformation
            **kwargs: Additional backend options
        """
        super().__init__(processing_pipeline, **kwargs)
    
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
            OpenSearch index pattern (e.g., "windows-process_creation-*")
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
        
        # Build complete PPL query with source command
        ppl_query = f"source = {index_pattern} | where {query}"
        
        return ppl_query
