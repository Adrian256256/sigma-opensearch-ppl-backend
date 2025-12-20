"""
OpenSearch PPL backend with correlation rule support.

This module extends the base OpenSearch PPL backend to support Sigma correlation rules,
enabling detection of complex patterns across multiple events within time windows.
"""
from typing import ClassVar, Dict, Optional, Any
from sigma.conversion.state import ConversionState
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationTypeLiteral,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaConversionError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

from .opensearch_ppl_textquery import OpenSearchPPLBackend


class OpenSearchPPLCorrelationBackend(OpenSearchPPLBackend):
    """
    OpenSearch PPL backend with correlation rule support.
    
    This backend extends the base OpenSearchPPLBackend to convert Sigma correlation rules
    into PPL queries that can detect complex patterns across multiple events.
    
    Supported correlation types:
    - event_count: Count events in aggregation bucket
    - value_count: Count distinct values of a field
    - temporal: Multiple event types close in time (order doesn't matter)
    - temporal_ordered: Multiple event types in specific order
    """
    
    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        **backend_options: Dict,
    ):
        """
        Initialize the OpenSearch PPL correlation backend.
        
        Args:
            processing_pipeline: Optional processing pipeline for rule transformation
            collect_errors: If True, collect errors instead of raising them
            time_field: Name of the timestamp field (default: "@timestamp")
            **backend_options: Additional backend options
        """
        super().__init__(processing_pipeline, collect_errors=collect_errors, **backend_options)
        self._time_field: str = backend_options.get("time_field", "@timestamp")
    
    # Correlation methods supported by this backend
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Default method",
    }
    
    ### Correlation query templates ###
    
    # All correlation types use the same query structure:
    # {search} | stats {aggregate} | where {condition}
    default_correlation_query: ClassVar[Dict[str, str]] = {
        "default": "{search} | stats {aggregate} | where {condition}"
    }
    
    ## Correlation query search phase ##
    
    # Joiner between multiple rule queries (unused but kept for compatibility)
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " "
    
    ## Correlation query aggregation phase ##
    
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
    
    ## Group-by expression templates ##
    
    groupby_expression: ClassVar[Dict[str, str]] = {"default": "{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}
    
    ## Correlation query condition phase ##
    
    # All correlation types use similar condition expressions
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
    
    ### Correlation conversion methods ###
    
    def convert_rule(self, rule: SigmaRule, output_format: str = "default") -> list[str]:
        """
        Convert a Sigma rule (regular or correlation) to PPL query.
        
        Args:
            rule: The Sigma rule to convert (can be regular or correlation)
            output_format: Output format to use
            
        Returns:
            List of generated PPL queries
        """
        # Check if this is a correlation rule
        if hasattr(rule, 'type') and hasattr(rule, 'rules') and hasattr(rule, 'timespan'):
            return self.convert_correlation_rule(rule, method="default")
        else:
            return super().convert_rule(rule, output_format)
    
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
        from sigma.correlations import SigmaCorrelationType
        
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
        """Format timespan for PPL query (e.g., "5m", "30m", "2h")."""
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
            op_str = condition.op.name  # Get enum name (e.g., 'GTE')
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
    
    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        """Finalize query - handle both regular rules and correlation rules."""
        # Correlation rules are already finalized, regular rules use parent's finalization
        if isinstance(rule, SigmaCorrelationRule):
            return query
        return super().finalize_query_default(rule, query, index, state)
