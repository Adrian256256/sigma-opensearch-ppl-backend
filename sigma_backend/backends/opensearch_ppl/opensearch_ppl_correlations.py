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


class PartialFormatDict(dict):
    """
    A dictionary subclass that handles missing keys by returning the key name in curly braces.
    
    This is useful for template formatting where some placeholders might not be needed
    for certain correlation types.
    """
    def __missing__(self, key):
        return "{" + key + "}"


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
    
    # Default timestamp field for OpenSearch
    default_time_field: ClassVar[str] = "@timestamp"
    
    # Correlation methods supported by this backend
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Default method",
    }
    
    ### Correlation query templates ###
    
    ## Correlation query frame
    # The correlation query frame is the basic structure for each correlation type.
    # Placeholders:
    # * {search} - search expression from correlation query search phase
    # * {aggregate} - aggregation expression from correlation query aggregation phase
    # * {condition} - condition expression from correlation query condition phase
    # * {timefield} - the timestamp field name
    
    default_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    
    # event_count correlation: counts events in time window
    event_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": (
            "{search}"
            " | stats {aggregate}"
            " | where {condition}"
        )
    }
    
    # value_count correlation: counts distinct values of a field
    value_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": (
            "{search}"
            " | stats {aggregate}"
            " | where {condition}"
        )
    }
    
    # temporal correlation: events close in time
    temporal_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": (
            "{search}"
            " | stats {aggregate}"
            " | where {condition}"
        )
    }
    
    # temporal_ordered correlation: events in specific order
    temporal_ordered_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": (
            "{search}"
            " | stats {aggregate}"
            " | where {condition}"
        )
    }
    
    ## Correlation query search phase ##
    
    # Multi-rule search expression (for multiple correlated rules)
    correlation_search_multi_rule_expression: ClassVar[Optional[str]] = "{queries}"
    
    # Query expression for each individual rule in correlation
    correlation_search_multi_rule_query_expression: ClassVar[Optional[str]] = "{query}"
    
    # Joiner string between multiple rule queries (PPL uses multisearch with square brackets)
    correlation_search_multi_rule_query_expression_joiner: ClassVar[Optional[str]] = (
        " "
    )
    
    ## Correlation query aggregation phase ##
    
    # event_count aggregation: count events grouped by fields within timespan
    event_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "count() as event_count by {groupby}"
    }
    
    # value_count aggregation: count distinct values of a field
    value_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "dc({field}) as value_count by {groupby}"
    }
    
    # temporal aggregation: group events close in time
    temporal_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "count() as event_count by {groupby}"
    }
    
    # temporal_ordered aggregation: group events in order
    temporal_ordered_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "count() as event_count by {groupby}"
    }
    
    # Convert timespan to seconds for PPL (False = use original format like 5m, 30m)
    timespan_seconds: ClassVar[bool] = False
    
    ## Group-by expression templates ##
    
    groupby_expression: ClassVar[Dict[str, str]] = {"default": "{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}
    
    ## Correlation query condition phase ##
    
    # Condition expressions filter aggregated results
    # Placeholders:
    # * {op} - condition operator (mapped from condition)
    # * {count} - count value from condition
    # * {field} - field name from condition
    
    event_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "event_count {op} {count}",
    }
    
    value_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "value_count {op} {count}",
    }
    
    temporal_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "event_count {op} {count}",
    }
    
    temporal_ordered_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "event_count {op} {count}",
    }
    
    # Operator mapping for conditions
    correlation_condition_op: ClassVar[Dict[str, str]] = {
        "eq": "=",
        "ne": "!=",
        "lt": "<",
        "lte": "<=",
        "gt": ">",
        "gte": ">=",
    }
    
    ### Correlation conversion methods ###
    
    def convert_rule(self, rule: SigmaRule, output_format: str = "default") -> list[str]:
        """
        Convert a Sigma rule (regular or correlation) to PPL query.
        
        This method overrides the parent to detect and handle correlation rules.
        
        Args:
            rule: The Sigma rule to convert (can be regular or correlation)
            output_format: Output format to use
            
        Returns:
            List of generated PPL queries
        """
        # Check if this is a correlation rule by checking for the type attribute
        if hasattr(rule, 'type') and hasattr(rule, 'rules') and hasattr(rule, 'timespan'):
            # This is a correlation rule
            return self.convert_correlation_rule(rule, method="default")
        else:
            # Regular rule - use parent's convert_rule
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
        correlation_type = rule.type
        return self.convert_correlation_rule_from_template(
            rule, correlation_type, method
        )
    
    def convert_correlation_rule_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> list[str]:
        """
        Convert correlation rule using templates.
        
        This method orchestrates the three phases of correlation query generation:
        1. Search: Find events matching referred rules
        2. Aggregate: Group and aggregate events
        3. Condition: Filter aggregated results
        
        Args:
            rule: The correlation rule to convert
            correlation_type: Type of correlation (event_count, value_count, etc.)
            method: Correlation method to use
            
        Returns:
            List containing the generated PPL query
        """
        # Get template for this correlation type
        template = (
            getattr(self, f"{correlation_type}_correlation_query")
            or self.default_correlation_query
        )
        
        if template is None:
            raise NotImplementedError(
                f"Correlation rule type '{correlation_type}' is not supported by backend."
            )
        
        if method not in template:
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
        query = template[method].format_map(
            PartialFormatDict(
                timefield=self._time_field,
                search=search,
                aggregate=aggregate,
                condition=condition,
            )
        )
        
        return [query]
    
    def convert_correlation_search(
        self,
        rule: SigmaCorrelationRule,
        **kwargs,
    ) -> str:
        """
        Convert the search phase of a correlation rule.
        
        Generates PPL queries for all referred rules and combines them using multisearch.
        For temporal correlations, uses multisearch syntax: | multisearch [search ...] [search ...]
        For simple aggregations (event_count, value_count), generates a single source query.
        
        Args:
            rule: The correlation rule
            **kwargs: Additional arguments
            
        Returns:
            Combined search expression
        """
        from sigma.correlations import SigmaCorrelationType
        
        correlation_type = rule.type
        timespan = self._format_timespan(rule.timespan)
        
        # For temporal/temporal_ordered, we need multiple subsearches with multisearch
        if correlation_type in [SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED]:
            subsearches = []
            for rule_reference in rule.rules:
                referred_rule = rule_reference.rule
                for query in referred_rule.get_conversion_result():
                    # Extract the WHERE conditions from the query
                    if " | where " in query:
                        # Split to get source and where parts
                        parts = query.split(" | where ", 1)
                        source_part = parts[0]  # e.g., "source=windows-security-*"
                        where_part = parts[1]    # e.g., "EventID=4625"
                        
                        # Build subsearch with time filter: [search source=... | where ... AND @timestamp >= now() - timespan]
                        subsearch = f"[search {source_part} | where {where_part} AND {self._time_field} >= now() - {timespan}]"
                        subsearches.append(subsearch)
                    else:
                        # Fallback if query doesn't have expected format
                        source_part = query if query.startswith("source=") else f"source=*"
                        subsearch = f"[search {source_part} | where {self._time_field} >= now() - {timespan}]"
                        subsearches.append(subsearch)
            
            # Join subsearches with space and prefix with | multisearch
            return "| multisearch " + " ".join(subsearches)
        
        else:
            # For event_count/value_count: single source query with time filter in WHERE
            queries = []
            for rule_reference in rule.rules:
                referred_rule = rule_reference.rule
                for query in referred_rule.get_conversion_result():
                    # Keep the full query but we'll add time filter to WHERE clause
                    if " | where " in query:
                        parts = query.split(" | where ", 1)
                        source_part = parts[0]
                        where_part = parts[1]
                        # Add time filter to WHERE clause
                        query_with_time = f"{source_part} | where {where_part} AND {self._time_field} >= now() - {timespan}"
                        queries.append(query_with_time)
                    else:
                        # If no WHERE, add it
                        queries.append(f"{query} | where {self._time_field} >= now() - {timespan}")
            
            # For single rule correlations, return the first query
            return queries[0] if queries else ""
    
    def _format_timespan(self, timespan) -> str:
        """
        Format timespan for PPL query.
        
        Args:
            timespan: Timespan object from Sigma rule
            
        Returns:
            Formatted timespan string (e.g., "5m", "30m", "2h")
        """
        # Check if timespan has a 'spec' attribute (SigmaCorrelationTimespan object)
        if hasattr(timespan, 'spec'):
            return str(timespan.spec)
        # Convert timespan to string format (e.g., "5m" instead of "300s")
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
        """
        Convert the aggregation phase of a correlation rule.
        
        Args:
            rule: The correlation rule
            correlation_type: Type of correlation
            method: Correlation method
            search: Search expression from previous phase
            
        Returns:
            Aggregation expression
        """
        templates = getattr(self, f"{correlation_type}_aggregation_expression")
        if templates is None:
            raise NotImplementedError(
                f"Correlation type '{correlation_type}' is not supported by backend."
            )
        
        template = templates[method]
        
        # Get the field for value_count correlation
        field = ""
        # Check if this is value_count correlation (correlation_type is an enum)
        if (correlation_type == "value_count" or 
            correlation_type == SigmaCorrelationType.VALUE_COUNT) and rule.condition:
            # Extract field from condition if available  
            if hasattr(rule.condition, 'fieldref') and rule.condition.fieldref:
                field = rule.condition.fieldref
        
        aggregation = template.format_map(
            PartialFormatDict(
                timefield=self._time_field,
                groupby=self.convert_correlation_aggregation_groupby_from_template(
                    rule.group_by, method
                ),
                timespan=self.convert_timespan(rule.timespan, method),
                field=field,
            )
        )
        
        return aggregation
    
    def convert_correlation_aggregation_groupby_from_template(
        self,
        group_by: Optional[list[str]],
        method: str,
    ) -> str:
        """
        Convert group-by fields to PPL format.
        
        Args:
            group_by: List of fields to group by
            method: Correlation method
            
        Returns:
            Group-by expression
        """
        if not group_by:
            return ""
        
        # Format each field
        fields = self.groupby_field_expression_joiner[method].join(
            self.groupby_field_expression[method].format(field=field)
            for field in group_by
        )
        
        return self.groupby_expression[method].format(fields=fields)
    
    def convert_timespan(
        self,
        timespan: Any,
        method: str,
    ) -> str:
        """
        Convert timespan to PPL format.
        
        Args:
            timespan: Timespan value (SigmaCorrelationTimespan object or string)
            method: Correlation method
            
        Returns:
            Timespan in appropriate format
        """
        # Check if it's a SigmaCorrelationTimespan object
        if hasattr(timespan, 'seconds'):
            # It's a SigmaCorrelationTimespan object
            if self.timespan_seconds:
                return f"{timespan.seconds}s"
            else:
                return timespan.spec
        
        # Otherwise, parse as string (e.g., "5m" -> 300 seconds)
        timespan_str = str(timespan)
        
        # Extract number and unit
        import re
        match = re.match(r'(\d+)([smhd])', timespan_str)
        if not match:
            raise SigmaConversionError(f"Invalid timespan format: {timespan_str}")
        
        value = int(match.group(1))
        unit = match.group(2)
        
        # Convert to seconds if needed
        if self.timespan_seconds:
            multipliers = {
                's': 1,
                'm': 60,
                'h': 3600,
                'd': 86400,
            }
            seconds = value * multipliers[unit]
            return f"{seconds}s"
        
        return timespan_str
    
    def convert_correlation_condition_from_template(
        self,
        condition: Any,
        rules: list,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        rule: SigmaCorrelationRule,
    ) -> str:
        """
        Convert the condition phase of a correlation rule.
        
        Args:
            condition: The correlation condition (SigmaCorrelationCondition object)
            rules: List of referred rules
            correlation_type: Type of correlation
            method: Correlation method
            rule: The correlation rule
            
        Returns:
            Condition expression
        """
        templates = getattr(self, f"{correlation_type}_condition_expression")
        if templates is None:
            raise NotImplementedError(
                f"Correlation type '{correlation_type}' is not supported by backend."
            )
        
        template = templates[method]
        
        # Extract operator and count from SigmaCorrelationCondition object
        if hasattr(condition, 'op') and hasattr(condition, 'count'):
            # It's a SigmaCorrelationCondition object
            op_enum = condition.op
            count = condition.count
            
            # Map the operator enum to string
            # SigmaCorrelationConditionOperator enum values: GT, GTE, LT, LTE, EQ, NE
            op_mapping = {
                'GT': 'gt',
                'GTE': 'gte',
                'LT': 'lt',
                'LTE': 'lte',
                'EQ': 'eq',
                'NE': 'ne',
            }
            
            op_str = op_enum.name  # Get the enum name (e.g., 'GTE')
            op_str = op_mapping.get(op_str, op_str.lower())
            
        elif isinstance(condition, dict):
            # Legacy format: {"gte": 10}
            op_str = list(condition.keys())[0]
            count = list(condition.values())[0]
        else:
            raise SigmaConversionError(f"Unsupported condition format: {condition}")
        
        # Map operator to PPL format
        if op_str not in self.correlation_condition_op:
            raise SigmaConversionError(f"Unsupported condition operator: {op_str}")
        
        op = self.correlation_condition_op[op_str]
        
        # Get field if needed for value_count
        field = ""
        if correlation_type == "value_count" and hasattr(condition, 'fieldref'):
            field = condition.fieldref or ""
        
        condition_expr = template.format_map(
            PartialFormatDict(
                op=op,
                count=count,
                field=field,
            )
        )
        
        return condition_expr
    
    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        """
        Finalize query - handle both regular rules and correlation rules.
        
        Args:
            rule: The Sigma rule (could be regular or correlation)
            query: The generated query
            index: Query index
            state: Conversion state
            
        Returns:
            Finalized query
        """
        # If it's a correlation rule, return as-is (already finalized)
        if isinstance(rule, SigmaCorrelationRule):
            return query
        
        # For regular rules, use parent's finalization
        return super().finalize_query_default(rule, query, index, state)
