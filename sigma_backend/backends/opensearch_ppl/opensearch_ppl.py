"""
OpenSearch PPL backend for Sigma rules.

This backend converts Sigma detection rules into PPL (Piped Processing Language)
queries for OpenSearch.
"""
from typing import List, Optional, Dict, Any, Union
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


class OpenSearchPPLBackend:
    """
    Backend for converting Sigma rules to OpenSearch PPL queries.
    
    This class implements a complete conversion pipeline from Sigma detection rules
    to OpenSearch PPL (Piped Processing Language) queries. It handles:
    - Logsource mapping to OpenSearch indices
    - Detection logic conversion (selections and conditions)
    - Field modifiers (contains, startswith, endswith, etc.)
    - Wildcard pattern matching
    - Numeric comparisons
    - Complex logical conditions (AND, OR, NOT)
    - Aggregations and timeframes (optional)
    """
    
    def __init__(self, processing_pipeline: Optional[object] = None):
        """
        Initialize the OpenSearch PPL backend.
        
        Args:
            processing_pipeline: Optional processing pipeline for rule transformation
        """
        self.processing_pipeline = processing_pipeline
    
    # =========================================================================
    # PUBLIC API - Main Conversion Methods
    # =========================================================================
    
    def convert(self, sigma_collection: SigmaCollection) -> str:
        """
        Convert a Sigma collection to PPL query/queries.
        
        This is the main entry point for converting one or more Sigma rules.
        If the collection contains multiple rules, they will be converted
        separately and combined appropriately.
        
        Args:
            sigma_collection: Collection of Sigma rules to convert
            
        Returns:
            PPL query string (single query or combined queries)
            
        Example:
            >>> backend = OpenSearchPPLBackend()
            >>> collection = SigmaCollection.from_yaml(rule_yaml)
            >>> ppl_query = backend.convert(collection)
            >>> print(ppl_query)
            source = windows-* | where EventID = 1 AND CommandLine = "test.exe"
        """
        if not sigma_collection:
            return ""
        
        # For now, return a placeholder implementation
        # This will be replaced with actual PPL conversion logic
        ppl_queries = []
        
        for rule in sigma_collection:
            ppl_query = self.convert_rule(rule)
            if ppl_query:
                ppl_queries.append(ppl_query)
        
        # Join multiple queries if needed
        if len(ppl_queries) == 1:
            return ppl_queries[0]
        elif len(ppl_queries) > 1:
            # Combine multiple queries (adjust based on PPL syntax)
            return " | ".join(ppl_queries)
        else:
            return ""
    
    def convert_rule(self, rule: SigmaRule) -> str:
        """
        Convert a single Sigma rule to PPL query.
        
        This is the main method that orchestrates the conversion of a single
        Sigma rule. It:
        1. Converts the logsource to a PPL source command
        2. Extracts and converts all detection selections
        3. Parses and converts the detection condition
        4. Combines everything into a complete PPL query
        
        Args:
            rule: Single Sigma rule to convert
            
        Returns:
            Complete PPL query string for the rule
            
        Example:
            >>> rule = SigmaRule.from_yaml(rule_yaml)
            >>> ppl_query = backend.convert_rule(rule)
            >>> print(ppl_query)
            source = windows-* | where EventID = 1
        """
        # Step 1: Convert logsource to source command
        source_cmd = self._convert_logsource(rule)
        
        # TODO: Step 2-4: Convert detection logic
        # For now, return just the source command with placeholder where clause
        return f"{source_cmd} | where true"
    
    # =========================================================================
    # LOGSOURCE CONVERSION - Mapping to OpenSearch Indices
    # =========================================================================
    
    def _convert_logsource(self, rule: SigmaRule) -> str:
        """
        Convert Sigma logsource to PPL source command.
        
        Maps the Sigma logsource (product, category, service) to an appropriate
        OpenSearch index pattern. The mapping strategy:
        - Uses product as primary identifier (windows, linux, etc.)
        - Appends category if specific (process_creation, network_connection)
        - Falls back to wildcard (*) if logsource is too generic
        
        Args:
            rule: Sigma rule containing logsource information
            
        Returns:
            PPL source command (e.g., "source = windows-process-*")
            
        Examples:
            logsource:
                product: windows
                category: process_creation
            → "source = windows-process-*"
            
            logsource:
                product: linux
                service: syslog
            → "source = linux-syslog-*"
            
            logsource:
                category: firewall
            → "source = firewall-*"
        """
        # Extract logsource components
        logsource = rule.logsource
        product = getattr(logsource, 'product', None)
        category = getattr(logsource, 'category', None)
        service = getattr(logsource, 'service', None)
        
        # Build index pattern
        index_parts = []
        
        # Add product if available
        if product:
            index_parts.append(product)
        
        # Add category if available
        if category:
            index_parts.append(category)
        
        # Add service if available
        if service:
            index_parts.append(service)
        
        # Build final index pattern
        if index_parts:
            index_pattern = '-'.join(index_parts) + '-*'
        else:
            # Fallback if no logsource info
            index_pattern = '*'
        
        return f"source = {index_pattern}"
    
    # =========================================================================
    # DETECTION CONVERSION - Selections and Conditions
    # =========================================================================
    
    def _convert_selection(self, selection: Dict[str, Any]) -> str:
        """
        Convert a Sigma detection selection to PPL where conditions.
        
        A selection is a dictionary of field-value pairs that represent
        conditions to match. This method:
        - Iterates through all field-value pairs
        - Handles lists of values (OR logic)
        - Applies field modifiers (contains, startswith, etc.)
        - Combines multiple conditions with AND
        
        Args:
            selection: Dictionary containing field-value pairs from detection
            
        Returns:
            PPL where clause conditions as a string
            
        Examples:
            selection:
                EventID: 1
                CommandLine: test.exe
            → 'EventID = 1 AND CommandLine = "test.exe"'
            
            selection:
                EventID: [1, 2, 3]
            → '(EventID = 1 OR EventID = 2 OR EventID = 3)'
            
            selection:
                CommandLine|contains: powershell
            → 'CommandLine like "%powershell%"'
        """
        # TODO: Implement selection conversion
        pass
    
    def _convert_field_value(
        self, 
        field: str, 
        value: Any, 
        modifier: Optional[str] = None
    ) -> str:
        """
        Convert a single field-value pair to PPL condition.
        
        This is the core method for converting individual conditions. It handles:
        - Simple equality: field = value
        - String quoting and escaping
        - Numeric values without quotes
        - Field modifiers (contains, startswith, endswith, gt, lt, etc.)
        - Wildcard conversion for pattern matching
        
        Args:
            field: Field name from Sigma rule
            value: Value to match (can be string, int, float, bool)
            modifier: Optional Sigma field modifier (contains, startswith, etc.)
            
        Returns:
            Single PPL condition as a string
            
        Examples:
            field="EventID", value=1, modifier=None
            → "EventID = 1"
            
            field="CommandLine", value="test.exe", modifier=None
            → 'CommandLine = "test.exe"'
            
            field="CommandLine", value="powershell", modifier="contains"
            → 'CommandLine like "%powershell%"'
            
            field="ProcessId", value=1000, modifier="gt"
            → "ProcessId > 1000"
        """
        # TODO: Implement field-value conversion with modifiers
        pass
    
    def _parse_condition(
        self, 
        condition: str, 
        selections: Dict[str, str]
    ) -> str:
        """
        Parse and convert Sigma condition to PPL logical expression.
        
        Sigma conditions define how selections are combined using logical
        operators (and, or, not) and parentheses for grouping. This method:
        - Parses the condition string
        - Replaces selection names with their PPL equivalents
        - Converts Sigma operators to PPL operators
        - Preserves parentheses for correct precedence
        
        Args:
            condition: Sigma condition string (e.g., "selection1 and selection2")
            selections: Dictionary mapping selection names to PPL conditions
            
        Returns:
            Complete PPL where clause with logical operators
            
        Examples:
            condition: "selection1 and selection2"
            selections: {"selection1": "EventID = 1", "selection2": "CommandLine like '%cmd%'"}
            → "(EventID = 1) AND (CommandLine like '%cmd%')"
            
            condition: "selection1 and (selection2 or selection3)"
            → "(EventID = 1) AND ((CommandLine like '%powershell%') OR (ParentImage = 'explorer.exe'))"
            
            condition: "not selection1"
            → "NOT (EventID = 4625)"
        """
        # TODO: Implement condition parsing and conversion
        pass
    
    # =========================================================================
    # FIELD MODIFIERS - Special Processing for Field Values
    # =========================================================================
    
    def _handle_field_modifiers(
        self, 
        field: str, 
        value: Any, 
        modifiers: List[str]
    ) -> str:
        """
        Handle complex Sigma field modifiers.
        
        Sigma supports various field modifiers that change how values are
        matched. This method handles compound modifiers like:
        - contains|all: all values must be present (AND logic)
        - contains|any: at least one value present (OR logic)
        - re: regular expression matching
        - base64: decode before matching
        
        Args:
            field: Field name
            value: Value or list of values
            modifiers: List of modifiers (e.g., ["contains", "all"])
            
        Returns:
            PPL condition with appropriate logic
            
        Examples:
            field="CommandLine", value=["suspicious", "malware"], modifiers=["contains", "all"]
            → 'CommandLine like "%suspicious%" AND CommandLine like "%malware%"'
            
            field="CommandLine", value=["cmd", "powershell"], modifiers=["contains", "any"]
            → '(CommandLine like "%cmd%" OR CommandLine like "%powershell%")'
        """
        # TODO: Implement complex modifier handling
        pass
    
    # =========================================================================
    # HELPER FUNCTIONS - String Processing and Conversion
    # =========================================================================
    
    def _convert_wildcards(self, pattern: str) -> str:
        """
        Convert Sigma wildcards to PPL wildcards.
        
        Sigma uses * and ? for wildcards, while PPL uses % and _.
        This method performs the conversion while preserving literal
        characters and handling escape sequences.
        
        Args:
            pattern: String potentially containing Sigma wildcards
            
        Returns:
            String with PPL wildcards
            
        Examples:
            "*.exe" → "%.exe"
            "cmd?.exe" → "cmd_.exe"
            "test*file*.txt" → "test%file%.txt"
        """
        # TODO: Implement wildcard conversion
        pass
    
    def _escape_string_value(self, value: str) -> str:
        """
        Escape special characters in string values for PPL.
        
        Ensures that string values are properly escaped for use in PPL
        queries. Handles:
        - Double quotes: " → \"
        - Backslashes: \ → \\
        - Other special characters as needed
        
        Args:
            value: Raw string value
            
        Returns:
            Escaped string safe for PPL
            
        Examples:
            'test"value' → 'test\\"value'
            'path\\to\\file' → 'path\\\\to\\\\file'
        """
        # TODO: Implement string escaping
        pass
    
    def _is_numeric(self, value: Any) -> bool:
        """
        Check if a value should be treated as numeric in PPL.
        
        Determines whether a value should be rendered without quotes
        in the PPL query (numeric) or with quotes (string).
        
        Args:
            value: Value to check
            
        Returns:
            True if value is numeric (int, float), False otherwise
            
        Examples:
            1 → True
            1.5 → True
            "123" → False (string, even if numeric content)
            True → False (boolean should be handled separately)
        """
        # TODO: Implement numeric type checking
        pass
    
    # =========================================================================
    # ADVANCED FEATURES - Aggregations and Timeframes
    # =========================================================================
    
    def _add_timeframe(self, query: str, timeframe: str) -> str:
        """
        Add timeframe filter to PPL query.
        
        Some Sigma rules specify a timeframe for detection (e.g., count
        events within last 10 minutes). This method adds appropriate
        time-based filtering to the PPL query.
        
        Args:
            query: Base PPL query
            timeframe: Sigma timeframe string (e.g., "10m", "1h", "24h")
            
        Returns:
            PPL query with time filter added
            
        Examples:
            query: "source = windows-* | where EventID = 4625"
            timeframe: "10m"
            → "source = windows-* | where EventID = 4625 AND @timestamp >= now() - 10m"
        """
        # TODO: Implement timeframe addition
        pass
    
    def _handle_aggregations(self, rule: SigmaRule, base_query: str) -> str:
        """
        Handle Sigma rules with aggregations (count, sum, etc.).
        
        Some Sigma rules require aggregation logic, such as counting
        events grouped by a field and checking if count exceeds a threshold.
        This method detects such requirements and adds PPL stats commands.
        
        Args:
            rule: Sigma rule that may contain aggregation requirements
            base_query: Base PPL query without aggregation
            
        Returns:
            PPL query with aggregation logic added
            
        Examples:
            Detection requires: count by SourceIP > 5
            → "source = windows-* | where EventID = 4625 | stats count() by SourceIP | where count() > 5"
        """
        # TODO: Implement aggregation handling
        pass
    
    # =========================================================================
    # VALIDATION AND ERROR HANDLING
    # =========================================================================
    
    def _validate_ppl_query(self, query: str) -> bool:
        """
        Validate that the generated PPL query has correct syntax.
        
        Performs basic validation checks on the generated PPL query:
        - Contains required 'source' command
        - Has balanced parentheses
        - Has valid PPL structure
        - No obvious syntax errors
        
        Args:
            query: Generated PPL query string
            
        Returns:
            True if query appears valid, False otherwise
            
        Raises:
            ValueError: If query has obvious syntax errors
        """
        # TODO: Implement query validation
        pass
    
    def _handle_unsupported_features(self, rule: SigmaRule) -> None:
        """
        Detect and report unsupported Sigma features.
        
        Not all Sigma features can be directly translated to PPL.
        This method identifies unsupported features and either:
        - Logs a warning
        - Raises an exception
        - Provides fallback behavior
        
        Args:
            rule: Sigma rule to check for unsupported features
            
        Raises:
            NotImplementedError: If rule contains unsupported features
            Warning: For features that can be partially supported
        """
        # TODO: Implement unsupported feature detection
        pass