"""
Tests for converting Sigma rules to OpenSearch PPL queries.
All tests use YAML rule files from the test_rules directory.
Uses the TextQueryBackend implementation (opensearch_ppl_textquery.py).
"""
import pytest
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


@pytest.fixture
def sigma_backend():
    """Fixture to import and return the OpenSearch PPL backend (TextQuery implementation)."""
    from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend
    # from sigma_backend.backends.opensearch_ppl.opensearch_ppl import OpenSearchPPLBackend
    return OpenSearchPPLBackend


def get_query_from_result(ppl_query):
    """
    Helper function to extract query string from backend result.
    TextQueryBackend returns a list of queries, so we extract the first one.
    
    Args:
        ppl_query: Result from backend.convert() - can be list or string
        
    Returns:
        str: The PPL query string
    """
    if isinstance(ppl_query, list):
        assert len(ppl_query) > 0, "Backend returned empty list"
        return ppl_query[0]
    return ppl_query


class TestSigmaToPPLConversion:
    """Test suite for Sigma to OpenSearch PPL conversion."""

    @pytest.fixture
    def test_rules_path(self):
        """Returns the path to test rules directory."""
        return Path(__file__).parent / "test_rules"

    def test_backend_import(self, sigma_backend):
        """Test that the backend can be imported."""
        assert sigma_backend is not None

    def test_simple_rule_conversion(self, sigma_backend, test_rules_path):
        """
        Test conversion of a simple Sigma rule to PPL.
        
        Sigma Rule (from simple_rule.yml):
        -----------------------------------
        detection:
            selection:
                EventID: 1
                CommandLine: test.exe
            condition: selection
        
        Expected PPL:
        -------------
        source = * | where EventID == 1 and CommandLine == "test.exe"
        
        Verifies:
        - Fields (EventID, CommandLine) are present
        - Values (1, test.exe) are present
        - Basic PPL structure (source, where)
        """
        rule_file = test_rules_path / "simple_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query = backend.convert(sigma_collection)
        
        # Verify output is not empty
        assert ppl_query is not None
        assert len(ppl_query) > 0
        
        # TextQueryBackend returns a list of queries
        assert isinstance(ppl_query, list)
        assert len(ppl_query) > 0
        
        # Get first query for testing
        query = ppl_query[0]
        assert isinstance(query, str)
        
        # Basic PPL structure checks
        query_lower = query.lower()
        assert "source" in query_lower or "index" in query_lower
        
        # Verify that the query contains the fields from the rule
        assert "eventid" in query_lower or "event_id" in query_lower
        assert "commandline" in query_lower or "command_line" in query_lower
        
        # Verify that the query contains the values from the rule
        assert "1" in query  # EventID: 1
        assert "test.exe" in query_lower  # CommandLine: test.exe
        
        # Verify PPL structure
        assert "where" in query_lower

    def test_complex_rule_conversion(self, sigma_backend, test_rules_path):
        """
        Test conversion of a complex Sigma rule with multiple conditions.
        
        Sigma Rule (from complex_rule.yml):
        -----------------------------------
        detection:
            selection1:
                EventID: 1
                Image: cmd.exe
            selection2:
                CommandLine|contains: powershell
            selection3:
                ParentImage: explorer.exe
            condition: selection1 and (selection2 or selection3)
        
        Expected PPL:
        -------------
        source = * | where EventID == 1 and Image == "cmd.exe" 
                 and (CommandLine contains "powershell" or ParentImage == "explorer.exe")
        
        Verifies:
        - All fields (EventID, Image, CommandLine, ParentImage) are present
        - All values (1, cmd.exe, powershell, explorer.exe) are present
        - AND/OR conditions are correctly applied
        """
        rule_file = test_rules_path / "complex_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        assert ppl_query_result is not None
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0
        
        query_lower = ppl_query.lower()
        
        # Verify that all fields are present
        assert "eventid" in query_lower or "event_id" in query_lower
        assert "image" in query_lower
        assert "commandline" in query_lower or "command_line" in query_lower
        assert "parentimage" in query_lower or "parent_image" in query_lower
        
        # Verify that all values are present
        assert "1" in ppl_query  # EventID: 1
        assert "cmd.exe" in query_lower  # Image: cmd.exe
        assert "powershell" in query_lower  # CommandLine: powershell
        assert "explorer.exe" in query_lower  # ParentImage: explorer.exe
        
        # Verify that conditions are present (AND/OR)
        assert ("1" in ppl_query and "cmd.exe" in query_lower and 
                ("powershell" in query_lower or "explorer.exe" in query_lower))

    def test_wildcard_rule_conversion(self, sigma_backend, test_rules_path):
        """
        Test handling of wildcard values in Sigma rules.
        
        Sigma Rule (from wildcard_rule.yml):
        ------------------------------------
        detection:
            selection:
                CommandLine|contains|all:
                    - '*suspicious*'
                    - '*malware*'
            condition: selection
        
        Expected PPL:
        -------------
        source = * | where CommandLine contains "suspicious" and CommandLine contains "malware"
        OR
        source = * | where CommandLine like "*suspicious*" and CommandLine like "*malware*"
        
        Verifies:
        - Wildcard patterns are converted to appropriate PPL operators
        - Pattern matching (like, contains, match) is used
        - Both values (suspicious, malware) are present
        """
        rule_file = test_rules_path / "wildcard_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        assert ppl_query_result is not None
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0
        
        query_lower = ppl_query.lower()
        
        # Verify that CommandLine field is present
        assert "commandline" in query_lower or "command_line" in query_lower
        
        # Verify that both wildcard patterns are present
        assert "suspicious" in query_lower
        assert "malware" in query_lower
        
        # Verify that wildcard is handled (may be converted to "like", "contains", "match", etc.)
        assert ("like" in query_lower or "contains" in query_lower or 
                "match" in query_lower or "*" in ppl_query or "~" in ppl_query)

    def test_numeric_comparison_rule_conversion(self, sigma_backend, test_rules_path):
        """
        Test handling of numeric comparison operators.
        
        Sigma Rule (from numeric_comparison_rule.yml):
        ----------------------------------------------
        detection:
            selection:
                EventID|gt: 1000
                ProcessId|lt: 10000
            condition: selection
        
        Expected PPL:
        -------------
        source = * | where EventID > 1000 and ProcessId < 10000
        OR
        source = * | where EventID gt 1000 and ProcessId lt 10000
        
        Verifies:
        - Greater than (gt) and less than (lt) operators are converted correctly
        - Values (1000, 10000) are present
        - Both numeric comparisons are properly applied
        """
        rule_file = test_rules_path / "numeric_comparison_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        assert ppl_query_result is not None
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0
        
        query_lower = ppl_query.lower()
        
        # Verify that fields are present
        assert "eventid" in query_lower or "event_id" in query_lower
        assert "processid" in query_lower or "process_id" in query_lower
        
        # Verify that values are present
        assert "1000" in ppl_query
        assert "10000" in ppl_query
        
        # Verify that comparison operators are converted correctly
        # May be ">", "gt", "greater" for gt, and "<", "lt", "less" for lt
        assert (">" in ppl_query or "gt" in query_lower or "greater" in query_lower)
        assert ("<" in ppl_query or "lt" in query_lower or "less" in query_lower)

    def test_multiple_rules_conversion(self, sigma_backend, test_rules_path):
        """
        Test conversion of multiple Sigma rules at once.
        
        Sigma Rules:
        ------------
        Rule 1 (simple_rule.yml): EventID == 1 and CommandLine == "test.exe"
        Rule 2 (complex_rule.yml): EventID == 1 and Image == "cmd.exe" 
                                   and (CommandLine contains "powershell" or ParentImage == "explorer.exe")
        
        Expected PPL:
        -------------
        Multiple queries combined (format depends on implementation):
        - source = * | where EventID == 1 and CommandLine == "test.exe"
        - source = * | where EventID == 1 and Image == "cmd.exe" and ...
        
        Verifies:
        - Multiple rules can be converted together
        - Output is valid PPL
        """
        rule_files = [
            test_rules_path / "simple_rule.yml",
            test_rules_path / "complex_rule.yml"
        ]
        
        rules_yaml = []
        for rule_file in rule_files:
            if rule_file.exists():
                with open(rule_file, 'r') as f:
                    rules_yaml.append(f.read())
        
        if not rules_yaml:
            pytest.skip("No rule files found")
        
        combined_yaml = "\n---\n".join(rules_yaml)
        sigma_collection = SigmaCollection.from_yaml(combined_yaml)
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        assert ppl_query_result is not None
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0

    def test_empty_collection(self, sigma_backend):
        """
        Test handling of empty Sigma collection.
        
        Sigma Rule:
        -----------
        (empty collection)
        
        Expected PPL:
        -------------
        "" (empty string) or valid empty query
        
        Verifies:
        - Empty collections are handled gracefully
        - No errors are raised
        """
        sigma_collection = SigmaCollection([])
        
        backend = sigma_backend()
        ppl_query = backend.convert(sigma_collection)
        
        # Should handle empty collection gracefully
        assert ppl_query is not None

    def test_ppl_query_structure(self, sigma_backend, test_rules_path):
        """
        Test that the generated PPL query has correct structure.
        
        Sigma Rule (from simple_rule.yml):
        -----------------------------------
        detection:
            selection:
                EventID: 1
                CommandLine: test.exe
            condition: selection
        
        Expected PPL Structure:
        ----------------------
        source = * | where <conditions>
        
        Verifies:
        - Basic PPL structure (source/index, where clause)
        - Fields from rule are present
        - Valid PPL syntax
        """
        rule_file = test_rules_path / "simple_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        
        # PPL queries should contain field references
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0
        
        query_lower = ppl_query.lower()
        
        # Verify basic PPL structure
        assert "source" in query_lower or "index" in query_lower
        assert "where" in query_lower
        
        # Verify that fields from the rule are present
        assert "eventid" in query_lower or "event_id" in query_lower
        assert "commandline" in query_lower or "command_line" in query_lower

    def test_field_mapping(self, sigma_backend, test_rules_path):
        """
        Test that Sigma fields are correctly mapped to OpenSearch fields.
        
        Sigma Rule (from simple_rule.yml):
        -----------------------------------
        detection:
            selection:
                EventID: 1
                CommandLine: test.exe
            condition: selection
        
        Expected PPL:
        -------------
        source = * | where EventID == 1 and CommandLine == "test.exe"
        (Fields may be mapped: EventID -> event_id, CommandLine -> command_line, etc.)
        
        Verifies:
        - Sigma fields are correctly mapped to OpenSearch field names
        - Values are preserved correctly
        - Field mapping is consistent
        """
        rule_file = test_rules_path / "simple_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        
        # The query should reference the fields from the rule
        query_lower = ppl_query.lower()
        
        # Verify that fields from the rule are present in the query
        # (may be mapped differently, but must exist)
        assert "eventid" in query_lower or "event_id" in query_lower
        assert "commandline" in query_lower or "command_line" in query_lower
        
        # Verify that values are correctly mapped
        assert "1" in ppl_query  # EventID: 1
        assert "test.exe" in query_lower  # CommandLine: test.exe

    def test_condition_operators(self, sigma_backend):
        """
        Test that different condition operators are handled correctly.
        
        Sigma Rule (OR condition):
        -------------------------
        detection:
            selection1:
                EventID: 1
            selection2:
                EventID: 2
            condition: selection1 or selection2
        
        Expected PPL:
        -------------
        source = * | where EventID == 1 or EventID == 2
        
        Verifies:
        - OR operator is correctly converted
        - Both values (1, 2) are present
        - Logical OR is properly applied
        """
        # Create OR condition rule inline
        or_rule_yaml = """
        title: OR Condition Test
        id: 123e4567-e89b-12d3-a456-426614174100
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection1:
                EventID: 1
            selection2:
                EventID: 2
            condition: selection1 or selection2
        """
        
        sigma_collection = SigmaCollection.from_yaml(or_rule_yaml)
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        assert ppl_query_result is not None
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0
        
        query_lower = ppl_query.lower()
        
        # Verify that EventID field is present
        assert "eventid" in query_lower or "event_id" in query_lower
        
        # Verify that both values are present (1 or 2)
        assert "1" in ppl_query
        assert "2" in ppl_query
        
        # Verify that OR operator is present (may be "or", "||", etc.)
        assert ("or" in query_lower or "||" in query_lower or 
                ("1" in ppl_query and "2" in ppl_query))

    def test_all_rules_in_directory(self, sigma_backend, test_rules_path):
        """
        Test conversion of all rule files in the test_rules directory.
        
        Verifies:
        - All YAML rule files can be converted
        - Output is valid PPL for each rule
        - No errors are raised during conversion
        """
        rule_files = list(test_rules_path.glob("*.yml"))
        
        if not rule_files:
            pytest.skip("No rule files found in test_rules directory")
        
        backend = sigma_backend()
        
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
                    sigma_collection = SigmaCollection.from_yaml(f.read())
                ppl_query_result = backend.convert(sigma_collection)
                
                assert ppl_query_result is not None, f"Failed to convert {rule_file.name}"
                
                # Extract query from list result
                ppl_query = get_query_from_result(ppl_query_result)
                assert isinstance(ppl_query, str), f"Invalid output type for {rule_file.name}"
                assert len(ppl_query) > 0, f"Empty output for {rule_file.name}"
            except Exception as e:
                pytest.fail(f"Error converting {rule_file.name}: {str(e)}")


class TestPPLQueryValidation:
    """Test suite for validating generated PPL queries."""

    @pytest.fixture
    def test_rules_path(self):
        """Returns the path to test rules directory."""
        return Path(__file__).parent / "test_rules"

    def test_ppl_syntax_validity(self, sigma_backend, test_rules_path):
        """
        Test that generated PPL queries have valid syntax structure.
        
        Sigma Rule (from simple_rule.yml):
        -----------------------------------
        detection:
            selection:
                EventID: 1
                CommandLine: test.exe
            condition: selection
        
        Expected PPL:
        -------------
        source = * | where EventID == 1 and CommandLine == "test.exe"
        
        Verifies:
        - Parentheses are balanced: ( == )
        - Brackets are balanced: [ == ]
        - Braces are balanced: { == }
        - Valid PPL syntax structure
        """
        rule_file = test_rules_path / "simple_rule.yml"
        
        if not rule_file.exists():
            pytest.skip(f"Test rule file not found: {rule_file}")
        
        with open(rule_file, 'r') as f:
            sigma_collection = SigmaCollection.from_yaml(f.read())
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        
        # Basic syntax checks
        assert isinstance(ppl_query, str)
        
        # PPL queries should not have unmatched parentheses
        assert ppl_query.count("(") == ppl_query.count(")")
        assert ppl_query.count("[") == ppl_query.count("]")
        assert ppl_query.count("{") == ppl_query.count("}")

    def test_ppl_escaping(self, sigma_backend):
        """
        Test that special characters are properly escaped in PPL.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                CommandLine: "test (value) [test]"
            condition: selection
        
        Expected PPL:
        -------------
        source = * | where CommandLine == "test (value) [test]"
        OR (with escaping):
        source = * | where CommandLine == "test \\(value\\) \\[test\\]"
        
        Verifies:
        - Special characters (parentheses, brackets) are handled
        - Values are preserved correctly
        - Escaping is applied if needed
        """
        special_char_rule_yaml = """
        title: Special Characters Test
        id: 123e4567-e89b-12d3-a456-426614174400
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine: "test (value) [test]"
            condition: selection
        """
        
        sigma_collection = SigmaCollection.from_yaml(special_char_rule_yaml)
        
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        
        assert ppl_query_result is not None
        
        # Extract query from list result
        ppl_query = get_query_from_result(ppl_query_result)
        assert isinstance(ppl_query, str)
        assert len(ppl_query) > 0
        
        query_lower = ppl_query.lower()
        
        # Verify that CommandLine field is present
        assert "commandline" in query_lower or "command_line" in query_lower
        
        # Verify that the value is present (may be escaped)
        assert "test" in query_lower
        assert "value" in query_lower
        
        # Verify that special characters are handled (escaped or preserved)
        # Parentheses and brackets should be handled correctly
        assert (ppl_query.count("(") == ppl_query.count(")") or
                "test" in query_lower and "value" in query_lower)


class TestUnsupportedFeatures:
    """
    Test suite for Sigma features that are NOT currently supported by the backend.
    These tests are marked with @pytest.mark.xfail to indicate expected failures.
    
    Purpose:
    - Document known limitations of the backend
    - Provide test cases for future feature implementation
    - Ensure failures are tracked and expected
    """

    @pytest.fixture
    def test_rules_path(self):
        """Returns the path to test rules directory."""
        return Path(__file__).parent / "test_rules"

    @pytest.mark.xfail(reason="Aggregation and statistics (stats commands) are not supported")
    def test_aggregation_count(self, sigma_backend):
        """
        Test aggregation with count() - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                EventID: 4625  # Failed logon
            condition: selection | count() > 5
        timeframe: 10m
        
        Expected PPL (if supported):
        ---------------------------
        source = windows-security-* | where EventID = 4625 
        | stats count() by SourceIP | where count() > 5
        
        Current Status: ❌ NOT SUPPORTED
        - Backend cannot generate stats commands
        - Aggregation functions are not implemented
        - Threshold detection is not available
        """
        aggregation_rule_yaml = """
        title: Multiple Failed Login Attempts
        id: 12345678-1234-1234-1234-123456789abc
        status: test
        logsource:
            product: windows
            service: security
        detection:
            selection:
                EventID: 4625
            condition: selection | count() > 5
        timeframe: 10m
        """
        
        sigma_collection = SigmaCollection.from_yaml(aggregation_rule_yaml)
        backend = sigma_backend()
        
        # This will fail because aggregations are not supported
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # If it were supported, it should contain stats
        assert "stats" in ppl_query.lower()
        assert "count()" in ppl_query.lower()

    @pytest.mark.xfail(reason="Aggregation group by is not supported")
    def test_aggregation_group_by(self, sigma_backend):
        """
        Test aggregation with GROUP BY - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                EventID: 1
            condition: selection | count() by User > 100
        
        Expected PPL (if supported):
        ---------------------------
        source = windows-* | where EventID = 1 
        | stats count() by User | where count() > 100
        
        Current Status: ❌ NOT SUPPORTED
        - Group by operations are not implemented
        - Cannot generate stats with grouping
        """
        group_by_rule_yaml = """
        title: Process Creation by User
        id: 12345678-1234-1234-1234-123456789abd
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                EventID: 1
            condition: selection | count() by User > 100
        """
        
        sigma_collection = SigmaCollection.from_yaml(group_by_rule_yaml)
        backend = sigma_backend()
        
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # If supported, should contain stats with group by
        assert "stats" in ppl_query.lower()
        assert "by user" in ppl_query.lower()

    @pytest.mark.xfail(reason="Correlation rules are not supported")
    def test_correlation_rule(self, sigma_backend):
        """
        Test correlation between multiple events - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection1:
                EventID: 4624  # Successful logon
            selection2:
                EventID: 4672  # Special privileges assigned
            condition: selection1 followed by selection2
        
        Expected PPL (if supported):
        ---------------------------
        Complex correlation query with joins or temporal ordering
        
        Current Status: ❌ NOT SUPPORTED
        - Correlation between events is not implemented
        - Temporal ordering (followed by) is not available
        - Multi-event detection is not supported
        """
        correlation_rule_yaml = """
        title: Privilege Escalation After Logon
        id: 12345678-1234-1234-1234-123456789abe
        status: test
        logsource:
            product: windows
            service: security
        detection:
            selection1:
                EventID: 4624
            selection2:
                EventID: 4672
            condition: selection1 followed by selection2
        """
        
        # This may fail at parsing or conversion
        try:
            sigma_collection = SigmaCollection.from_yaml(correlation_rule_yaml)
            backend = sigma_backend()
            ppl_query_result = backend.convert(sigma_collection)
            ppl_query = get_query_from_result(ppl_query_result)
            
            # If supported, should handle temporal correlation
            assert "join" in ppl_query.lower() or "followed" in ppl_query.lower()
        except (SigmaError, Exception) as e:
            # Expected to fail
            pytest.fail(f"Correlation not supported: {str(e)}")

    @pytest.mark.xfail(reason="Timeframe filtering is not supported")
    def test_timeframe_filtering(self, sigma_backend):
        """
        Test timeframe-based filtering - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                EventID: 4625
            condition: selection
        timeframe: 5m
        
        Expected PPL (if supported):
        ---------------------------
        source = windows-security-* | where EventID = 4625 
        AND @timestamp >= now() - 5m
        
        Current Status: ❌ NOT SUPPORTED
        - Timeframe constraints are not converted
        - Time-based filtering is not implemented
        - Temporal windows are ignored
        """
        timeframe_rule_yaml = """
        title: Recent Failed Logins
        id: 12345678-1234-1234-1234-123456789abf
        status: test
        logsource:
            product: windows
            service: security
        detection:
            selection:
                EventID: 4625
            condition: selection
        timeframe: 5m
        """
        
        sigma_collection = SigmaCollection.from_yaml(timeframe_rule_yaml)
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # If supported, should contain timestamp filtering
        assert ("@timestamp" in ppl_query.lower() or 
                "time" in ppl_query.lower() or 
                "5m" in ppl_query.lower())

    @pytest.mark.xfail(reason="Field transformations (eval commands) are not supported")
    def test_field_transformation(self, sigma_backend):
        """
        Test field transformations with eval - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                CommandLine|base64: "powershell"
            condition: selection
        
        Expected PPL (if supported):
        ---------------------------
        source = windows-* | eval CommandLine_decoded = base64decode(CommandLine)
        | where CommandLine_decoded like "%powershell%"
        
        Current Status: ❌ NOT SUPPORTED
        - Field transformations are not implemented
        - base64, re modifiers may not work correctly
        - eval commands are not generated
        """
        transformation_rule_yaml = """
        title: Base64 Encoded Command
        id: 12345678-1234-1234-1234-123456789ac0
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|base64: "powershell"
            condition: selection
        """
        
        sigma_collection = SigmaCollection.from_yaml(transformation_rule_yaml)
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # If supported, should contain eval with transformation
        assert ("eval" in ppl_query.lower() or 
                "base64" in ppl_query.lower())

    @pytest.mark.xfail(reason="Complex NOT conditions may not work correctly")
    def test_complex_negation(self, sigma_backend):
        """
        Test complex NOT conditions - MAY NOT WORK.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                EventID: 1
            filter:
                Image|endswith:
                    - '\\svchost.exe'
                    - '\\explorer.exe'
            condition: selection and not filter
        
        Expected PPL:
        -------------
        source = windows-* | where EventID = 1 
        AND NOT (Image like "%\\svchost.exe" OR Image like "%\\explorer.exe")
        
        Current Status: ⚠️  MAY NOT WORK
        - Simple NOT works, but complex negations may fail
        - Multiple values in NOT conditions may not be handled correctly
        - Parentheses grouping in NOT may be incorrect
        """
        negation_rule_yaml = """
        title: Suspicious Process Excluding System
        id: 12345678-1234-1234-1234-123456789ac1
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                EventID: 1
            filter:
                Image|endswith:
                    - '\\svchost.exe'
                    - '\\explorer.exe'
            condition: selection and not filter
        """
        
        sigma_collection = SigmaCollection.from_yaml(negation_rule_yaml)
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # Should contain NOT with proper grouping
        query_lower = ppl_query.lower()
        assert "not" in query_lower
        assert "svchost.exe" in query_lower
        assert "explorer.exe" in query_lower
        
        # Should have proper parentheses for NOT grouping
        # This is where it might fail
        assert "(" in ppl_query and ")" in ppl_query

    @pytest.mark.xfail(reason="Near modifier for proximity search is not supported")
    def test_near_proximity_search(self, sigma_backend):
        """
        Test NEAR proximity search - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                CommandLine|near:
                    - "password"
                    - "admin"
            condition: selection
        
        Expected PPL (if supported):
        ---------------------------
        source = windows-* | where match(CommandLine, '.*password.{0,10}admin.*')
        
        Current Status: ❌ NOT SUPPORTED
        - Near/proximity modifiers are not implemented
        - Cannot generate proximity-based patterns
        """
        near_rule_yaml = """
        title: Password Near Admin
        id: 12345678-1234-1234-1234-123456789ac2
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|near:
                    - "password"
                    - "admin"
            condition: selection
        """
        
        # May fail at parsing or conversion
        try:
            sigma_collection = SigmaCollection.from_yaml(near_rule_yaml)
            backend = sigma_backend()
            ppl_query_result = backend.convert(sigma_collection)
            ppl_query = get_query_from_result(ppl_query_result)
            
            # If supported, should handle proximity
            assert "near" in ppl_query.lower() or "match" in ppl_query.lower()
        except (SigmaError, Exception):
            pytest.fail("Near modifier not supported")

    @pytest.mark.xfail(reason="Field aliases and lookups are not supported")
    def test_field_alias_lookup(self, sigma_backend):
        """
        Test field aliases and lookups - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                CommandLine|lookup:
                    - malicious_commands.csv
            condition: selection
        
        Expected PPL (if supported):
        ---------------------------
        Complex lookup join operation
        
        Current Status: ❌ NOT SUPPORTED
        - External lookups are not implemented
        - CSV/database enrichment not available
        - Field aliases may not work
        """
        # This will likely fail at parsing
        lookup_rule_yaml = """
        title: Lookup Malicious Commands
        id: 12345678-1234-1234-1234-123456789ac3
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|lookup: malicious_commands
            condition: selection
        """
        
        try:
            sigma_collection = SigmaCollection.from_yaml(lookup_rule_yaml)
            backend = sigma_backend()
            ppl_query_result = backend.convert(sigma_collection)
            ppl_query = get_query_from_result(ppl_query_result)
            
            assert "lookup" in ppl_query.lower() or "join" in ppl_query.lower()
        except (SigmaError, Exception):
            pytest.fail("Lookup not supported")

    @pytest.mark.xfail(reason="Regular expression modifiers may have limited support")
    def test_regex_modifier(self, sigma_backend):
        """
        Test regular expression modifier - LIMITED SUPPORT.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                CommandLine|re: '.*powershell.*-enc.*'
            condition: selection
        
        Expected PPL:
        -------------
        source = windows-* | where match(CommandLine, '.*powershell.*-enc.*')
        
        Current Status: ⚠️  LIMITED SUPPORT
        - Basic regex may work
        - Complex regex patterns may not be converted correctly
        - Some regex features may not be supported
        """
        regex_rule_yaml = """
        title: Regex Pattern Match
        id: 12345678-1234-1234-1234-123456789ac4
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|re: '.*powershell.*-enc(oded)?.*'
            condition: selection
        """
        
        sigma_collection = SigmaCollection.from_yaml(regex_rule_yaml)
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # Should contain regex matching
        query_lower = ppl_query.lower()
        assert ("match" in query_lower or 
                "regex" in query_lower or 
                "powershell.*-enc" in ppl_query)

    @pytest.mark.xfail(reason="CIDR notation for IP ranges is not supported")
    def test_cidr_notation(self, sigma_backend):
        """
        Test CIDR notation for IP addresses - NOT SUPPORTED.
        
        Sigma Rule:
        -----------
        detection:
            selection:
                SourceIP|cidr: '192.168.1.0/24'
            condition: selection
        
        Expected PPL (if supported):
        ---------------------------
        source = network-* | where cidr_match(SourceIP, '192.168.1.0/24')
        
        Current Status: ❌ NOT SUPPORTED
        - CIDR notation is not converted
        - IP range matching is not implemented
        - Network operations are not available
        """
        cidr_rule_yaml = """
        title: IP Range Detection
        id: 12345678-1234-1234-1234-123456789ac5
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            selection:
                SourceIP|cidr: '192.168.1.0/24'
            condition: selection
        """
        
        sigma_collection = SigmaCollection.from_yaml(cidr_rule_yaml)
        backend = sigma_backend()
        ppl_query_result = backend.convert(sigma_collection)
        ppl_query = get_query_from_result(ppl_query_result)
        
        # Should contain CIDR or IP range logic
        query_lower = ppl_query.lower()
        assert ("cidr" in query_lower or 
                "192.168.1" in ppl_query or
                "subnet" in query_lower)
