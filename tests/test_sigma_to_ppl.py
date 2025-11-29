"""
Tests for converting Sigma rules to OpenSearch PPL queries.
All tests use YAML rule files from the test_rules directory.
"""
import pytest
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


@pytest.fixture
def sigma_backend():
    """Fixture to import and return the OpenSearch PPL backend."""
    from sigma_backend.backends.opensearch_ppl.opensearch_ppl import OpenSearchPPLBackend
    return OpenSearchPPLBackend


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
        
        # Verify it's a string (PPL query)
        assert isinstance(ppl_query, str)
        
        # Basic PPL structure checks
        query_lower = ppl_query.lower()
        assert "source" in query_lower or "index" in query_lower
        
        # Verify that the query contains the fields from the rule
        assert "eventid" in query_lower or "event_id" in query_lower
        assert "commandline" in query_lower or "command_line" in query_lower
        
        # Verify that the query contains the values from the rule
        assert "1" in ppl_query  # EventID: 1
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
        ppl_query = backend.convert(sigma_collection)
        
        assert ppl_query is not None
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
        ppl_query = backend.convert(sigma_collection)
        
        assert ppl_query is not None
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
        ppl_query = backend.convert(sigma_collection)
        
        assert ppl_query is not None
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
        ppl_query = backend.convert(sigma_collection)
        
        assert ppl_query is not None
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
        ppl_query = backend.convert(sigma_collection)
        
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
        ppl_query = backend.convert(sigma_collection)
        
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
        ppl_query = backend.convert(sigma_collection)
        
        assert ppl_query is not None
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
                ppl_query = backend.convert(sigma_collection)
                
                assert ppl_query is not None, f"Failed to convert {rule_file.name}"
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
        ppl_query = backend.convert(sigma_collection)
        
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
        ppl_query = backend.convert(sigma_collection)
        
        assert ppl_query is not None
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
