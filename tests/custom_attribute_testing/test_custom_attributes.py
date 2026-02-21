"""
Test custom attributes functionality in OpenSearch PPL backend.

This test demonstrates how custom attributes in Sigma rule YAML
can override backend default settings.
"""
import pytest
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl import OpenSearchPPLBackend


def test_custom_index_attribute():
    """Test that opensearch_ppl_index custom attribute overrides default index pattern."""
    rule = """
title: Test Custom Index
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
custom:
  opensearch_ppl_index: "my-custom-index-*"
"""
    backend = OpenSearchPPLBackend()
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # Should use custom index from rule YAML, not default logsource mapping
    assert "source=my-custom-index-*" in result
    assert "windows-" not in result


def test_custom_time_field_attribute():
    """Test that opensearch_ppl_time_field custom attribute is used."""
    rule = """
title: Test Custom Time Field
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
custom:
  opensearch_ppl_time_field: "event.created"
  opensearch_ppl_min_time: "-7d"
"""
    backend = OpenSearchPPLBackend()
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # Should use custom time field, not default @timestamp
    assert "event.created >=" in result
    assert "@timestamp" not in result


def test_custom_min_max_time_attributes():
    """Test that opensearch_ppl_min_time and opensearch_ppl_max_time work."""
    rule = """
title: Test Custom Time Range
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
custom:
  opensearch_ppl_min_time: "-30d"
  opensearch_ppl_max_time: "now"
"""
    backend = OpenSearchPPLBackend()
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # Should include time filters
    assert ">= now() - 30d" in result
    assert "<= now()" in result


def test_custom_attributes_priority_over_backend_options():
    """Test that custom attributes override backend options."""
    rule = """
title: Test Priority
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
custom:
  opensearch_ppl_index: "custom-index-*"
  opensearch_ppl_min_time: "-7d"
"""
    # Backend initialized with different options
    backend = OpenSearchPPLBackend(
        custom_logsource="backend-option-index-*",
        min_time="-30d"
    )
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # Custom attributes should take priority
    assert "source=custom-index-*" in result
    assert ">= now() - 7d" in result
    # Should NOT use backend options
    assert "backend-option-index-*" not in result
    assert "30d" not in result


def test_all_custom_attributes_together():
    """Test using all custom attributes in one rule."""
    rule = """
title: Test All Custom Attributes
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
custom:
  opensearch_ppl_index: "complete-test-*"
  opensearch_ppl_time_field: "custom_timestamp"
  opensearch_ppl_min_time: "-14d"
  opensearch_ppl_max_time: "now"
"""
    backend = OpenSearchPPLBackend()
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # All custom settings should be present
    assert "source=complete-test-*" in result
    assert "custom_timestamp >=" in result
    assert ">= now() - 14d" in result
    assert "<= now()" in result


def test_no_custom_attributes_uses_defaults():
    """Test that without custom attributes, backend uses defaults."""
    rule = """
title: Test Defaults
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
"""
    backend = OpenSearchPPLBackend()
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # Should use default logsource-based mapping
    assert "source=windows-process_creation-*" in result
    # Should NOT have time filters (no min/max time set)
    assert "@timestamp" not in result


def test_partial_custom_attributes():
    """Test that only specified custom attributes are used."""
    rule = """
title: Test Partial Custom
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: test.exe
  condition: selection
custom:
  opensearch_ppl_index: "partial-custom-*"
  # Only index is custom, others use defaults
"""
    backend = OpenSearchPPLBackend()
    sigma_rule = SigmaCollection.from_yaml(rule)
    result = backend.convert(sigma_rule)[0]
    
    # Custom index should be used
    assert "source=partial-custom-*" in result
    # Default behavior for time (no time filter)
    assert ">=" not in result or "@timestamp" not in result


if __name__ == "__main__":
    # Run tests manually for demonstration
    print("Running custom attributes tests...\n")
    
    tests = [
        ("Custom Index", test_custom_index_attribute),
        ("Custom Time Field", test_custom_time_field_attribute),
        ("Custom Time Range", test_custom_min_max_time_attributes),
        ("Priority Over Backend Options", test_custom_attributes_priority_over_backend_options),
        ("All Attributes", test_all_custom_attributes_together),
        ("Defaults Without Custom", test_no_custom_attributes_uses_defaults),
        ("Partial Custom", test_partial_custom_attributes),
    ]
    
    for name, test_func in tests:
        try:
            test_func()
            print(f"[PASS] {name}")
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
        except Exception as e:
            print(f"[ERROR] {name}: {type(e).__name__}: {e}")
    
    print("\nDone!")
