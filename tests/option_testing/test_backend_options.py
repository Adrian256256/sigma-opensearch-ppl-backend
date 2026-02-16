#!/usr/bin/env python3
"""
Test script for backend options functionality.

Demonstrates how to use backend options to customize query generation,
similar to Splunk's -O/--backend-option parameter.
"""
import sys
from pathlib import Path

# Add project root to path to import sigma_backend
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend

# Example Sigma rule
SIGMA_RULE = """
title: Test Rule - Process Creation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: 'Invoke-'
  condition: selection
"""

def test_default_logsource():
    """Test default logsource behavior (auto-generated from rule)."""
    print("=" * 80)
    print("TEST 1: Default logsource (auto-generated)")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend()
    
    queries = backend.convert(collection)
    print("\nGenerated query:")
    print(queries[0])
    print("\nNote: Index pattern 'windows-process_creation-*' was auto-generated from logsource\n")


def test_custom_logsource():
    """Test custom logsource override via backend option."""
    print("=" * 80)
    print("TEST 2: Custom logsource (backend option override)")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    
    # Initialize backend with custom logsource
    backend = OpenSearchPPLBackend(custom_logsource="my-custom-logs-*")
    
    queries = backend.convert(collection)
    print("\nGenerated query:")
    print(queries[0])
    print("\nNote: Index pattern 'my-custom-logs-*' was provided via backend option\n")


def test_multiple_custom_logsources():
    """Test multiple different custom logsources."""
    print("=" * 80)
    print("TEST 3: Multiple custom logsources")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    
    custom_sources = [
        "security-logs-*",
        "windows-events-*",
        "custom-index-pattern-*",
        "logs-windows-*",
    ]
    
    for source in custom_sources:
        backend = OpenSearchPPLBackend(custom_logsource=source)
        queries = backend.convert(collection)
        print(f"\nLogsource '{source}':")
        print(f"  {queries[0]}")


def test_time_filters_default():
    """Test query without time filters (default behavior)."""
    print("=" * 80)
    print("TEST 4: Default behavior - No time filters")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend()
    
    queries = backend.convert(collection)
    print("\nGenerated query (without time filters):")
    print(queries[0])
    print("\nNote: No time filters added - query remains unchanged\n")


def test_time_filters_relative():
    """Test relative time filters (-30d, now)."""
    print("=" * 80)
    print("TEST 5: Relative time filters (-30d to now)")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend(min_time="-30d", max_time="now")
    
    queries = backend.convert(collection)
    print("\nGenerated query with relative time filters:")
    print(queries[0])
    print("\nNote: Time filters '@timestamp >= now() - 30d AND @timestamp <= now()' added\n")


def test_time_filters_absolute():
    """Test absolute time filters."""
    print("=" * 80)
    print("TEST 6: Absolute time filters")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend(
        min_time="2024-01-01T00:00:00",
        max_time="2024-01-31T23:59:59"
    )
    
    queries = backend.convert(collection)
    print("\nGenerated query with absolute time filters:")
    print(queries[0])
    print("\nNote: Absolute timestamps wrapped in quotes\n")


def test_time_filters_only_min():
    """Test with only minimum time filter."""
    print("=" * 80)
    print("TEST 7: Only minimum time filter")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend(min_time="-7d")
    
    queries = backend.convert(collection)
    print("\nGenerated query with only min_time:")
    print(queries[0])
    print("\nNote: Only '@timestamp >= now() - 7d' filter added\n")


def test_time_filters_only_max():
    """Test with only maximum time filter."""
    print("=" * 80)
    print("TEST 8: Only maximum time filter")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend(max_time="now")
    
    queries = backend.convert(collection)
    print("\nGenerated query with only max_time:")
    print(queries[0])
    print("\nNote: Only '@timestamp <= now()' filter added\n")


def test_combined_options():
    """Test combining custom logsource with time filters."""
    print("=" * 80)
    print("TEST 9: Combined options (custom logsource + time filters)")
    print("=" * 80)
    
    collection = SigmaCollection.from_yaml(SIGMA_RULE)
    backend = OpenSearchPPLBackend(
        custom_logsource="security-logs-*",
        min_time="-24h",
        max_time="now"
    )
    
    queries = backend.convert(collection)
    print("\nGenerated query with custom logsource AND time filters:")
    print(queries[0])
    print("\nNote: Both custom index pattern and time filters applied\n")


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "Backend Options Test Suite" + " " * 32 + "║")
    print("╚" + "=" * 78 + "╝")
    print("\n")
    
    test_default_logsource()
    test_custom_logsource()
    test_multiple_custom_logsources()
    test_time_filters_default()
    test_time_filters_relative()
    test_time_filters_absolute()
    test_time_filters_only_min()
    test_time_filters_only_max()
    test_combined_options()
    
    print("\n" + "=" * 80)
    print("USAGE IN COMMAND LINE (when integrated with sigma CLI):")
    print("=" * 80)
    print("""
# Default behavior (auto-generate from logsource)
sigma convert -t opensearch-ppl rule.yml

# Custom logsource
sigma convert -t opensearch-ppl -O custom_logsource=my-logs-* rule.yml

# Time filters (relative)
sigma convert -t opensearch-ppl -O min_time=-30d -O max_time=now rule.yml

# Time filters (absolute)
sigma convert -t opensearch-ppl -O min_time=2024-01-01T00:00:00 -O max_time=2024-12-31T23:59:59 rule.yml

# Combined options
sigma convert -t opensearch-ppl \\
    -O custom_logsource=security-* \\
    -O min_time=-7d \\
    -O max_time=now \\
    rule.yml

# Convert entire directory with options
sigma convert -t opensearch-ppl \\
    -O custom_logsource=security-* \\
    -O min_time=-24h \\
    -O max_time=now \\
    -o output/ \\
    rules/
""")
    
    print("\n" + "=" * 80)
    print("PROGRAMMATIC USAGE:")
    print("=" * 80)
    print("""
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend

# With custom logsource
backend = OpenSearchPPLBackend(custom_logsource="my-custom-logs-*")

# With time filters (relative)
backend = OpenSearchPPLBackend(min_time="-30d", max_time="now")

# With time filters (absolute)
backend = OpenSearchPPLBackend(
    min_time="2024-01-01T00:00:00",
    max_time="2024-12-31T23:59:59"
)

# Combined options
backend = OpenSearchPPLBackend(
    custom_logsource="security-logs-*",
    min_time="-7d",
    max_time="now"
)

# Multiple queries for different indices with time filters
for index in ["logs-a-*", "logs-b-*", "logs-c-*"]:
    backend = OpenSearchPPLBackend(
        custom_logsource=index,
        min_time="-24h",
        max_time="now"
    )
    queries = backend.convert(collection)
""")


if __name__ == "__main__":
    main()
