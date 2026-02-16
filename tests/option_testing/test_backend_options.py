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
    
    print("\n" + "=" * 80)
    print("USAGE IN COMMAND LINE (when integrated with sigma CLI):")
    print("=" * 80)
    print("""
# Default behavior (auto-generate from logsource)
sigma convert -t opensearch-ppl rule.yml

# Custom logsource
sigma convert -t opensearch-ppl -O custom_logsource=my-logs-* rule.yml

# Convert entire directory with custom logsource
sigma convert -t opensearch-ppl \\
    -O custom_logsource=security-* \\
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

# Multiple queries for different indices
for index in ["logs-a-*", "logs-b-*", "logs-c-*"]:
    backend = OpenSearchPPLBackend(custom_logsource=index)
    queries = backend.convert(collection)
""")


if __name__ == "__main__":
    main()
