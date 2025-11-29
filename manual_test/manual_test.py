#!/usr/bin/env python3
"""
Manual testing script for OpenSearch PPL Backend
Run this to quickly test your backend implementation
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl import OpenSearchPPLBackend


# ============================================================================
# CONFIGURATION: Specify which example rules to test
# ============================================================================

# List of rule files from example_rules/ directory to test
# Add or remove rule names as needed
EXAMPLE_RULES_TO_TEST = [
    "powershell_suspicious.yml",
    "network_suspicious.yml",
]

# Set to True to test ALL rules in example_rules/ directory
TEST_ALL_EXAMPLE_RULES = False


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_example_rules():
    """Test rules from example_rules/ directory"""
    print("=" * 70)
    print("Testing Example Rules from example_rules/")
    print("=" * 70)
    
    # Get the example_rules directory
    example_rules_dir = Path(__file__).parent / "example_rules"
    
    if not example_rules_dir.exists():
        print(f"\n❌ Directory not found: {example_rules_dir}")
        return
    
    # Determine which rules to test
    if TEST_ALL_EXAMPLE_RULES:
        rule_files = list(example_rules_dir.glob("*.yml"))
        print(f"\n📚 Testing ALL {len(rule_files)} rules in example_rules/\n")
    else:
        rule_files = [example_rules_dir / rule_name for rule_name in EXAMPLE_RULES_TO_TEST]
        print(f"\n📚 Testing {len(EXAMPLE_RULES_TO_TEST)} specified rules\n")
    
    # Create backend instance
    backend = OpenSearchPPLBackend()
    
    # Test each rule
    for rule_file in rule_files:
        if not rule_file.exists():
            print(f"\n❌ Rule file not found: {rule_file.name}")
            print("-" * 70)
            continue
        
        print(f"\n📝 Testing: {rule_file.name}")
        print("-" * 70)
        
        try:
            # Load the rule
            with open(rule_file, 'r') as f:
                yaml_content = f.read()
            
            # Convert to PPL
            collection = SigmaCollection.from_yaml(yaml_content)
            ppl_query = backend.convert(collection)
            
            print("\n✅ Generated PPL Query:")
            print("─" * 70)
            print(ppl_query)
            print("─" * 70)
            
        except Exception as e:
            print(f"\n❌ Error occurred: {type(e).__name__}")
            print(f"Message: {str(e)}")
            import traceback
            traceback.print_exc()
        
        print()

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n🚀 Starting Manual Tests for OpenSearch PPL Backend\n")
    
    try:
        # Test example rules from example_rules/ directory
        test_example_rules()
        
        print("=" * 70)
        print("✅ All manual tests completed!")
        print("=" * 70)
        
    except Exception as e:
        print("\n" + "=" * 70)
        print(f"❌ Error occurred: {type(e).__name__}")
        print(f"Message: {str(e)}")
        print("=" * 70)
        import traceback
        traceback.print_exc()
