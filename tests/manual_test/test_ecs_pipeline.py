#!/usr/bin/env python3
"""
Test script for ECS Field Mapping Pipeline

This demonstrates the YAML-based approach to ECS field mapping.
"""

import sys
from pathlib import Path

# Add project root directory to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
from ecs_mapping import load_ecs_pipeline_from_yaml


def test_yaml_ecs_mapping():
    """Test YAML-based ECS field mapping"""
    
    # Example Sigma rule
    sigma_rule_yaml = """
    title: Suspicious PowerShell Execution
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|contains:
                - 'powershell'
                - 'Invoke-Expression'
            ProcessName|endswith: 'powershell.exe'
            User: Administrator
        condition: selection
    """
    
    print("=" * 80)
    print("ECS FIELD MAPPING TEST")
    print("=" * 80)
    print()
    
    # Test 1: Without ECS pipeline
    print("Test 1: WITHOUT ECS Pipeline")
    print("-" * 80)
    backend_no_ecs = OpenSearchPPLBackend()
    collection = SigmaCollection.from_yaml(sigma_rule_yaml)
    result_no_ecs = backend_no_ecs.convert(collection)
    
    if isinstance(result_no_ecs, list):
        result_no_ecs = result_no_ecs[0] if result_no_ecs else ""
    
    print("Generated PPL Query (Original Field Names):")
    print(result_no_ecs)
    print()
    
    # Test 2: With YAML-based ECS pipeline
    print("Test 2: WITH ECS Pipeline (YAML-based)")
    print("-" * 80)
    
    try:
        ecs_pipeline = load_ecs_pipeline_from_yaml()
        backend_with_ecs = OpenSearchPPLBackend(processing_pipeline=ecs_pipeline)
        collection = SigmaCollection.from_yaml(sigma_rule_yaml)
        result_with_ecs = backend_with_ecs.convert(collection)
        
        if isinstance(result_with_ecs, list):
            result_with_ecs = result_with_ecs[0] if result_with_ecs else ""
        
        print("Generated PPL Query (ECS Field Names from YAML):")
        print(result_with_ecs)
        print()
    except Exception as e:
        print(f"Error loading YAML pipeline: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 3: Network rule
    print("=" * 80)
    print("Test 3: NETWORK RULE WITH ECS MAPPING")
    print("-" * 80)
    
    network_rule_yaml = """
    title: Suspicious Network Connection
    logsource:
        product: windows
        category: network_connection
    detection:
        selection:
            DestinationIp|startswith: '192.168.'
            DestinationPort: 445
            Protocol: tcp
        condition: selection
    """
    
    try:
        ecs_pipeline = load_ecs_pipeline_from_yaml()
        backend_network = OpenSearchPPLBackend(processing_pipeline=ecs_pipeline)
        collection = SigmaCollection.from_yaml(network_rule_yaml)
        result_network = backend_network.convert(collection)
        
        if isinstance(result_network, list):
            result_network = result_network[0] if result_network else ""
        
        print("Generated PPL Query (Network fields mapped to ECS):")
        print(result_network)
        print()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        test_yaml_ecs_mapping()
    except Exception as e:
        print(f"\nError occurred: {type(e).__name__}")
        print(f"Message: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
