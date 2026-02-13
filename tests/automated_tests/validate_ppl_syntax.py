#!/usr/bin/env python3
"""
Validate PPL query syntax against OpenSearch.
Tests all reference queries in refs/ directory for syntactic correctness.
"""

import requests
from pathlib import Path
import json
from requests.auth import HTTPBasicAuth
import sys

# OpenSearch configuration
OPENSEARCH_URL = "http://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "admin"

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def validate_ppl_syntax(query: str) -> dict:
    """
    Validate PPL query syntax by executing it against OpenSearch.
    
    Args:
        query: PPL query string to validate
        
    Returns:
        dict with 'valid', 'error', 'error_type' keys
    """
    try:
        response = requests.post(
            f"{OPENSEARCH_URL}/_plugins/_ppl",
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            json={"query": query},
            timeout=10
        )
        
        if response.status_code == 200:
            # Query executed successfully
            result = response.json()
            return {
                'valid': True,
                'error': None,
                'error_type': None,
                'hits': result.get('total', 0)
            }
        elif response.status_code == 404:
            # Index not found - but syntax is OK
            error_data = response.json()
            if 'error' in error_data:
                error_type = error_data['error'].get('type', '')
                if 'IndexNotFoundException' in error_type or 'no such index' in error_data['error'].get('reason', ''):
                    return {
                        'valid': True,
                        'error': 'Index not found (syntax is valid)',
                        'error_type': 'IndexNotFoundException',
                        'hits': 0
                    }
            return {
                'valid': False,
                'error': response.text,
                'error_type': 'NotFound',
                'hits': 0
            }
        else:
            # Syntax error or other error
            return {
                'valid': False,
                'error': response.text,
                'error_type': 'SyntaxError',
                'hits': 0
            }
    except requests.exceptions.ConnectionError:
        return {
            'valid': False,
            'error': 'Could not connect to OpenSearch. Is it running on localhost:9200?',
            'error_type': 'ConnectionError',
            'hits': 0
        }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'error_type': 'Exception',
            'hits': 0
        }

def validate_all_refs():
    """Validate all reference PPL queries in refs/ directory."""
    refs_dir = Path(__file__).parent / "refs"
    
    if not refs_dir.exists():
        print(f"{Colors.RED}Error: refs/ directory not found{Colors.END}")
        return False
    
    # Get all .txt files in refs/
    ref_files = sorted(refs_dir.glob("*.txt"))
    
    if not ref_files:
        print(f"{Colors.YELLOW}Warning: No .txt files found in refs/{Colors.END}")
        return False
    
    results = {
        'total': 0,
        'valid': 0,
        'invalid': 0,
        'index_not_found': 0,
        'connection_error': False,
        'errors': []
    }
    
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}PPL Query Syntax Validation{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}\n")
    
    for ref_file in ref_files:
        results['total'] += 1
        
        # Read query from file
        with open(ref_file, 'r') as f:
            query = f.read().strip()
        
        # Skip empty files
        if not query:
            print(f"{Colors.YELLOW}SKIPPED: {ref_file.name} (empty file){Colors.END}")
            continue
        
        print(f"\n{Colors.BOLD}Testing: {ref_file.name}{Colors.END}")
        print(f"Query: {query[:80]}{'...' if len(query) > 80 else ''}")
        
        # Validate syntax
        result = validate_ppl_syntax(query)
        
        if result['valid']:
            if result['error_type'] == 'IndexNotFoundException':
                print(f"{Colors.GREEN}VALID SYNTAX{Colors.END} (Index not found, but query is syntactically correct)")
                results['valid'] += 1
                results['index_not_found'] += 1
            else:
                print(f"{Colors.GREEN}VALID SYNTAX{Colors.END} (Returned {result['hits']} hits)")
                results['valid'] += 1
        else:
            if result['error_type'] == 'ConnectionError':
                print(f"{Colors.RED}CONNECTION ERROR{Colors.END}")
                print(f"  {result['error']}")
                results['connection_error'] = True
                results['invalid'] += 1
            else:
                print(f"{Colors.RED}INVALID SYNTAX{Colors.END}")
                error_preview = result['error'][:200] if result['error'] else 'Unknown error'
                print(f"  {error_preview}{'...' if len(result['error']) > 200 else ''}")
                results['invalid'] += 1
                results['errors'].append({
                    'file': ref_file.name,
                    'query': query,
                    'error': result['error']
                })
    
    # Print summary
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}VALIDATION SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"Total queries tested: {results['total']}")
    print(f"{Colors.GREEN}Valid syntax: {results['valid']}{Colors.END}")
    if results['index_not_found'] > 0:
        print(f"  {Colors.YELLOW}Index not found: {results['index_not_found']} (syntax OK){Colors.END}")
    print(f"{Colors.RED}Invalid syntax: {results['invalid']}{Colors.END}")
    
    if results['connection_error']:
        print(f"\n{Colors.RED}{Colors.BOLD}Connection Error: Could not connect to OpenSearch{Colors.END}")
        print(f"{Colors.YELLOW}Make sure OpenSearch is running: docker ps{Colors.END}")
        return False
    
    if results['errors']:
        print(f"\n{Colors.RED}{Colors.BOLD}Failed Queries:{Colors.END}")
        for i, err in enumerate(results['errors'], 1):
            print(f"\n{i}. {Colors.BOLD}{err['file']}{Colors.END}")
            print(f"   Query: {err['query'][:100]}...")
            print(f"   Error: {err['error'][:150]}...")
    
    print()
    
    # Return success if all queries are valid
    return results['invalid'] == 0

if __name__ == "__main__":
    success = validate_all_refs()
    sys.exit(0 if success else 1)
