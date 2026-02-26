#!/usr/bin/env python3
"""
Test Checker for Custom Attributes in Sigma to OpenSearch PPL Backend

This script runs the backend on all custom attribute test rules and compares
the output with the expected reference PPL queries.
"""

import os
import sys
from pathlib import Path
from typing import Tuple, List
import argparse

# Add project root directory to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend


class TestResult:
    """Holds the result of a single test"""
    def __init__(self, rule_name: str, passed: bool, expected: str = "", actual: str = "", error: str = ""):
        self.rule_name = rule_name
        self.passed = passed
        self.expected = expected
        self.actual = actual
        self.error = error


def normalize_query(query: str) -> str:
    """Normalize a PPL query for comparison by removing extra whitespace"""
    # Remove leading/trailing whitespace
    query = query.strip()
    # Replace multiple spaces with single space
    query = ' '.join(query.split())
    return query


def load_expected_output(refs_dir: Path, rule_name: str) -> str:
    """Load the expected PPL output from refs directory"""
    ref_file = refs_dir / f"{rule_name}.txt"
    if not ref_file.exists():
        raise FileNotFoundError(f"Reference file not found: {ref_file}")
    
    with open(ref_file, 'r') as f:
        return f.read().strip()


def convert_rule_to_ppl(backend: OpenSearchPPLBackend, rule_file: Path) -> str:
    """Convert a Sigma rule to PPL query"""
    with open(rule_file, 'r') as f:
        yaml_content = f.read()
    
    collection = SigmaCollection.from_yaml(yaml_content)
    ppl_query = backend.convert(collection)
    
    # Handle list output (convert returns list)
    if isinstance(ppl_query, list):
        ppl_query = ppl_query[0] if ppl_query else ""
    
    return str(ppl_query).strip()


def run_test(backend: OpenSearchPPLBackend, rules_dir: Path, refs_dir: Path, out_dir: Path, rule_name: str) -> TestResult:
    """Run a single test case"""
    rule_file = rules_dir / f"{rule_name}.yml"
    
    try:
        # Load expected output
        expected = load_expected_output(refs_dir, rule_name)
        
        # Convert rule to PPL
        actual = convert_rule_to_ppl(backend, rule_file)
        
        # Save actual output to out directory
        out_file = out_dir / f"{rule_name}.txt"
        with open(out_file, 'w') as f:
            f.write(actual)
        
        # Normalize both queries for comparison
        expected_normalized = normalize_query(expected)
        actual_normalized = normalize_query(actual)
        
        # Compare
        passed = (expected_normalized == actual_normalized)
        
        return TestResult(
            rule_name=rule_name,
            passed=passed,
            expected=expected,
            actual=actual
        )
        
    except FileNotFoundError as e:
        return TestResult(
            rule_name=rule_name,
            passed=False,
            error=str(e)
        )
    except Exception as e:
        return TestResult(
            rule_name=rule_name,
            passed=False,
            error=f"Error converting rule: {str(e)}"
        )


def print_results(results: List[TestResult], verbose: bool = False):
    """Print test results"""
    passed_count = sum(1 for r in results if r.passed)
    failed_count = len(results) - passed_count
    
    print(f"\n{'='*80}")
    print(f"TEST RESULTS: {passed_count}/{len(results)} passed")
    print(f"{'='*80}\n")
    
    # Print failed tests
    if failed_count > 0:
        print("FAILED TESTS:")
        print("-" * 80)
        for result in results:
            if not result.passed:
                print(f"\nFAILED: {result.rule_name}")
                if result.error:
                    print(f"   Error: {result.error}")
                else:
                    print(f"   Expected: {result.expected}")
                    print(f"   Actual:   {result.actual}")
        print()
    
    # Print passed tests if verbose
    if verbose and passed_count > 0:
        print("PASSED TESTS:")
        print("-" * 80)
        for result in results:
            if result.passed:
                print(f"PASSED: {result.rule_name}")
        print()
    
    # Summary
    if failed_count == 0:
        print("All tests passed!")
    else:
        print(f"WARNING: {failed_count} test(s) failed")
    
    return failed_count == 0


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="Test custom attribute functionality")
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all test results')
    parser.add_argument('-t', '--test', type=str, help='Run specific test by name')
    args = parser.parse_args()
    
    # Setup directories
    test_dir = Path(__file__).parent
    rules_dir = test_dir / "rules"
    refs_dir = test_dir / "refs"
    out_dir = test_dir / "out"
    
    # Create out directory if it doesn't exist
    out_dir.mkdir(exist_ok=True)
    
    # Initialize backend
    backend = OpenSearchPPLBackend()
    
    # Get list of test rules
    if args.test:
        test_rules = [args.test]
    else:
        test_rules = sorted([f.stem for f in rules_dir.glob("*.yml")])
    
    if not test_rules:
        print("No test rules found!")
        return 1
    
    # Run tests
    print(f"\nRunning {len(test_rules)} custom attribute test(s)...\n")
    results = []
    
    for rule_name in test_rules:
        result = run_test(backend, rules_dir, refs_dir, out_dir, rule_name)
        results.append(result)
        
        # Print progress
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {rule_name}")
    
    # Print detailed results
    success = print_results(results, verbose=args.verbose)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
