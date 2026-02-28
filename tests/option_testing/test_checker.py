#!/usr/bin/env python3
"""
Test Checker for Backend Options in Sigma to OpenSearch PPL Backend

This script runs the backend on all backend option test rules and compares
the output with the expected reference PPL queries.

Tests the following backend options:
- custom_logsource: Custom index pattern override
- min_time: Minimum time filter (relative or absolute)
- max_time: Maximum time filter (relative or absolute)
"""

import os
import sys
from pathlib import Path
from typing import Tuple, List, Dict
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


# Test configurations mapping rule names to backend options
TEST_CONFIGS = {
    "default_logsource": {},
    "custom_logsource": {
        "custom_logsource": "my-custom-logs-*"
    },
    "time_filters_relative": {
        "min_time": "-30d",
        "max_time": "now"
    },
    "time_filters_absolute": {
        "min_time": "2024-01-01T00:00:00",
        "max_time": "2024-01-31T23:59:59"
    },
    "time_filters_min_only": {
        "min_time": "-7d"
    },
    "time_filters_max_only": {
        "max_time": "now"
    },
    "combined_options": {
        "custom_logsource": "security-logs-*",
        "min_time": "-24h",
        "max_time": "now"
    }
}


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


def run_test(rules_dir: Path, refs_dir: Path, out_dir: Path, rule_name: str) -> TestResult:
    """Run a single test case"""
    rule_file = rules_dir / f"{rule_name}.yml"
    
    try:
        # Get backend options for this test
        backend_options = TEST_CONFIGS.get(rule_name, {})
        
        # Load expected output
        expected = load_expected_output(refs_dir, rule_name)
        
        # Create backend with appropriate options
        backend = OpenSearchPPLBackend(**backend_options)
        
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
            error=f"File not found: {e}"
        )
    except Exception as e:
        return TestResult(
            rule_name=rule_name,
            passed=False,
            error=f"Error: {type(e).__name__}: {e}"
        )


def print_test_result(result: TestResult, verbose: bool = False):
    """Print the result of a single test"""
    status = "✓ PASSED" if result.passed else "✗ FAILED"
    color = "\033[92m" if result.passed else "\033[91m"
    reset = "\033[0m"
    
    print(f"{color}{status}{reset} - {result.rule_name}")
    
    if not result.passed:
        if result.error:
            print(f"  Error: {result.error}")
        else:
            print(f"  Expected: {result.expected}")
            print(f"  Actual:   {result.actual}")
    
    if verbose and result.passed:
        print(f"  Query: {result.actual}")


def print_summary(results: List[TestResult]):
    """Print summary of all test results"""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total tests:  {total}")
    print(f"Passed:       {passed}")
    print(f"Failed:       {failed}")
    
    if failed > 0:
        print("\nFailed tests:")
        for result in results:
            if not result.passed:
                print(f"  - {result.rule_name}")
    
    print("=" * 80)


def get_all_test_rules(rules_dir: Path) -> List[str]:
    """Get all test rule names from the rules directory"""
    rule_files = sorted(rules_dir.glob("*.yml"))
    return [f.stem for f in rule_files]


def main():
    parser = argparse.ArgumentParser(
        description="Test backend options for Sigma to OpenSearch PPL conversion"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output including passed test queries"
    )
    parser.add_argument(
        "-t", "--test",
        help="Run only specific test (rule name without .yml extension)"
    )
    
    args = parser.parse_args()
    
    # Setup directories
    script_dir = Path(__file__).parent
    rules_dir = script_dir / "rules"
    refs_dir = script_dir / "refs"
    out_dir = script_dir / "out"
    
    # Create out directory if it doesn't exist
    out_dir.mkdir(exist_ok=True)
    
    print("\n" + "=" * 80)
    print("Backend Options Test Suite")
    print("=" * 80)
    print(f"Rules directory: {rules_dir}")
    print(f"References directory: {refs_dir}")
    print(f"Output directory: {out_dir}")
    print("=" * 80 + "\n")
    
    # Get list of tests to run
    if args.test:
        test_names = [args.test]
    else:
        test_names = get_all_test_rules(rules_dir)
    
    # Run tests
    results = []
    for test_name in test_names:
        result = run_test(rules_dir, refs_dir, out_dir, test_name)
        results.append(result)
        print_test_result(result, args.verbose)
    
    # Print summary
    print_summary(results)
    
    # Exit with error code if any tests failed
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
