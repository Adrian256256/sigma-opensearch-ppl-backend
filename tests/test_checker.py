#!/usr/bin/env python3
"""
Test Checker for Sigma to OpenSearch PPL Backend

This script runs the backend on all test rules and compares the output
with the expected reference PPL queries.
"""

import os
import sys
from pathlib import Path
from typing import Tuple, List
import argparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend


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
            error=f"File not found: {str(e)}"
        )
    except Exception as e:
        return TestResult(
            rule_name=rule_name,
            passed=False,
            error=f"{type(e).__name__}: {str(e)}"
        )


def get_all_test_rules(rules_dir: Path) -> List[str]:
    """Get all rule files from the rules directory"""
    rule_files = list(rules_dir.glob("*.yml"))
    # Extract base names without extension
    return sorted([f.stem for f in rule_files])


def print_test_result(result: TestResult, verbose: bool = False):
    """Print the result of a test"""
    status = "✅ PASS" if result.passed else "❌ FAIL"
    print(f"{status} | {result.rule_name}")
    
    if not result.passed and verbose:
        if result.error:
            print(f"  Error: {result.error}")
        else:
            print(f"  Expected: {result.expected}")
            print(f"  Got:      {result.actual}")


def print_summary(results: List[TestResult]):
    """Print test summary"""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests:  {total}")
    print(f"Passed:       {passed} ({100 * passed / total:.1f}%)" if total > 0 else "Passed: 0")
    print(f"Failed:       {failed}")
    print("=" * 70)
    
    if failed > 0:
        print("\nFailed tests:")
        for result in results:
            if not result.passed:
                print(f"  - {result.rule_name}")
                if result.error:
                    print(f"    Error: {result.error}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Test checker for Sigma to OpenSearch PPL backend"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output for failed tests"
    )
    parser.add_argument(
        "-t", "--test",
        type=str,
        help="Run only specific test (rule name without extension)"
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show output for all tests, including passed ones"
    )
    
    args = parser.parse_args()
    
    # Setup paths
    tests_dir = Path(__file__).parent
    rules_dir = tests_dir / "rules"
    refs_dir = tests_dir / "refs"
    out_dir = tests_dir / "out"
    
    # Create output directory if it doesn't exist
    out_dir.mkdir(exist_ok=True)
    
    # Validate directories exist
    if not rules_dir.exists():
        print(f"❌ Rules directory not found: {rules_dir}")
        sys.exit(1)
    
    if not refs_dir.exists():
        print(f"❌ References directory not found: {refs_dir}")
        sys.exit(1)
    
    # Create backend instance
    backend = OpenSearchPPLBackend()
    
    # Get test cases
    if args.test:
        test_rules = [args.test]
        print(f"\n🧪 Running single test: {args.test}\n")
    else:
        test_rules = get_all_test_rules(rules_dir)
        print(f"\n🧪 Running {len(test_rules)} tests...\n")
    
    print("=" * 70)
    
    # Run tests
    results = []
    for rule_name in test_rules:
        result = run_test(backend, rules_dir, refs_dir, out_dir, rule_name)
        results.append(result)
        
        if args.show_all or not result.passed or args.verbose:
            print_test_result(result, verbose=args.verbose or args.show_all)
        elif result.passed:
            # Just show the checkmark in compact mode
            print(f"✅ PASS | {result.rule_name}")
    
    # Print summary
    print_summary(results)
    
    # Exit with appropriate code
    all_passed = all(r.passed for r in results)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
