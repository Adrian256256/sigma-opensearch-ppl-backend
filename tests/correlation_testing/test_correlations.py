#!/usr/bin/env python3
"""Test script for Sigma correlation rules conversion to OpenSearch PPL."""

import sys
from pathlib import Path

script_dir = Path(__file__).parent
project_root = script_dir.parent.parent
sys.path.insert(0, str(project_root))

from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLCorrelationBackend


class CorrelationTester:
    """Test harness for correlation rule conversion."""
    
    def __init__(self, rules_dir: Path, output_dir: Path, refs_dir: Path = None):
        self.rules_dir = rules_dir
        self.output_dir = output_dir
        self.refs_dir = refs_dir
        self.backend = OpenSearchPPLCorrelationBackend()
        self.output_dir.mkdir(exist_ok=True)
        
        self.stats = {
            'successful': 0,
            'failed': 0,
            'validation_passed': 0,
            'validation_failed': 0,
        }
    
    def process_all_rules(self):
        """Process all correlation rule files."""
        rule_files = sorted(self.rules_dir.glob("*.yml")) + sorted(self.rules_dir.glob("*.yaml"))
        
        for rule_file in rule_files:
            self.process_rule_file(rule_file)
        
        if self.refs_dir and self.refs_dir.exists():
            self.validate_outputs()
        
        self.print_summary()
    
    def process_rule_file(self, rule_file: Path):
        """Process a single correlation rule file."""
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                collection = SigmaCollection.from_yaml(f.read())
            
            # First, convert all base rules (non-correlation rules)
            base_rules = [r for r in collection.rules 
                         if not (hasattr(r, 'type') and hasattr(r, 'rules') and hasattr(r, 'timespan'))]
            
            for base_rule in base_rules:
                try:
                    self.backend.convert_rule(base_rule)
                except Exception:
                    pass  # Ignore errors in base rule conversion
            
            # Now process correlation rules
            correlation_rules = [r for r in collection.rules 
                               if hasattr(r, 'type') and hasattr(r, 'rules') and hasattr(r, 'timespan')]
            
            if not correlation_rules:
                return
            
            results = []
            for corr_rule in correlation_rules:
                try:
                    queries = self.backend.convert_correlation_rule(corr_rule)
                    results.append(queries[0] if queries else "")
                    self.stats['successful'] += 1
                except Exception as e:
                    results.append(f"ERROR: {str(e)}")
                    self.stats['failed'] += 1
            
            if results:
                output_file = self.output_dir / f"{rule_file.stem}.txt"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(results))
                    
        except Exception as e:
            self.stats['failed'] += 1
    
    def validate_outputs(self):
        """Validate generated output files against reference files."""
        output_files = sorted(self.output_dir.glob("*.txt"))
        
        for output_file in output_files:
            ref_file = self.refs_dir / output_file.name
            
            if not ref_file.exists():
                continue
            
            with open(output_file, 'r', encoding='utf-8') as f:
                output_query = f.read().strip()
            
            with open(ref_file, 'r', encoding='utf-8') as f:
                ref_query = f.read().strip()
            
            if output_query == ref_query:
                self.stats['validation_passed'] += 1
                print(f"[PASS] {output_file.name}")
            else:
                self.stats['validation_failed'] += 1
                print(f"[FAIL] {output_file.name}")
                print(f"  Expected: {ref_query}")
                print(f"  Got:      {output_query}")
    
    def print_summary(self):
        """Print summary of test results."""
        print(f"\n{'='*80}")
        print(f"CONVERSION: {self.stats['successful']} passed, {self.stats['failed']} failed")
        if self.refs_dir:
            print(f"VALIDATION: {self.stats['validation_passed']} passed, {self.stats['validation_failed']} failed")
        print(f"{'='*80}\n")


def main():
    script_dir = Path(__file__).parent
    rules_dir = script_dir / "sigma_rules"
    output_dir = script_dir / "out"
    refs_dir = script_dir / "ppl_refs"
    
    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)
    
    tester = CorrelationTester(rules_dir, output_dir, refs_dir)
    tester.process_all_rules()


if __name__ == "__main__":
    main()
