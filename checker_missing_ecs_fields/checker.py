#!/usr/bin/env python3
"""
Script to extract all field names from Sigma rules and output them to a CSV file.
Each row contains the rule filename and all fields found in that rule.
"""

import os
import yaml
import csv
from pathlib import Path
from typing import Set, List, Dict, Any


def extract_fields_from_value(value: Any, fields: Set[str]) -> None:
    """
    Recursively extract field names from detection values.
    Handles nested dictionaries and lists.
    """
    if isinstance(value, dict):
        for key, val in value.items():
            # Check if the key contains a pipe (field with modifier)
            if '|' in key:
                # Extract the field name (part before the pipe)
                field_name = key.split('|')[0]
                fields.add(field_name)
            elif key not in ['condition', 'timeframe', 'correlation', 'type', 'rules', 'group-by', 'ordered', 'generate']:
                # It's likely a field name (not a keyword)
                # Skip special Sigma keywords
                if not key.startswith('selection') and not key.startswith('filter') and not key.startswith('keyword'):
                    fields.add(key)
            
            # Recursively process the value
            extract_fields_from_value(val, fields)
    elif isinstance(value, list):
        for item in value:
            extract_fields_from_value(item, fields)


def extract_fields_from_detection(detection: Dict[str, Any]) -> Set[str]:
    """
    Extract all field names from a Sigma rule's detection section.
    """
    fields = set()
    
    if not isinstance(detection, dict):
        return fields
    
    for key, value in detection.items():
        # Skip the condition key as it doesn't contain field definitions
        if key == 'condition':
            continue
        
        # Process selection/filter blocks
        if isinstance(value, dict):
            for field_key, field_value in value.items():
                # Check if the field has a modifier (contains pipe)
                if '|' in field_key:
                    field_name = field_key.split('|')[0]
                    fields.add(field_name)
                else:
                    # It's a plain field name
                    fields.add(field_key)
                
                # Recursively check nested structures
                extract_fields_from_value(field_value, fields)
        elif isinstance(value, list):
            # Handle list of selections
            for item in value:
                extract_fields_from_value(item, fields)
    
    return fields


def process_sigma_rules(rules_directory: str, output_csv: str) -> None:
    """
    Process all Sigma rules in the directory and extract unique fields to CSV.
    
    Args:
        rules_directory: Path to the sigma-master/rules directory
        output_csv: Path to the output CSV file
    """
    rules_path = Path(rules_directory)
    
    if not rules_path.exists():
        print(f"Error: Directory {rules_directory} does not exist!")
        return
    
    # Find all YAML files
    yaml_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
    
    print(f"Found {len(yaml_files)} Sigma rule files")
    
    # Use a set to collect all unique fields
    all_fields = set()
    errors = []
    processed_count = 0
    
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            
            if not rule_data or 'detection' not in rule_data:
                continue
            
            # Extract fields from detection section
            fields = extract_fields_from_detection(rule_data['detection'])
            
            if fields:
                all_fields.update(fields)
                processed_count += 1
        
        except yaml.YAMLError as e:
            errors.append(f"YAML error in {yaml_file}: {e}")
        except Exception as e:
            errors.append(f"Error processing {yaml_file}: {e}")
    
    # Sort fields alphabetically for consistent output
    sorted_fields = sorted(all_fields)
    
    # Write results to CSV - one field per line
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow(['field'])
        
        # Write each unique field on its own line
        for field in sorted_fields:
            writer.writerow([field])
    
    print(f"\nProcessed {processed_count} rules successfully")
    print(f"Found {len(sorted_fields)} unique fields")
    print(f"Output written to: {output_csv}")
    
    if errors:
        print(f"\nEncountered {len(errors)} errors:")
        for error in errors[:10]:  # Show first 10 errors
            print(f"  - {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")


def main():
    """Main entry point of the script."""
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    
    # Define paths
    rules_directory = script_dir / "sigma-master" / "rules"
    output_csv = script_dir / "sigma_fields.csv"
    
    print("=" * 60)
    print("Sigma Rules Field Extractor")
    print("=" * 60)
    print(f"Rules directory: {rules_directory}")
    print(f"Output CSV: {output_csv}")
    print("=" * 60)
    print()
    
    process_sigma_rules(str(rules_directory), str(output_csv))
    
    print("\nDone!")


if __name__ == "__main__":
    main()
