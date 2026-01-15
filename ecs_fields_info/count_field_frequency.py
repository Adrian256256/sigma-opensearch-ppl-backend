#!/usr/bin/env python3
"""
Script to count the frequency of Sigma fields and output them sorted by frequency.
Reads from sigma_fields_with_paths.csv and creates sigma_fields_frequency.csv
"""

import csv
from collections import Counter
import os

# File paths
INPUT_FILE = 'sigma_fields_with_paths.csv'
OUTPUT_FILE = 'sigma_fields_frequency.csv'

def count_field_frequency(input_file, output_file):
    """
    Count the frequency of each field in the input CSV and write results to output CSV.
    
    Args:
        input_file: Path to the input CSV file with fields
        output_file: Path to the output CSV file for frequency results
    """
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, input_file)
    output_path = os.path.join(script_dir, output_file)
    
    # Counter to store field frequencies
    field_counter = Counter()
    
    # Read the input CSV file
    print(f"Reading from: {input_path}")
    with open(input_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            field = row['field'].strip()
            # Count all fields, including empty ones
            field_counter[field] += 1
    
    # Sort by frequency (descending) and then alphabetically by field name
    sorted_fields = sorted(field_counter.items(), key=lambda x: (-x[1], x[0]))
    
    # Write results to output CSV
    print(f"Writing results to: {output_path}")
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['field', 'frequency'])
        
        for field, frequency in sorted_fields:
            writer.writerow([field, frequency])
    
    # Print summary statistics
    total_entries = sum(field_counter.values())
    unique_fields = len(field_counter)
    
    print(f"\n=== Summary ===")
    print(f"Total entries: {total_entries}")
    print(f"Unique fields: {unique_fields}")
    print(f"\nTop 10 most frequent fields:")
    for i, (field, freq) in enumerate(sorted_fields[:10], 1):
        field_display = field if field else "(empty)"
        print(f"  {i:2d}. {field_display:40s} - {freq:5d} occurrences")
    
    print(f"\nResults saved to: {output_file}")

if __name__ == '__main__':
    count_field_frequency(INPUT_FILE, OUTPUT_FILE)
