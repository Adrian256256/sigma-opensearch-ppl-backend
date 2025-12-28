#!/usr/bin/env python3
"""
Script to add ECS documentation links to ecs_verification_results.csv
"""

import csv
import re
from pathlib import Path


def get_ecs_field_set(ecs_field):
    """
    Extract the field set (first part) from an ECS field.
    'process.command_line' -> 'process'
    """
    if not ecs_field:
        return None
    
    # Handle multiple fields separated by |
    if '|' in ecs_field:
        # Take the first one
        ecs_field = ecs_field.split('|')[0].strip()
    
    # Get the first part before the dot
    parts = ecs_field.split('.')
    if parts:
        return parts[0]
    
    return None


def generate_ecs_link(ecs_field):
    """
    Generate the ECS documentation link for a given field.
    """
    field_set = get_ecs_field_set(ecs_field)
    
    if not field_set:
        return ""
    
    # Base URL for ECS documentation
    base_url = "https://www.elastic.co/guide/en/ecs/current/ecs-"
    
    # Special mappings for some field sets
    field_set_mappings = {
        'winlog': 'base',  # Windows specific, link to base
        'orchestrator': 'orchestrator',
        'container': 'container',
        'process': 'process',
        'file': 'file',
        'event': 'event',
        'user': 'user',
        'source': 'source',
        'destination': 'destination',
        'client': 'client',
        'server': 'server',
        'host': 'host',
        'network': 'network',
        'dns': 'dns',
        'tls': 'tls',
        'http': 'http',
        'url': 'url',
        'user_agent': 'user-agent',
        'log': 'log',
        'cloud': 'cloud',
        'device': 'device',
        'error': 'error',
        'registry': 'registry',
        'dll': 'dll',
        'driver': 'driver',
        'service': 'service',
        'rule': 'rule',
        'threat': 'threat',
        'vulnerability': 'vulnerability',
        'observer': 'observer',
        'organization': 'organization',
        'package': 'package',
        'related': 'related',
        'geo': 'geo',
        'hash': 'hash',
        'pe': 'pe',
        'code_signature': 'code-signature',
        'x509': 'x509',
        'as': 'as',
        'vlan': 'vlan',
        'interface': 'interface',
        'email': 'email',
        'message': 'base',  # Core field, link to base
    }
    
    # Get the mapped field set name for URL
    url_field_set = field_set_mappings.get(field_set, field_set)
    
    return f"{base_url}{url_field_set}.html"


def add_ecs_links(input_csv, output_csv):
    """
    Read the input CSV and add ECS documentation links.
    """
    rows = []
    
    with open(input_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            ecs_field = row.get('ecs_field', '')
            ecs_link = generate_ecs_link(ecs_field)
            
            # Add the new column
            row['ecs_documentation_link'] = ecs_link
            rows.append(row)
    
    # Write to output CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['sigma_field', 'ecs_field', 'ecs_documentation_link', 'notes']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    
    print(f"Successfully added ECS documentation links!")
    print(f"Output written to: {output_csv}")
    print(f"Total rows processed: {len(rows)}")


def main():
    """Main entry point of the script."""
    script_dir = Path(__file__).parent
    
    input_csv = script_dir / "ecs_verification_results.csv"
    output_csv = script_dir / "ecs_verification_results.csv"
    
    print("=" * 60)
    print("Add ECS Documentation Links")
    print("=" * 60)
    print(f"Input CSV: {input_csv}")
    print(f"Output CSV: {output_csv}")
    print("=" * 60)
    print()
    
    add_ecs_links(str(input_csv), str(output_csv))
    
    print("\nDone!")


if __name__ == "__main__":
    main()
