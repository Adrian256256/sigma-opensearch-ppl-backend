#!/usr/bin/env python3
"""
Convert EVTX files to OpenSearch bulk-ready NDJSON format.
Processes Windows Event Logs (EVTX) and converts them to JSON documents
that can be indexed into OpenSearch.
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import xmltodict


def parse_evtx_to_json(evtx_file_path):
    """
    Parse an EVTX file and convert each event to JSON format.
    
    Args:
        evtx_file_path: Path to the EVTX file
        
    Yields:
        dict: Event data as a dictionary
    """
    try:
        with evtx.Evtx(evtx_file_path) as log:
            for record in log.records():
                try:
                    # Get XML representation
                    xml_content = record.xml()
                    
                    # Convert XML to dict
                    event_dict = xmltodict.parse(xml_content)
                    
                    # Extract the Event node
                    if 'Event' in event_dict:
                        event_data = event_dict['Event']
                        
                        # Process System data
                        system_data = event_data.get('System', {})
                        event_id = system_data.get('EventID', {})
                        if isinstance(event_id, dict):
                            event_id = event_id.get('#text', 'Unknown')
                        
                        # Process EventData
                        event_details = {}
                        if 'EventData' in event_data:
                            event_data_node = event_data['EventData']
                            if event_data_node and 'Data' in event_data_node:
                                data_items = event_data_node['Data']
                                if isinstance(data_items, list):
                                    for item in data_items:
                                        if isinstance(item, dict) and '@Name' in item:
                                            key = item['@Name']
                                            value = item.get('#text', '')
                                            event_details[key] = value
                                elif isinstance(data_items, dict):
                                    if '@Name' in data_items:
                                        key = data_items['@Name']
                                        value = data_items.get('#text', '')
                                        event_details[key] = value
                        
                        # Get timestamp
                        time_created = system_data.get('TimeCreated', {})
                        timestamp = time_created.get('@SystemTime', datetime.utcnow().isoformat())
                        
                        # Build the document
                        document = {
                            '@timestamp': timestamp,
                            'event': {
                                'code': str(event_id),
                                'provider': system_data.get('Provider', {}).get('@Name', 'Unknown'),
                                'category': system_data.get('Channel', 'Unknown')
                            },
                            'host': {
                                'name': system_data.get('Computer', 'Unknown')
                            },
                            'winlog': {
                                'event_id': int(event_id) if str(event_id).isdigit() else 0,
                                'channel': system_data.get('Channel', 'Unknown'),
                                'computer_name': system_data.get('Computer', 'Unknown'),
                                'event_data': event_details,
                                'record_id': system_data.get('EventRecordID', 0)
                            }
                        }
                        
                        # Add Sigma-compatible fields from event data
                        # Common Sysmon/Windows fields
                        field_mappings = {
                            'Image': 'Image',
                            'CommandLine': 'CommandLine',
                            'ParentImage': 'ParentImage',
                            'ParentCommandLine': 'ParentCommandLine',
                            'User': 'User',
                            'TargetObject': 'TargetObject',
                            'Details': 'Details',
                            'QueryName': 'QueryName',
                            'DestinationIp': 'DestinationIp',
                            'DestinationPort': 'DestinationPort',
                            'SourceIp': 'SourceIp',
                            'SourcePort': 'SourcePort',
                            'OriginalFileName': 'OriginalFileName',
                            'ImageLoaded': 'ImageLoaded',
                            'TargetFilename': 'TargetFilename',
                            'ServiceName': 'ServiceName',
                            'ServiceFileName': 'ServiceFileName',
                            'ObjectName': 'ObjectName',
                            'TargetUserName': 'TargetUserName',
                            'SubjectUserName': 'SubjectUserName',
                            'ProcessName': 'ProcessName',
                            'WorkstationName': 'WorkstationName',
                            'IpAddress': 'IpAddress',
                            'AccountName': 'AccountName'
                        }
                        
                        for evtx_field, sigma_field in field_mappings.items():
                            if evtx_field in event_details:
                                document[sigma_field] = event_details[evtx_field]
                        
                        # Add EventID at root level for easier querying
                        document['EventID'] = int(event_id) if str(event_id).isdigit() else 0
                        
                        yield document
                        
                except Exception as e:
                    print(f"Error parsing record: {e}", file=sys.stderr)
                    continue
                    
    except Exception as e:
        print(f"Error opening EVTX file {evtx_file_path}: {e}", file=sys.stderr)


def convert_evtx_directory(input_dir, output_file, max_files=None):
    """
    Convert all EVTX files in a directory to OpenSearch bulk format.
    
    Args:
        input_dir: Directory containing EVTX files
        output_file: Output NDJSON file for bulk indexing
        max_files: Maximum number of EVTX files to process (None for all)
    """
    evtx_files = list(Path(input_dir).rglob('*.evtx'))
    
    if max_files:
        evtx_files = evtx_files[:max_files]
    
    print(f"Found {len(evtx_files)} EVTX files to process")
    
    total_events = 0
    processed_files = 0
    
    with open(output_file, 'w') as f:
        # Write the bulk POST header
        f.write('POST _bulk\n')
        
        for evtx_file in evtx_files:
            print(f"Processing: {evtx_file}")
            file_events = 0
            
            try:
                for event in parse_evtx_to_json(str(evtx_file)):
                    # Write the index action
                    index_action = {"index": {"_index": "evtx-attack-samples"}}
                    f.write(json.dumps(index_action) + '\n')
                    
                    # Write the document
                    f.write(json.dumps(event) + '\n')
                    
                    file_events += 1
                    total_events += 1
                
                processed_files += 1
                print(f"  → Extracted {file_events} events")
                
            except Exception as e:
                print(f"  → Error processing file: {e}", file=sys.stderr)
                continue
    
    print(f"\n✓ Successfully processed {processed_files}/{len(evtx_files)} files")
    print(f"✓ Total events extracted: {total_events}")
    print(f"✓ Output saved to: {output_file}")
    

if __name__ == "__main__":
    input_directory = "EVTX-ATTACK-SAMPLES"
    output_file = "evtx_attack_samples_bulk.ndjson"
    
    # Process first 20 EVTX files for testing (remove limit to process all)
    max_files = 20
    
    if not os.path.exists(input_directory):
        print(f"Error: Directory '{input_directory}' not found!", file=sys.stderr)
        sys.exit(1)
    
    print("=" * 60)
    print("EVTX to OpenSearch Converter")
    print("=" * 60)
    
    convert_evtx_directory(input_directory, output_file, max_files)
    
    print("\nNext steps:")
    print(f"1. Index to OpenSearch: tail -n +2 {output_file} | curl -X POST 'localhost:9200/_bulk' -H 'Content-Type: application/json' --data-binary @-")
    print(f"2. Verify: curl 'localhost:9200/evtx-attack-samples/_count'")
