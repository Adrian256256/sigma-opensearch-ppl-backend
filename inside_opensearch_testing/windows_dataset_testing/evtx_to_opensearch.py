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
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# OpenSearch configuration
OPENSEARCH_URL = "http://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "admin"


def create_index_with_mapping(index_name):
    """
    Create an OpenSearch index with proper mapping for timestamp and other fields.
    
    Args:
        index_name: Name of the index to create
    """
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {
                    "type": "date",
                    "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd HH:mm:ss.SSSSSSZ||yyyy-MM-dd HH:mm:ss.SSSSSSXXX"
                },
                "EventID": {
                    "type": "long"
                },
                "event": {
                    "properties": {
                        "code": {"type": "keyword"},
                        "provider": {"type": "keyword"},
                        "category": {"type": "keyword"}
                    }
                },
                "host": {
                    "properties": {
                        "name": {"type": "keyword"}
                    }
                },
                "Image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "CommandLine": {"type": "text"},
                "ParentImage": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "ParentCommandLine": {"type": "text"},
                "User": {"type": "keyword"},
                "DestinationIp": {"type": "ip"},
                "DestinationPort": {"type": "keyword"},
                "SourceIp": {"type": "ip"},
                "SourcePort": {"type": "keyword"}
            }
        }
    }
    
    try:
        # Check if index exists
        response = requests.head(
            f"{OPENSEARCH_URL}/{index_name}",
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            verify=False
        )
        
        if response.status_code == 200:
            print(f"Index '{index_name}' already exists. Deleting it...")
            # Delete existing index
            response = requests.delete(
                f"{OPENSEARCH_URL}/{index_name}",
                auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
                verify=False
            )
            if response.status_code not in [200, 404]:
                print(f"Warning: Could not delete index: {response.text}")
        
        # Create new index with mapping
        response = requests.put(
            f"{OPENSEARCH_URL}/{index_name}",
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            json=mapping,
            verify=False
        )
        
        if response.status_code == 200:
            print(f"✓ Index '{index_name}' created successfully with proper mapping")
            return True
        else:
            print(f"✗ Error creating index: {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ Error managing index: {e}")
        return False


def index_documents_to_opensearch(documents, index_name):
    """
    Index documents directly to OpenSearch using the bulk API.
    
    Args:
        documents: List of document dictionaries
        index_name: Name of the index
    """
    if not documents:
        return
    
    # Build bulk request body
    bulk_body = ""
    for doc in documents:
        # Index action
        bulk_body += json.dumps({"index": {"_index": index_name}}) + "\n"
        # Document
        bulk_body += json.dumps(doc) + "\n"
    
    try:
        response = requests.post(
            f"{OPENSEARCH_URL}/_bulk",
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/x-ndjson"},
            data=bulk_body,
            verify=False
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('errors'):
                print(f"✗ Some documents failed to index")
                # Print first error for debugging
                for item in result.get('items', []):
                    if 'error' in item.get('index', {}):
                        print(f"  Error: {item['index']['error']}")
                        break
            else:
                print(f"✓ Indexed {len(documents)} documents")
            return True
        else:
            print(f"✗ Bulk indexing failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ Error indexing documents: {e}")
        return False


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


def convert_evtx_directory(input_dir, index_name="evtx-attack-samples", max_files=None, batch_size=500):
    """
    Convert all EVTX files in a directory and index directly to OpenSearch.
    
    Args:
        input_dir: Directory containing EVTX files
        index_name: Name of the OpenSearch index
        max_files: Maximum number of EVTX files to process (None for all)
        batch_size: Number of documents to index in each batch
    """
    evtx_files = list(Path(input_dir).rglob('*.evtx'))
    
    if max_files:
        evtx_files = evtx_files[:max_files]
    
    print(f"Found {len(evtx_files)} EVTX files to process")
    
    # Create index with proper mapping
    if not create_index_with_mapping(index_name):
        print("Failed to create index. Exiting.")
        return
    
    total_events = 0
    processed_files = 0
    batch = []
    
    for evtx_file in evtx_files:
        print(f"Processing: {evtx_file}")
        file_events = 0
        
        try:
            for event in parse_evtx_to_json(str(evtx_file)):
                batch.append(event)
                file_events += 1
                total_events += 1
                
                # Index in batches
                if len(batch) >= batch_size:
                    index_documents_to_opensearch(batch, index_name)
                    batch = []
            
            processed_files += 1
            print(f"Extracted {file_events} events")
            
        except Exception as e:
            print(f"Error processing file: {e}", file=sys.stderr)
            continue
    
    # Index remaining documents
    if batch:
        index_documents_to_opensearch(batch, index_name)
    
    print(f"\nSuccessfully processed {processed_files}/{len(evtx_files)} files")
    print(f"Total events indexed: {total_events}")
    print(f"Index: {index_name}")
    

if __name__ == "__main__":
    input_directory = "EVTX-ATTACK-SAMPLES"
    index_name = "evtx-attack-samples"
    max_files = 20
    
    if not os.path.exists(input_directory):
        print(f"Error: Directory '{input_directory}' not found!", file=sys.stderr)
        sys.exit(1)
    
    print("EVTX to OpenSearch Converter")
    print("=" * 60)
    
    convert_evtx_directory(input_directory, index_name, max_files)

