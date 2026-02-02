#!/usr/bin/env python3
"""
Convert Apache HTTP access logs to OpenSearch bulk-ready NDJSON format.
Processes Apache access logs and converts them to ECS-compatible JSON documents
that can be indexed into OpenSearch, with attack pattern detection.
"""

import json
import sys
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs


# Apache Combined Log Format regex
# Format: IP - - [timestamp] "METHOD /path HTTP/version" status bytes "referer" "user-agent"
APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<url>[^\s]+) HTTP/(?P<http_version>[\d\.]+)" '
    r'(?P<status>\d+) (?P<bytes>[\d\-]+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

# Attack pattern detection
XSS_PATTERNS = [
    r'<script[^>]*>',
    r'javascript:',
    r'onerror\s*=',
    r'onload\s*=',
    r'<img[^>]+src',
    r'<iframe',
    r'alert\(',
    r'document\.cookie',
    r'eval\(',
]

SQLI_PATTERNS = [
    r"'\s*OR\s*'",
    r"'\s*OR\s*1\s*=\s*1",
    r'UNION\s+SELECT',
    r'DROP\s+TABLE',
    r';\s*DROP',
    r'--\s*$',
    r'xp_cmdshell',
    r'exec\s*\(',
    r'EXEC\s+',
    r'information_schema',
]

PATH_TRAVERSAL_PATTERNS = [
    r'\.\.[/\\]',
    r'%2e%2e[/\\]',
    r'\.\.%2f',
]

COMMAND_INJECTION_PATTERNS = [
    r';\s*\w+',
    r'\|\s*\w+',
    r'&&\s*\w+',
    r'`[^`]+`',
    r'\$\([^)]+\)',
]

SCANNER_USER_AGENTS = [
    'nikto',
    'sqlmap',
    'nmap',
    'masscan',
    'nessus',
    'acunetix',
    'burp',
    'metasploit',
    'w3af',
    'dirbuster',
    'gobuster',
    'wpscan',
    'havij',
]


def parse_apache_timestamp(timestamp_str):
    """
    Parse Apache log timestamp to ISO 8601 format.
    Apache format: 15/Mar/2018:10:30:45 +0000
    """
    try:
        # Remove timezone for simplicity
        timestamp_str = timestamp_str.split()[0]
        dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
        return dt.isoformat() + 'Z'
    except Exception as e:
        print(f"Error parsing timestamp '{timestamp_str}': {e}", file=sys.stderr)
        return datetime.utcnow().isoformat() + 'Z'


def detect_attacks(url, user_agent):
    """
    Detect attack patterns in URL and user agent.
    
    Returns:
        dict: Attack detection results with types and indicators
    """
    attacks = {
        'detected': False,
        'types': [],
        'indicators': []
    }
    
    url_lower = url.lower()
    user_agent_lower = user_agent.lower()
    
    # XSS detection
    for pattern in XSS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            if 'xss' not in attacks['types']:
                attacks['types'].append('xss')
            attacks['indicators'].append(f"XSS pattern: {pattern}")
            attacks['detected'] = True
    
    # SQL Injection detection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            if 'sqli' not in attacks['types']:
                attacks['types'].append('sqli')
            attacks['indicators'].append(f"SQLI pattern: {pattern}")
            attacks['detected'] = True
    
    # Path Traversal detection
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            if 'path_traversal' not in attacks['types']:
                attacks['types'].append('path_traversal')
            attacks['indicators'].append(f"Path traversal: {pattern}")
            attacks['detected'] = True
    
    # Command Injection detection
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            if 'command_injection' not in attacks['types']:
                attacks['types'].append('command_injection')
            attacks['indicators'].append(f"Command injection: {pattern}")
            attacks['detected'] = True
    
    # Scanner detection
    for scanner in SCANNER_USER_AGENTS:
        if scanner in user_agent_lower:
            if 'vulnerability_scan' not in attacks['types']:
                attacks['types'].append('vulnerability_scan')
            attacks['indicators'].append(f"Scanner: {scanner}")
            attacks['detected'] = True
    
    return attacks


def parse_apache_log_line(line):
    """
    Parse a single Apache log line and convert to ECS-compatible document.
    
    Args:
        line: Apache log line string
        
    Returns:
        dict: ECS-compatible document or None if parsing fails
    """
    # Remove surrounding quotes if present
    line = line.strip()
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1]
    
    match = APACHE_LOG_PATTERN.match(line.strip())
    if not match:
        return None
    
    data = match.groupdict()
    
    # Parse URL components
    url = data['url']
    parsed_url = urlparse(url)
    url_path = parsed_url.path
    query_string = parsed_url.query
    
    # Parse timestamp
    timestamp = parse_apache_timestamp(data['timestamp'])
    
    # Detect attacks
    attacks = detect_attacks(url, data['user_agent'])
    
    # Build ECS-compatible document
    document = {
        '@timestamp': timestamp,
        'source': {
            'ip': data['ip']
        },
        'http': {
            'request': {
                'method': data['method'],
                'referrer': data['referer'] if data['referer'] != '-' else None
            },
            'response': {
                'status_code': int(data['status']),
                'bytes': int(data['bytes']) if data['bytes'] != '-' else 0
            },
            'version': data['http_version']
        },
        'url': {
            'original': url,
            'path': url_path,
            'query': query_string if query_string else None
        },
        'user_agent': {
            'original': data['user_agent']
        },
        'event': {
            'category': 'web',
            'type': 'access',
            'kind': 'alert' if attacks['detected'] else 'event'
        }
    }
    
    # Add attack detection results
    if attacks['detected']:
        document['attack'] = attacks
    
    # Add Sigma-compatible web proxy fields
    document['cs-uri-query'] = query_string if query_string else ''
    document['cs-uri-stem'] = url_path
    document['cs-method'] = data['method']
    document['c-ip'] = data['ip']
    document['sc-status'] = int(data['status'])
    document['cs-User-Agent'] = data['user_agent']
    document['cs-Referer'] = data['referer'] if data['referer'] != '-' else ''
    
    return document


def convert_apache_logs(input_file, output_file):
    """
    Convert Apache access log file to OpenSearch bulk format.
    
    Args:
        input_file: Path to Apache access log file
        output_file: Output NDJSON file for bulk indexing
    """
    total_logs = 0
    parsed_logs = 0
    attacks_detected = {
        'xss': 0,
        'sqli': 0,
        'path_traversal': 0,
        'command_injection': 0,
        'vulnerability_scan': 0
    }
    
    print(f"Processing: {input_file}")
    
    with open(output_file, 'w') as out_f:
        # Write the bulk POST header
        out_f.write('POST _bulk\n')
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as in_f:
            for line in in_f:
                total_logs += 1
                
                try:
                    document = parse_apache_log_line(line)
                    if document:
                        # Write the index action
                        index_action = {"index": {"_index": "apache-http-logs"}}
                        out_f.write(json.dumps(index_action) + '\n')
                        
                        # Write the document
                        out_f.write(json.dumps(document) + '\n')
                        
                        parsed_logs += 1
                        
                        # Count attacks by type
                        if 'attack' in document:
                            for attack_type in document['attack']['types']:
                                if attack_type in attacks_detected:
                                    attacks_detected[attack_type] += 1
                        
                except Exception as e:
                    print(f"Error parsing line: {e}", file=sys.stderr)
                    continue
    
    print(f"\n✓ Total log lines: {total_logs}")
    print(f"✓ Successfully parsed: {parsed_logs}")
    print(f"✓ Failed to parse: {total_logs - parsed_logs}")
    
    print(f"\nAttacks detected:")
    total_attacks = sum(attacks_detected.values())
    print(f"  Total attacks: {total_attacks}")
    for attack_type, count in attacks_detected.items():
        if count > 0:
            print(f"  - {attack_type}: {count}")
    
    print(f"\n✓ Output saved to: {output_file}")


def process_directory(input_dir, output_file):
    """
    Process all log files in a directory and combine into single output.
    
    Args:
        input_dir: Directory containing Apache log files
        output_file: Output NDJSON file
    """
    log_files = list(Path(input_dir).rglob('*.log')) + \
                list(Path(input_dir).rglob('access.log*')) + \
                list(Path(input_dir).rglob('*.txt'))
    
    if not log_files:
        print(f"No log files found in {input_dir}")
        return
    
    print(f"Found {len(log_files)} log file(s) to process")
    
    total_logs = 0
    parsed_logs = 0
    attacks_detected = {
        'xss': 0,
        'sqli': 0,
        'path_traversal': 0,
        'command_injection': 0,
        'vulnerability_scan': 0
    }
    
    with open(output_file, 'w') as out_f:
        # Write the bulk POST header
        out_f.write('POST _bulk\n')
        
        for log_file in log_files:
            print(f"\nProcessing: {log_file}")
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as in_f:
                for line in in_f:
                    total_logs += 1
                    
                    try:
                        document = parse_apache_log_line(line)
                        if document:
                            # Write the index action
                            index_action = {"index": {"_index": "apache-http-logs"}}
                            out_f.write(json.dumps(index_action) + '\n')
                            
                            # Write the document
                            out_f.write(json.dumps(document) + '\n')
                            
                            parsed_logs += 1
                            
                            # Count attacks by type
                            if 'attack' in document:
                                for attack_type in document['attack']['types']:
                                    if attack_type in attacks_detected:
                                        attacks_detected[attack_type] += 1
                            
                    except Exception as e:
                        print(f"Error parsing line: {e}", file=sys.stderr)
                        continue
    
    print(f"\n" + "=" * 60)
    print(f"✓ Total log lines processed: {total_logs}")
    print(f"✓ Successfully parsed: {parsed_logs}")
    print(f"✓ Failed to parse: {total_logs - parsed_logs}")
    
    print(f"\n📊 Attacks detected:")
    total_attacks = sum(attacks_detected.values())
    print(f"  Total attacks: {total_attacks}")
    for attack_type, count in attacks_detected.items():
        if count > 0:
            print(f"  - {attack_type}: {count}")
    
    print(f"\n✓ Output saved to: {output_file}")


if __name__ == "__main__":
    input_directory = "apache-http-logs"
    output_file = "apache_http_logs_bulk.ndjson"
    
    if not os.path.exists(input_directory):
        print(f"Error: Directory '{input_directory}' not found!", file=sys.stderr)
        print(f"\nPlease clone the dataset first:", file=sys.stderr)
        print(f"  git clone https://github.com/ocatak/apache-http-logs.git", file=sys.stderr)
        sys.exit(1)
    
    print("=" * 60)
    print("Apache HTTP Logs to OpenSearch Converter")
    print("=" * 60)
    
    process_directory(input_directory, output_file)
    
    print("\nNext steps:")
    print(f"1. Index to OpenSearch: tail -n +2 {output_file} | curl -X POST 'localhost:9200/_bulk' -H 'Content-Type: application/x-ndjson' --data-binary @-")
    print(f"2. Verify: curl 'localhost:9200/apache-http-logs/_count'")
