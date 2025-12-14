# Sigma Correlation Rules Testing

> ** DISCLAIMER:** TODO: Correlation tests are currently not functional. The backend does not yet have an implementation for correlation rules. The refference OpenSearch PPL files are not correct, yet.

This directory contains Sigma correlation rules for testing and demonstrating advanced detection capabilities. The rules are organized according to official Sigma specifications available at [SigmaHQ Correlations Documentation](https://sigmahq.io/docs/meta/correlations.html).

## About Sigma Correlations

Sigma Correlations provide a standardized way to create more sophisticated detections that analyze relationships between events. Unlike traditional Sigma rules that detect individual events, correlation rules can identify complex patterns across multiple events occurring within a time window.

## Correlation Types

Sigma supports four main correlation types:

### 1. event_count
Counts events in the aggregation bucket. Useful for detecting event frequency within a given time frame.

Use cases:
- Brute force attacks (high number of failed authentications)
- DoS attacks (high number of connections)
- Log source reliability issues (low event count)

### 2. value_count
Counts distinct values of a given field. Useful for detecting high or low numbers of unique entities.

Use cases:
- Privileged group enumeration
- Network scanning (multiple destinations accessed)
- Password spraying (multiple accounts targeted)

### 3. temporal
Detects if multiple different event types occur close together in time. Order does not matter.

Use cases:
- Brute force followed by successful authentication
- Vulnerability exploitation (endpoint access + process creation)
- Lateral movement (remote service creation + process execution)

### 4. ordered_temporal
Similar to temporal, but also verifies event order. Used with caution due to complexity and clock synchronization issues.

Use cases:
- Scenarios where order is critical
- Exploitation chains with strict sequences

---

## Implemented Correlation Rules

### 1. Brute Force Detection (brute_force_detection.yml)

Type: event_count

Description: Detects brute force attacks by identifying a high number of failed authentication attempts for the same user within a short time period.

Parameters:
- Timespan: 5 minutes
- Condition: >= 10 events
- Group-by: TargetUserName, TargetDomainName

Detected cases:
- Brute force attacks on individual accounts
- Automated password guessing attempts
- Misconfigured systems generating repeated failed authentications

MITRE ATT&CK: T1110 (Brute Force)

Level: High

---

### 2. Privileged Group Enumeration (privileged_group_enumeration.yml)

Type: value_count

Description: Detects enumeration of multiple privileged Active Directory groups within a short time frame, characteristic of reconnaissance tools like BloodHound.

Parameters:
- Timespan: 15 minutes
- Condition: >= 4 distinct values for TargetUserName
- Group-by: SubjectUserName

Detected cases:
- BloodHound scans with default options
- Automated AD enumeration
- Post-compromise reconnaissance activities

MITRE ATT&CK: T1087 (Account Discovery)

Level: High

---

### 3. Successful Brute Force (successful_brute_force.yml)

Type: temporal

Description: Detects successful brute force attacks by correlating failed authentication attempts with successful logins from the same source IP for the same user.

Parameters:
- Timespan: 10 minutes
- Group-by: IpAddress, TargetUserName
- Rules: win_failed_logon + win_successful_logon

Detected cases:
- Brute force attacks that successfully guess the password
- Account compromise after multiple attempts
- High-priority indicators for investigation

MITRE ATT&CK: T1110 (Brute Force)

Level: Critical

---

### 4. Lateral Movement Detection (lateral_movement_detection.yml)

Type: temporal

Description: Detects lateral movement in the network by correlating remote service creation with suspicious process execution (cmd.exe, powershell.exe, wmic.exe).

Parameters:
- Timespan: 2 minutes
- Group-by: ComputerName
- Rules: remote_service_creation + remote_process_creation

Detected cases:
- Lateral movement via PsExec
- Remote execution through Windows service creation
- Malware propagation techniques in the network

MITRE ATT&CK: T1021 (Remote Services), T1569 (System Services)

Level: High

---

### 5. Password Spraying (password_spraying.yml)

Type: value_count

Description: Detects password spraying attacks by identifying failed authentication attempts on multiple different accounts from the same source IP.

Parameters:
- Timespan: 30 minutes
- Condition: >= 10 distinct users
- Group-by: IpAddress

Detected cases:
- Password spraying attacks (common password on many accounts)
- Large-scale compromise attempts
- Testing of stolen credentials

MITRE ATT&CK: T1110.003 (Password Spraying)

Level: High

---

### 6. Account Manipulation (account_manipulation.yml)

Type: ordered_temporal

Description: Detects rapid creation of a user account followed by adding it to a privileged group. Uses field aliases to correlate TargetUserName with MemberName.

Parameters:
- Timespan: 5 minutes
- Group-by: user (alias)
- Rules: user_account_created -> user_added_to_group (strict order)
- Aliases: user = {TargetUserName, MemberName}

Detected cases:
- Backdoor account creation
- Rapid privilege escalation
- Malicious persistence activities

MITRE ATT&CK: T1136 (Create Account), T1098 (Account Manipulation)

Level: Critical

---

### 7. Suspicious Network Connection (suspicious_network_connection.yml)

Type: temporal with field aliases

Description: Correlates suspicious process execution (powershell, cmd, scripts) with network connections to ports commonly used for C2 (Command and Control).

Parameters:
- Timespan: 60 seconds
- Group-by: process (ProcessId), ComputerName
- Rules: suspicious_process + suspicious_network_connection
- Aliases: process = ProcessId

Detected cases:
- Reverse shells
- C2 beacons (Cobalt Strike, Metasploit)
- Malware communications with command servers

MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol)

Level: High

---

### 8. Data Exfiltration (data_exfiltration.yml)

Type: temporal

Description: Detects potential data exfiltration by correlating access to sensitive files with large network data transfers (>10 MB).

Parameters:
- Timespan: 10 minutes
- Group-by: User, ComputerName
- Rules: sensitive_file_access + large_data_transfer

Detected cases:
- Confidential document exfiltration
- Unauthorized data transfers
- Intellectual property theft

MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)

Level: High

---

## File Structure

```
correlation_testing/
├── README.md                          # This file
├── sigma_rules/                       # Sigma correlation rules
│   ├── brute_force_detection.yml
│   ├── privileged_group_enumeration.yml
│   ├── successful_brute_force.yml
│   ├── lateral_movement_detection.yml
│   ├── password_spraying.yml
│   ├── account_manipulation.yml
│   ├── suspicious_network_connection.yml
│   └── data_exfiltration.yml
└── ppl_refs/                          # Generated PPL references
```

## Key Concepts

### Base Rules and Correlation Rules

Each correlation file contains:
1. Base rule(s) - normal Sigma rules with detection section that detect individual events
2. Correlation rule - the rule that correlates events detected by base rules

Rules are separated by `---` in the same YAML file.

### Field Aliases

Field aliases allow correlating fields with different names across log sources:

```yaml
aliases:
  ip:
    rule_with_src_ip: src_ip
    rule_with_dest_ip: dest_ip
group-by:
  - ip
```

### Generate Flag

By default, correlation rules omit the base rule from the final query. To retain it, add:

```yaml
correlation:
  generate: true
```
