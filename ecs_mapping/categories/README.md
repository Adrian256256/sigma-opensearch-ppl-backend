# ECS Field Mapping Categories

This directory contains the ECS (Elastic Common Schema) field mappings organized by category for the Sigma OpenSearch PPL backend.

## Directory Structure

### Base Fields (`base/`)
- **base_fields.yml** - Root-level event fields like timestamps, messages, and tags

### Process Fields (`process/`)
- **process_fields.yml** - Process execution and creation events
- **process_pe_fields.yml** - Windows Portable Executable metadata
- **process_hash_fields.yml** - Process file hashes

### Identity Fields (`identity/`)
- **user_fields.yml** - User information and authentication context
- **group_fields.yml** - Group membership information

### Network Fields (`network/`)
- **source_fields.yml** - Source side of network connections
- **destination_fields.yml** - Destination side of network connections
- **network_fields.yml** - General network communication details
- **dns_fields.yml** - DNS queries and answers
- **http_fields.yml** - HTTP request and response details
- **url_fields.yml** - URL components
- **user_agent_fields.yml** - Browser user agent information

### File Fields (`file/`)
- **file_fields.yml** - File operations and attributes
- **file_hash_fields.yml** - File hashes (MD5, SHA1, SHA256)
- **dll_fields.yml** - Dynamic Link Library information

### Registry Fields (`registry/`)
- **registry_fields.yml** - Windows Registry operations

### Host Fields (`host/`)
- **host_fields.yml** - Host/computer information

### Event Fields (`event/`)
- **event_fields.yml** - Event categorization and metadata
- **log_fields.yml** - Log-specific information

### Windows Fields (`windows/`)
Windows-specific event data:
- **winlog_fields.yml** - Windows Event Log fields
- **wmi_fields.yml** - Windows Management Instrumentation
- **image_load_fields.yml** - DLL/Image loading events (Sysmon EID 7)
- **driver_load_fields.yml** - Driver loading events (Sysmon EID 6)
- **create_remote_thread_fields.yml** - Remote thread creation (Sysmon EID 8)
- **raw_access_read_fields.yml** - Raw disk access (Sysmon EID 9)
- **process_access_fields.yml** - Process memory access (Sysmon EID 10)
- **pipe_fields.yml** - Named pipe events (Sysmon EID 17, 18)
- **clipboard_fields.yml** - Clipboard capture (Sysmon EID 24)
- **process_tampering_fields.yml** - Process tampering (Sysmon EID 25)
- **file_delete_fields.yml** - File deletion events (Sysmon EID 23, 26)
- **powershell_fields.yml** - PowerShell script logging
- **task_scheduler_fields.yml** - Windows Task Scheduler events
- **authentication_fields.yml** - Windows authentication events
- **certificate_fields.yml** - Certificate and code signing
- **account_management_fields.yml** - User/group account changes
- **sysmon_extended_fields.yml** - Additional Sysmon-specific fields
- **firewall_fields.yml** - Network firewall events

### Service Fields (`service/`)
- **service_fields.yml** - Service information

### Security Fields (`security/`)
- **rule_fields.yml** - Detection rule information
- **threat_fields.yml** - Threat intelligence information
- **related_fields.yml** - Fields for pivoting and correlation

### Web Fields (`web/`)
- **proxy_fields.yml** - Web proxy logs (W3C format)
- **webserver_fields.yml** - Web server access logs

### Cloud Fields (`cloud/`)
- **cloud_fields.yml** - Cloud provider events (AWS, Azure, GCP)
