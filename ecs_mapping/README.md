# ECS Field Mapping

YAML-based Elastic Common Schema (ECS) field mapping for Sigma to OpenSearch PPL conversion.

## Overview

This pipeline automatically maps Sigma field names to ECS-compliant fields when converting rules to OpenSearch PPL queries. It uses the standard Sigma YAML pipeline format for simplicity and compatibility.

## Quick Start

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
from ecs_mapping import load_ecs_pipeline_from_yaml

# Load ECS pipeline
pipeline = load_ecs_pipeline_from_yaml()

# Use with backend
backend = OpenSearchPPLBackend(processing_pipeline=pipeline)
collection = SigmaCollection.from_yaml(rule_yaml)
ppl_query = backend.convert(collection)
```

## Example

**Sigma Rule:**
```yaml
detection:
    selection:
        CommandLine|contains: 'powershell'
        User: Administrator
```

**Without ECS:**
```ppl
source=windows-* | where LIKE(CommandLine, "%powershell%") AND User="Administrator"
```

**With ECS:**
```ppl
source=windows-* | where LIKE(process.command_line, "%powershell%") AND user.name="Administrator"
```

## Field Mappings

The pipeline includes **250+ field mappings** across **45 categories** aligned with:
- **Elastic Common Schema (ECS) 9.2.0**
- **Sigma Taxonomy Specification v2.1.0**
- **Windows Sysmon Events** (EID 1-29)
- **Windows Security Events** (Authentication, Account Management)
- **PowerShell Script Logging**
- **Cloud Provider Events** (AWS, Azure, GCP)

### Core Field Categories

| Category | Example Mappings | Coverage |
|----------|------------------|----------|
| **Base Fields** | `UtcTime` - `@timestamp`<br>`Message` - `message`<br>`Tags` - `tags` | Timestamps, metadata |
| **Process** | `CommandLine` - `process.command_line`<br>`Image` - `process.executable`<br>`ProcessId` - `process.pid`<br>`ParentUser` - `process.parent.user.name` | Process creation, parent processes |
| **Process PE** | `OriginalFileName` - `process.pe.original_file_name`<br>`Company` - `process.pe.company`<br>`Imphash` - `process.pe.imphash` | Windows PE metadata |
| **Process Hash** | `Hashes` - `related.hash`<br>`MD5` - `process.hash.md5`<br>`SHA256` - `process.hash.sha256` | File hashes (MD5, SHA1, SHA256) |
| **User** | `User` - `user.name`<br>`TargetUserName` - `user.target.name`<br>`SubjectLogonId` - `winlog.event_data.SubjectLogonId` | Subject and target users |
| **Group** | `GroupName` - `group.name`<br>`TargetGroupSid` - `group.id` | Group information |
| **Network** | `DestinationIp` - `destination.ip`<br>`SourcePort` - `source.port`<br>`Protocol` - `network.protocol`<br>`Initiated` - `network.direction` | Network connections |
| **DNS** | `QueryName` - `dns.question.name`<br>`QueryStatus` - `dns.response_code`<br>`QueryResults` - `dns.answers.data` | DNS queries (Sysmon EID 22) |
| **HTTP** | `cs-method` - `http.request.method`<br>`sc-status` - `http.response.status_code` | HTTP requests/responses |
| **File** | `TargetFilename` - `file.path`<br>`MD5` - `file.hash.md5`<br>`FileSize` - `file.size`<br>`CreationUtcTime` - `file.created` | File operations (Sysmon EID 11, 23, 26) |
| **Registry** | `TargetObject` - `registry.path`<br>`RegistryKey` - `registry.key`<br>`EventType` - `registry.action` | Registry events (Sysmon EID 12-14) |
| **Host** | `ComputerName` - `host.name`<br>`IpAddress` - `host.ip`<br>`WorkstationName` - `host.name` | Host/system information |
| **Event** | `EventID` - `event.code`<br>`EventType` - `event.type`<br>`Action` - `event.action` | Event metadata |
| **WinLog** | `Channel` - `winlog.channel`<br>`LogonType` - `winlog.event_data.LogonType`<br>`Provider_Name` - `winlog.provider_name` | Windows Event Log fields |
| **Service** | `ServiceName` - `service.name`<br>`ServiceFileName` - `service.executable` | Windows services |

### Advanced Sysmon Event Coverage

| Event Type | Sysmon EID | Key Mappings |
|------------|------------|--------------|
| **Image Load** | 7 | `ImageLoaded` - `file.path`<br>`Signed` - `file.code_signature.signed` |
| **Driver Load** | 6 | `ImageLoaded` - `driver.name`<br>`SignatureStatus` - `file.code_signature.status` |
| **Create Remote Thread** | 8 | `SourceImage` - `process.executable`<br>`TargetImage` - `process.target.executable`<br>`StartAddress` - `winlog.event_data.StartAddress` |
| **Raw Access Read** | 9 | `Device` - `file.device` |
| **Process Access** | 10 | `GrantedAccess` - `winlog.event_data.GrantedAccess`<br>`CallTrace` - `winlog.event_data.CallTrace` |
| **Pipe Created** | 17, 18 | `PipeName` - `file.name` |
| **WMI Events** | 19, 20, 21 | `EventNamespace` - `winlog.event_data.EventNamespace`<br>`Query` - `winlog.event_data.Query`<br>`Consumer` - `winlog.event_data.Consumer` |
| **Clipboard Capture** | 24 | `ClientInfo` - `winlog.event_data.ClientInfo` |
| **Process Tampering** | 25 | `Type` - `event.action` |

### Windows Security & PowerShell

| Category | Key Mappings |
|----------|--------------|
| **Authentication** | `LogonType` - `winlog.event_data.LogonType`<br>`AuthenticationPackageName` - `winlog.event_data.AuthenticationPackageName`<br>`IpAddress` - `source.ip`<br>`WorkstationName` - `source.domain` |
| **PowerShell** | `ScriptBlockText` - `powershell.file.script_block_text`<br>`ScriptBlockId` - `powershell.file.script_block_id`<br>`HostApplication` - `process.command_line` |
| **Task Scheduler** | `TaskName` - `winlog.event_data.TaskName`<br>`TaskContent` - `winlog.event_data.TaskContent` |
| **Account Management** | `SamAccountName` - `user.target.name`<br>`PrivilegeList` - `winlog.event_data.PrivilegeList` |

### Network & Web

| Category | Key Mappings |
|----------|--------------|
| **Firewall** | `RuleName` - `rule.name`<br>`Direction` - `network.direction` |
| **Proxy** | `c-uri` - `url.full`<br>`c-useragent` - `user_agent.original`<br>`cs-cookie` - `http.request.cookies` |
| **Webserver** | `c-ip` - `source.ip`<br>`s-sitename` - `service.name`<br>`time-taken` - `event.duration` |

### Cloud Provider Events

| Provider | Key Mappings |
|----------|--------------|
| **AWS CloudTrail** | `eventName` - `event.action`<br>`eventSource` - `event.provider`<br>`awsRegion` - `cloud.region` |
| **Azure** | `operationName` - `event.action`<br>`resourceId` - `cloud.instance.id` |
| **GCP** | `protoPayload.methodName` - `event.action`<br>`resource.type` - `cloud.service.name` |

## Customization

Edit `ecs_mapping.yml` to add or modify mappings:

```yaml
transformations:
  - id: custom_mapping
    type: field_name_mapping
    mapping:
      MyField: my.ecs.field
      AnotherField: another.ecs.field
```

## Using with Sigma CLI

```bash
sigma convert -t opensearch-ppl -p ecs_mapping/ecs_mapping.yml rule.yml
```

## API Reference

### `load_ecs_pipeline_from_yaml(yaml_path=None)`

Load ECS pipeline from YAML file.

**Parameters:**
- `yaml_path` (str, optional): Path to YAML file. If None, uses default `ecs_mapping.yml`

**Returns:** `ProcessingPipeline`

### `create_ecs_pipeline_from_yaml(yaml_path=None)`

Alias for `load_ecs_pipeline_from_yaml`.

## References

- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Sigma Pipelines Documentation](https://sigmahq.io/docs/digging-deeper/pipelines.html)
- [pySigma](https://github.com/SigmaHQ/pySigma)
