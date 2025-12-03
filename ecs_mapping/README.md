# ECS Field Mapping

YAML-based Elastic Common Schema (ECS) field mapping for Sigma to OpenSearch PPL conversion.

## Overview

This pipeline automatically maps Sigma field names to ECS-compliant fields when converting rules to OpenSearch PPL queries. It uses the standard Sigma YAML pipeline format for simplicity and compatibility.

## Quick Start

```python
from sigma.collection import SigmaCollection
from sigma_backend.backends.opensearch_ppl.opensearch_ppl_textquery import OpenSearchPPLBackend
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

The pipeline includes 100+ field mappings across these categories:

| Category | Example Mappings |
|----------|------------------|
| **Process** | `CommandLine` → `process.command_line`<br>`Image` → `process.executable`<br>`ProcessId` → `process.pid` |
| **User** | `User` → `user.name`<br>`TargetUserName` → `user.target.name`<br>`LogonId` → `user.id` |
| **Network** | `DestinationIp` → `destination.ip`<br>`SourcePort` → `source.port`<br>`Protocol` → `network.protocol` |
| **File** | `TargetFilename` → `file.path`<br>`MD5` → `file.hash.md5`<br>`FileSize` → `file.size` |
| **Registry** | `TargetObject` → `registry.path`<br>`RegistryKey` → `registry.key` |
| **Host** | `ComputerName` → `host.name`<br>`IpAddress` → `host.ip` |
| **Event** | `EventID` → `event.code`<br>`Channel` → `winlog.channel` |

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
