# Testing Sigma Rules on EVTX-ATTACK-SAMPLES Dataset

This folder contains the **EVTX-ATTACK-SAMPLES** dataset that has been imported into local OpenSearch.
The dataset contains ~31,911 Windows events mapped to MITRE ATT&CK techniques.

## evtx_to_opensearch.py

Python script that converts Windows Event Log files (EVTX) to OpenSearch bulk-ready NDJSON format.

**Step-by-step process:**

1. **EVTX File Discovery**
   - Recursively scans the `EVTX-ATTACK-SAMPLES` directory for all `.evtx` files
   - Limits processing to first 20 files by default (configurable via `max_files` parameter)

2. **Binary EVTX Parsing**
   - Opens each EVTX file using `python-evtx` library
   - Iterates through binary event records in the EVTX file format
   - Extracts raw XML representation of each Windows event

3. **XML to Dictionary Conversion**
   - Converts XML event string to Python dictionary using `xmltodict`
   - Preserves the hierarchical structure: `Event -> System` and `Event -> EventData`

4. **System Data Extraction**
   - Extracts core event metadata from the `System` node:
     - `EventID`: The Windows event identifier (e.g., 4624 for logon, 1 for Sysmon process creation)
     - `TimeCreated/@SystemTime`: Event timestamp in ISO 8601 format
     - `Provider/@Name`: Event source (e.g., Microsoft-Windows-Sysmon, Security)
     - `Channel`: Log channel (e.g., Microsoft-Windows-Sysmon/Operational, Security)
     - `Computer`: Hostname where the event was generated
     - `EventRecordID`: Unique record identifier in the log file

5. **EventData Field Parsing**
   - Processes the `EventData` node containing event-specific details
   - Handles both single and multiple `Data` elements
   - Extracts key-value pairs where `@Name` is the field name and `#text` is the value
   - Example: `<Data Name="CommandLine">powershell.exe -enc ...</Data>` -> `{"CommandLine": "powershell.exe -enc ..."}`

6. **Sigma Field Mapping**
   - Maps common Windows/Sysmon fields to root-level document fields for Sigma rule compatibility:
     - `Image`: Process executable path (e.g., `C:\Windows\System32\cmd.exe`)
     - `CommandLine`: Full command line with arguments
     - `ParentImage`: Parent process executable path
     - `ParentCommandLine`: Parent process command line
     - `User`: Account that executed the process
     - `TargetObject`: Registry key or file path (for Sysmon events)
     - `Details`: Registry value details
     - `QueryName`: DNS query name (Sysmon Event ID 22)
     - `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`: Network connection details
     - `OriginalFileName`, `ImageLoaded`, `TargetFilename`: File operation fields
     - `ServiceName`, `ServiceFileName`: Service-related fields
     - `TargetUserName`, `SubjectUserName`, `AccountName`: User account fields
     - `WorkstationName`, `IpAddress`: Logon/authentication fields

7. **Document Structure Creation**
   - Builds an ECS-compatible JSON document with the following structure:
     ```json
     {
       "@timestamp": "2024-01-15T10:30:45.123Z",
       "EventID": 1,
       "event": {
         "code": "1",
         "provider": "Microsoft-Windows-Sysmon",
         "category": "Microsoft-Windows-Sysmon/Operational"
       },
       "host": {
         "name": "DESKTOP-ABC123"
       },
       "winlog": {
         "event_id": 1,
         "channel": "Microsoft-Windows-Sysmon/Operational",
         "computer_name": "DESKTOP-ABC123",
         "event_data": { "CommandLine": "...", "Image": "..." },
         "record_id": 12345
       },
       "CommandLine": "powershell.exe -enc ...",
       "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
       "ParentImage": "C:\\Windows\\System32\\cmd.exe"
     }
     ```

8. **Bulk NDJSON Generation**
   - Creates `evtx_attack_samples_bulk.ndjson` with OpenSearch bulk API format
   - Each event generates **two lines**:
     - Line 1: Index action → `{"index": {"_index": "evtx-attack-samples"}}`
     - Line 2: Document JSON → the complete event document
   - First line of file contains `POST _bulk` header (removed during import)

## Dataset Import/Re-import Commands

To delete the existing index and re-import the dataset into OpenSearch:

```bash
# Navigate to the real_dataset_testing folder
cd real_dataset_testing

# Delete the existing index
curl -X DELETE "localhost:9200/evtx-attack-samples"

# Re-import the dataset (removes the first line "POST _bulk" and imports clean data)
tail -n +2 evtx_attack_samples_bulk.ndjson | curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-

# Verify the import
curl -X GET "localhost:9200/evtx-attack-samples/_count" | jq '.'
```

## Tested and Validated Sigma Rules

The following official Sigma rules from `ecs_fields_info/sigma-master` return results when queried against this dataset:

### 1. PowerShell Token Obfuscation Detection

**Rule File**: `ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_powershell_token_obfuscation.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_powershell_token_obfuscation.yml
```

**Generated PPL Query**:
```ppl
source=evtx-attack-samples | where (match(CommandLine, '\w+`(\w+|-|.)`[\w+|\s]') OR match(CommandLine, '"(\{\d\})+"\s*-f') OR match(CommandLine, '(?i)\$\{`?e`?n`?v`?:`?p`?a`?t`?h`?\}')) AND NOT LIKE(CommandLine, "%${env:path}%")
```

---

### 2. CertUtil Download Detection

**Rule File**: `ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_certutil_download.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_certutil_download.yml
```

**Generated PPL Query**:
```ppl
source=evtx-attack-samples | where (LIKE(Image, "%\\certutil.exe") OR OriginalFileName="CertUtil.exe") AND (LIKE(CommandLine, "%urlcache %") OR LIKE(CommandLine, "%verifyctl %") OR LIKE(CommandLine, "%URL %")) AND LIKE(CommandLine, "%http%")
```

---

### 3. BITSAdmin Download Detection

**Rule File**: `ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml
```

**Generated PPL Query**:
```ppl
source=evtx-attack-samples | where (LIKE(Image, "%\\bitsadmin.exe") OR OriginalFileName="bitsadmin.exe") AND (LIKE(CommandLine, "% /transfer %") OR (LIKE(CommandLine, "% /create %") OR LIKE(CommandLine, "% /addfile %")) AND LIKE(CommandLine, "%http%"))
```

---

### 4. Calculator From Uncommon Location

**Rule File**: `ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_calc_uncommon_exec.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_calc_uncommon_exec.yml
```

**Generated PPL Query**:
```ppl
source=evtx-attack-samples | where LIKE(CommandLine, "%\\calc.exe %") OR LIKE(Image, "%\\calc.exe") AND NOT (LIKE(Image, "%:\\Windows\\System32\\%") OR LIKE(Image, "%:\\Windows\\SysWOW64\\%") OR LIKE(Image, "%:\\Windows\\WinSxS\\%"))
```

---

### 5. Suspicious MSHTA Execution Pattern

**Rule File**: `ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.yml
```

**Generated PPL Query**:
```ppl
source=evtx-attack-samples | where (LIKE(Image, "%\\mshta.exe") OR OriginalFileName="MSHTA.EXE") AND (LIKE(ParentImage, "%\\cmd.exe") OR LIKE(ParentImage, "%\\cscript.exe") OR LIKE(ParentImage, "%\\powershell.exe") OR LIKE(ParentImage, "%\\pwsh.exe") OR LIKE(ParentImage, "%\\regsvr32.exe") OR LIKE(ParentImage, "%\\rundll32.exe") OR LIKE(ParentImage, "%\\wscript.exe")) AND (LIKE(CommandLine, "%\\AppData\\Local\\%") OR LIKE(CommandLine, "%C:\\ProgramData\\%") OR LIKE(CommandLine, "%C:\\Users\\Public\\%") OR LIKE(CommandLine, "%C:\\Windows\\Temp\\%")) OR (LIKE(Image, "%\\mshta.exe") OR OriginalFileName="MSHTA.EXE") AND NOT (LIKE(Image, "C:\\Windows\\System32\\%") OR LIKE(Image, "C:\\Windows\\SysWOW64\\%") OR LIKE(CommandLine, "%.htm%") OR LIKE(CommandLine, "%.hta%") OR LIKE(CommandLine, "%mshta.exe") OR LIKE(CommandLine, "%mshta"))
```

---

