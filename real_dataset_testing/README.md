# Testing Sigma Rules on EVTX-ATTACK-SAMPLES Dataset

This folder contains the **EVTX-ATTACK-SAMPLES** dataset that has been imported into local OpenSearch.
The dataset contains ~31,911 Windows events mapped to MITRE ATT&CK techniques.

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

**Results**: 334 matches ✓

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

**Results**: 1 match ✓

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

**Results**: 3 matches ✓

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

**Results**: 12 matches ✓

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

**Results**: 4 matches ✓

---

