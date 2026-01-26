# Log Generator

Python script for generating synthetic security logs to test Sigma rules in OpenSearch.

## How It Works

This script generates realistic Windows security event logs by simulating various system activities:

1. **Creates base log structure** - Each log includes standard fields like timestamp, hostname, Windows event metadata (Sysmon)
2. **Generates malicious events** - Simulates common attack patterns with authentic field names from Sigma rules (Image, CommandLine, QueryName, etc.)
3. **Adds benign events** - Creates normal system activity to provide realistic background noise
4. **Outputs in bulk format** - Produces NDJSON file ready for direct import into OpenSearch

The generated logs use **Sigma original field names** (Image, CommandLine, QueryName) ensuring direct compatibility with PPL queries converted by `sigma-ppl`.

## Usage

```bash
# Generate 500 logs (30% malicious) - default
python3 generate_logs.py

# Generate custom number of logs
python3 generate_logs.py --count 1000

# Change malicious ratio
python3 generate_logs.py --count 500 --malicious-ratio 0.2

# Custom output file
python3 generate_logs.py --output my_logs.ndjson
```

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--count` / `-c` | `500` | Number of logs to generate |
| `--malicious-ratio` / `-r` | `0.3` | Ratio of malicious logs (0.0-1.0) |
| `--output` / `-o` | `bulk_ready.ndjson` | Output file path |

## Generated Log Types

**Malicious logs** (match Sigma rules):
- Calculator execution
- Suspicious DNS queries (.tk, .ml, .ga, .gq domains)
- Mimikatz execution
- Suspicious PowerShell commands
- PsExec lateral movement
- Suspicious network connections
- Registry modifications (Run keys)
- Scheduled task creation

**Benign logs** (baseline traffic):
- Normal process execution (Chrome, Notepad, Word)
- Legitimate DNS queries

## Indexing in OpenSearch

### Using OpenSearch Dashboard

**Step 1: Generate logs**

```bash
python3 generate_logs.py --count 500
```

**Step 2: Index via Dashboard**

1. Open OpenSearch Dashboard at `http://localhost:5601`
2. Navigate to **Dev Tools** in the left sidebar
3. Open `bulk_ready.ndjson` and **copy all contents** (including the `POST _bulk` line at the top)
4. Paste into the Console
5. Click the play button (▶) to execute

The file already contains the `POST _bulk` command, so you can copy-paste directly without modifications.

### Using curl

```bash
curl -X POST "localhost:9200/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary "@bulk_ready.ndjson"
```

### Delete Old Index (Optional)

If you want to replace the old logs with new ones, delete the existing index first:

**Using OpenSearch Dashboard Dev Tools:**

```json
DELETE security-logs
```

**Using curl:**

```bash
curl -X DELETE "localhost:9200/security-logs"
```

After deleting, you can re-index with the new logs using the steps above.

### Verify Indexing

In OpenSearch Dashboard Dev Tools:

```json
GET security-logs/_count
```

Expected result: `{"count": 500}` (or your specified count)

## Querying with PPL

### How to run PPL queries in Dashboard

1. Open **Dev Tools** from the left sidebar
2. Select **Query Workbench** tab (at the top)
3. Change the language dropdown from **SQL** to **PPL**
4. Write your PPL query and click **Run** (▶)

### Example PPL Queries

**Count all logs:**
```ppl
search source=security-logs | stats count()
```

**View first 10 logs:**
```ppl
search source=security-logs | head 10
```

**Count by event category:**
```ppl
search source=security-logs | stats count() by event.category
```

**Find malicious logs:**
```ppl
search source=security-logs 
| where process.executable like '%calc.exe%' 
   OR dns.question.name like '%.tk' 
   OR process.name like '%mimikatz%'
| stats count()
```

**View specific fields:**
```ppl
search source=security-logs 
| fields @timestamp, host.name, process.name, process.executable
| head 20
```
