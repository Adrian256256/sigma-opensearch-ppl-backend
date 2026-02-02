# Testing Sigma Rules on Apache HTTP Logs Dataset

This folder contains the **apache-http-logs** dataset for testing Sigma rules on HTTP/web server logs.
The dataset contains Apache access logs with various attack types: vulnerability scans, XSS attacks, and SQL injection attacks.

## Dataset Source

**Repository:** [ocatak/apache-http-logs](https://github.com/ocatak/apache-http-logs)

**Citation:**
```
@article{BASSEYYAR201828,
    title = "Detection of attack-targeted scans from the Apache HTTP Server access logs",
    journal = "Applied Computing and Informatics",
    volume = "14",
    number = "1",
    pages = "28 - 36",
    year = "2018",
    issn = "2210-8327",
    doi = "https://doi.org/10.1016/j.aci.2017.04.002",
    url = "http://www.sciencedirect.com/science/article/pii/S2210832717300169",
    author = "Merve Baş Seyyar and Ferhat Özgür Çatak and Ensar Gül",
    keywords = "Rule-based model, Log analysis, Scan detection, Web application security, XSS detection, SQLI detection"
}
```

## Dataset Setup

### 1. Clone the Dataset Repository

```bash
cd http_dataset_testing
git clone https://github.com/ocatak/apache-http-logs.git
```

## apache_to_opensearch.py

Python script that converts Apache HTTP access logs to OpenSearch bulk-ready NDJSON format.

**Step-by-step process:**

1. **Apache Log File Discovery**
   - Scans the `apache-http-logs` directory for access log files
   - Processes common Apache log formats (Combined Log Format, Common Log Format)

2. **Log Line Parsing**
   - Uses regex patterns to parse Apache access log format
   - Extracts fields from each log entry:
     - `client_ip`: Source IP address making the request
     - `timestamp`: Request timestamp in Apache format
     - `http_method`: HTTP method (GET, POST, PUT, DELETE, etc.)
     - `url_path`: Requested URL path
     - `query_string`: URL query parameters
     - `http_version`: HTTP protocol version
     - `status_code`: HTTP response status code (200, 404, 500, etc.)
     - `response_bytes`: Size of response in bytes
     - `referer`: HTTP Referer header
     - `user_agent`: User-Agent string (browser/tool identification)

3. **Attack Pattern Detection**
   - Analyzes URL parameters and paths for malicious patterns:
     - **XSS Detection**: Looks for JavaScript injection patterns (`<script>`, `onerror=`, `javascript:`, etc.)
     - **SQL Injection Detection**: Identifies SQL keywords and syntax (`UNION SELECT`, `' OR '1'='1'`, `DROP TABLE`, etc.)
     - **Path Traversal**: Detects directory traversal attempts (`../`, `..\\`, etc.)
     - **Command Injection**: Finds shell command patterns (`;`, `|`, `&&`, backticks, etc.)
     - **Vulnerability Scans**: Identifies scanner signatures (Nikto, sqlmap, Nmap, etc.) in User-Agent

4. **ECS Field Mapping**
   - Maps Apache log fields to Elastic Common Schema (ECS) for standardization:
     - `@timestamp`: ISO 8601 formatted timestamp
     - `source.ip`: Client IP address
     - `http.request.method`: HTTP method
     - `url.original`: Full URL with query string
     - `url.path`: URL path without query
     - `url.query`: Query string parameters
     - `http.response.status_code`: Response status
     - `http.response.bytes`: Response size
     - `http.request.referrer`: Referer header
     - `user_agent.original`: Full User-Agent string
     - `event.category`: "web" for all HTTP logs
     - `event.type`: "access" for access logs

5. **Sigma-Compatible Field Addition**
   - Adds root-level fields for Sigma rule matching:
     - `cs-uri-query`: Query string (common in web proxy logs)
     - `cs-uri-stem`: URL path (web proxy field)
     - `cs-method`: HTTP method (web proxy field)
     - `c-ip`: Client IP (web proxy field)
     - `sc-status`: Status code (web proxy field)
     - `cs-User-Agent`: User agent (web proxy field)

6. **Attack Classification**
   - Tags each log entry with detected attack types:
     - `attack.detected`: Boolean flag (true if any attack detected)
     - `attack.types`: Array of detected attack types (e.g., ["xss", "sqli"])
     - `attack.indicators`: Array of specific patterns matched
     - `event.kind`: "alert" for attacks, "event" for normal traffic

7. **Document Structure Creation**
   - Builds an ECS-compatible JSON document:
     ```json
     {
       "@timestamp": "2018-03-15T10:30:45.000Z",
       "source": {
         "ip": "192.168.1.100"
       },
       "http": {
         "request": {
           "method": "GET",
           "referrer": "http://example.com"
         },
         "response": {
           "status_code": 200,
           "bytes": 1234
         }
       },
       "url": {
         "original": "/admin.php?id=1' OR '1'='1",
         "path": "/admin.php",
         "query": "id=1' OR '1'='1"
       },
       "user_agent": {
         "original": "Mozilla/5.0..."
       },
       "event": {
         "category": "web",
         "type": "access",
         "kind": "alert"
       },
       "attack": {
         "detected": true,
         "types": ["sqli"],
         "indicators": ["' OR '1'='1"]
       },
       "cs-uri-query": "id=1' OR '1'='1",
       "cs-uri-stem": "/admin.php",
       "cs-method": "GET",
       "c-ip": "192.168.1.100",
       "sc-status": 200
     }
     ```

8. **Bulk NDJSON Generation**
   - Creates `apache_http_logs_bulk.ndjson` with OpenSearch bulk API format
   - Each log entry generates **two lines**:
     - Line 1: Index action → `{"index": {"_index": "apache-http-logs"}}`
     - Line 2: Document JSON → the complete log document
   - First line of file contains `POST _bulk` header (removed during import)

9. **Statistics and Output**
   - Tracks total logs processed
   - Counts attacks detected by type (XSS, SQLI, scans, etc.)
   - Handles parsing errors gracefully
   - Prints detection summary and statistics
   - Provides OpenSearch indexing instructions

**Key benefits for Sigma web rule testing:**
- ECS-compatible structure for standard detection rules
- Web proxy field compatibility (cs-uri-query, cs-method, c-ip, etc.)
- Automatic attack classification and tagging
- Preserves original Apache log format details
- Fast bulk import into OpenSearch for large datasets

## Dataset Import/Re-import Commands

To delete the existing index and re-import the dataset into OpenSearch:

```bash
# Navigate to the http_dataset_testing folder
cd http_dataset_testing

# Delete the existing index
curl -X DELETE "localhost:9200/apache-http-logs"

# Re-import the dataset (removes the first line "POST _bulk" and imports clean data)
tail -n +2 apache_http_logs_bulk.ndjson | curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-

# Verify the import
curl -X GET "localhost:9200/apache-http-logs/_count" | jq '.'
```

## Example Sigma Rules for HTTP Logs

### Web Vulnerability Scanning Detection

```yaml
title: Web Vulnerability Scanner Detection
logsource:
  category: webserver
detection:
  selection:
    cs-User-Agent|contains:
      - 'nikto'
      - 'sqlmap'
      - 'nmap'
      - 'masscan'
  condition: selection
```

### SQL Injection Attack Detection

```yaml
title: SQL Injection in URL Parameters
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "' OR '"
      - "UNION SELECT"
      - "DROP TABLE"
      - "'; DROP"
  condition: selection
```

### Cross-Site Scripting (XSS) Detection

```yaml
title: XSS Attack in HTTP Request
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '<script>'
      - 'javascript:'
      - 'onerror='
      - '<img src='
  condition: selection
```

## Next Steps

1. **Download the dataset**: Clone the apache-http-logs repository
2. **Generate NDJSON**: Run `python apache_to_opensearch.py` to convert logs
3. **Import to OpenSearch**: Use the bulk import command above
4. **Test Sigma rules**: Convert web-focused Sigma rules to PPL and query the dataset
5. **Analyze results**: Review detected attacks and validate rule effectiveness
