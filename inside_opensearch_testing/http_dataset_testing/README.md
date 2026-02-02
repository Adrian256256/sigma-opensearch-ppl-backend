# Testing Sigma Rules on Apache HTTP Logs Dataset

This folder contains the **apache-http-logs** dataset for testing Sigma rules on HTTP/web server logs.
The dataset contains Apache access logs with various attack types: vulnerability scans, XSS attacks, and SQL injection attacks.

## Dataset Source

**Repository:** [ocatak/apache-http-logs](https://github.com/ocatak/apache-http-logs)


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

## Tested and Validated Sigma Rules

The following official Sigma rules from `ecs_fields_info/sigma-master` work **directly** with the PPL backend (no manual query modifications needed, just change the source index):

### 1. Path Traversal Exploitation Attempt

**Rule File**: `ecs_fields_info/sigma-master/rules/web/webserver_generic/web_path_traversal_exploitation_attempt.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/web/webserver_generic/web_path_traversal_exploitation_attempt.yml
```

**Generated PPL Query** (Backend Output):
```ppl
source=webserver-* | where LIKE(`cs-uri-query`, "%../../../../../lib/password%") OR LIKE(`cs-uri-query`, "%../../../../windows/%") OR LIKE(`cs-uri-query`, "%../../../etc/%") OR LIKE(`cs-uri-query`, "%..\%252f..\%252f..\%252fetc\%252f%") OR LIKE(`cs-uri-query`, "%..\%c0\%af..\%c0\%af..\%c0\%afetc\%c0\%af%") OR LIKE(`cs-uri-query`, "%\%252e\%252e\%252fetc\%252f%")
```

**Test Query** (only change: `source=apache-http-logs`):
```bash
curl -X POST "localhost:9200/_plugins/_ppl" -H 'Content-Type: application/json' -d '{
  "query": "source=apache-http-logs | where LIKE(`cs-uri-query`, \"%../../../../../lib/password%\") OR LIKE(`cs-uri-query`, \"%../../../../windows/%\") OR LIKE(`cs-uri-query`, \"%../../../etc/%\") | head 5"
}' | jq '.'
```

---

### 2. Suspicious Windows Paths in URI

**Rule File**: `ecs_fields_info/sigma-master/rules/web/webserver_generic/web_susp_windows_path_uri.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/web/webserver_generic/web_susp_windows_path_uri.yml
```

**Generated PPL Query** (Backend Output):
```ppl
source=webserver-* | where LIKE(`cs-uri-query`, "%=C:/Users%") OR LIKE(`cs-uri-query`, "%=C:/Program\%20Files%") OR LIKE(`cs-uri-query`, "%=C:/Windows%") OR LIKE(`cs-uri-query`, "%=C\%3A\%5CUsers%") OR LIKE(`cs-uri-query`, "%=C\%3A\%5CProgram\%20Files%") OR LIKE(`cs-uri-query`, "%=C\%3A\%5CWindows%")
```

**Test Query** (only change: `source=apache-http-logs`):
```bash
curl -X POST "localhost:9200/_plugins/_ppl" -H 'Content-Type: application/json' -d '{
  "query": "source=apache-http-logs | where LIKE(`cs-uri-query`, \"%=C:/Users%\") OR LIKE(`cs-uri-query`, \"%=C:/Windows%\") | head 5"
}' | jq '.'
```

---

### 3. Webshell ReGeorg Detection

**Rule File**: `ecs_fields_info/sigma-master/rules/web/webserver_generic/web_webshell_regeorg.yml`

**Convert Sigma Rule to PPL**:
```bash
./cli/sigma-ppl ecs_fields_info/sigma-master/rules/web/webserver_generic/web_webshell_regeorg.yml
```

**Generated PPL Query** (Backend Output):
```ppl
source=webserver-* | where (LIKE(`cs-uri-query`, "%cmd=read%") OR LIKE(`cs-uri-query`, "%connect&target%") OR LIKE(`cs-uri-query`, "%cmd=connect%") OR LIKE(`cs-uri-query`, "%cmd=disconnect%") OR LIKE(`cs-uri-query`, "%cmd=forward%")) AND isnull(`cs-referer`) AND isnull(`cs-user-agent`) AND `cs-method`="POST"
```

**Test Query** (only change: `source=apache-http-logs`):
```bash
curl -X POST "localhost:9200/_plugins/_ppl" -H 'Content-Type: application/json' -d '{
  "query": "source=apache-http-logs | where (LIKE(`cs-uri-query`, \"%cmd=read%\") OR LIKE(`cs-uri-query`, \"%cmd=connect%\")) AND `cs-method`=\"POST\" | head 5"
}' | jq '.'
```
