#!/bin/bash
# Manual syntax validation for custom_attribute_testing PPL queries in OpenSearch

OPENSEARCH_URL="http://localhost:9200"
OPENSEARCH_USER="admin"
OPENSEARCH_PASS="Admin@123"

echo "=========================================="
echo "Custom Attribute Testing - PPL Validation"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_query() {
    local query="$1"
    local name="$2"
    
    echo -e "${YELLOW}Testing: ${name}${NC}"
    echo "Query: $query"
    
    # Escape backslashes and quotes for JSON
    local escaped_query=$(echo "$query" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
    
    # Use explain API to validate syntax without executing
    response=$(curl -s -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
        -X POST "${OPENSEARCH_URL}/_plugins/_ppl/_explain" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$escaped_query\"}")
    
    # Check for syntax errors (not index not found errors)
    if echo "$response" | grep -q '"type":"SyntaxCheckException"'; then
        echo -e "${RED}✗ SYNTAX ERROR${NC}"
        echo "$response" | jq '.'
    elif echo "$response" | grep -q '"type":"IndexNotFoundException"'; then
        echo -e "${GREEN}✓ SYNTAX OK (index not found is expected)${NC}"
    elif echo "$response" | grep -q '"error"'; then
        echo -e "${RED}✗ ERROR${NC}"
        echo "$response" | jq '.'
    else
        echo -e "${GREEN}✓ SYNTAX OK${NC}"
    fi
    echo ""
}

echo "=== Basic Queries ==="
echo ""

echo "Test 1: All Attributes"
test_query "search earliest=-14d latest=now CommandLine=\"test.exe\" source=complete-test-*" "all_attributes"

echo "Test 2: No Attributes"
test_query "source=windows-process_creation-* | where CommandLine=\"test.exe\"" "no_attributes"

echo "Test 3: Partial Attributes"
test_query "source=partial-test-* | where CommandLine=\"test.exe\"" "partial_attributes"

echo "Test 4: Custom Index"
test_query "source=my-custom-index-* | where CommandLine=\"test.exe\"" "custom_index"

echo ""
echo "=== Time Filter Queries ==="
echo ""

echo "Test 5: Time Absolute"
test_query "search earliest='2024-01-15 10:00:00' latest='2024-01-15 16:00:00' CommandLine=\"test.exe\" source=windows-process_creation-*" "time_absolute"

echo "Test 6: Time Min Max"
test_query "search earliest=-30d latest=now CommandLine=\"test.exe\" source=windows-process_creation-*" "time_min_max"

echo "Test 7: Time Modifier Simple"
test_query "search earliest=-7d CommandLine=\"test.exe\" source=windows-process_creation-*" "time_modifier_simple"

echo "Test 8: Time Rounding"
test_query "search earliest='-1month@month' latest='+1d@d' CommandLine=\"test.exe\" source=windows-process_creation-*" "time_rounding"

echo ""
echo "=== Correlation Queries ==="
echo ""

echo "Test 9: Correlation Event Count"
test_query "| search earliest=-24h latest=now source=windows-security-* | where EventID=4625 | stats count() as event_count by SourceIP | where event_count >= 5" "correlation_event_count"

echo "Test 10: Correlation Temporal"
read -r -d '' QUERY << 'EOF'
| multisearch [search earliest='2026-02-01 00:00:00' latest='2026-02-28 23:59:59' source=windows-process_creation-* | where LIKE(CommandLine, "%suspicious%")] [search earliest='2026-02-01 00:00:00' latest='2026-02-28 23:59:59' source=windows-network_connection-* | where Initiated="true"] | stats dc(EventID) as unique_rules by span(@timestamp, 2m), Computer | where unique_rules >= 2
EOF
test_query "$QUERY" "correlation_temporal"

echo "Test 11: Correlation Value Count"
test_query "| search earliest='-1month@month' latest='+1d@d' source=windows-process_creation-* | where LIKE(Image, \"%powershell.exe\") | stats dc(CommandLine) as value_count by User | where value_count >= 3" "correlation_value_count"

echo "Test 12: Correlation Mixed Times"
test_query "| multisearch [search earliest=-7d latest=now LIKE(CommandLine, \"%malware%\") source=windows-process_creation-*] [search earliest=-30d latest=now source=windows-network_connection-* | where DestinationPort=443] | stats dc(EventID) as unique_rules by span(@timestamp, 5m), Computer | where unique_rules >= 2" "correlation_mixed_times"

echo "=========================================="
echo "Validation Complete"
echo "=========================================="
