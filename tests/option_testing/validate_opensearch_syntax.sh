#!/bin/bash
# Manual syntax validation for PPL queries in OpenSearch

OPENSEARCH_URL="http://localhost:9200"
OPENSEARCH_USER="admin"
OPENSEARCH_PASS="Admin@123"

echo "=========================================="
echo "OpenSearch PPL Syntax Validation"
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
    
    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}✗ FAILED - Syntax Error${NC}"
        echo "$response" | jq '.'
    else
        echo -e "${GREEN}✓ PASSED - Valid Syntax${NC}"
        # echo "$response" | jq -r '.root'
    fi
    echo ""
}

echo "=== Basic Queries ==="
echo ""

echo "Test 1: Default Logsource"
test_query "$(cat out/default_logsource.txt)" "default_logsource"

echo "Test 2: Custom Logsource"
test_query "$(cat out/custom_logsource.txt)" "custom_logsource"

echo ""
echo "=== Time Filter Queries ==="
echo ""

echo "Test 3: Time Filters Relative"
test_query "$(cat out/time_filters_relative.txt)" "time_filters_relative"

echo "Test 4: Time Filters Absolute"
test_query "$(cat out/time_filters_absolute.txt)" "time_filters_absolute"

echo "Test 5: Time Filters Min Only"
test_query "$(cat out/time_filters_min_only.txt)" "time_filters_min_only"

echo "Test 6: Time Filters Max Only"
test_query "$(cat out/time_filters_max_only.txt)" "time_filters_max_only"

echo "Test 7: Combined Options"
test_query "$(cat out/combined_options.txt)" "combined_options"

echo "=========================================="
echo "Syntax Validation Complete"
echo "=========================================="
