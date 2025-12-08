#!/bin/bash

# Script to scan domains from scan_list/list.txt using quic_client.sh
# Records results including status codes, geo-restriction detection, and timing info

LIST_FILE="300_test/list.txt"
OUTPUT_LOG="300_test/domain_scan.log"
CSV_LOG="300_test/domain_scan_results.csv"

# Check if list file exists
if [[ ! -f "$LIST_FILE" ]]; then
    echo "Error: $LIST_FILE not found!"
    exit 1
fi

# Create CSV header if file doesn't exist
if [[ ! -f "$CSV_LOG" ]]; then
    echo "domain,status_code,geo_restricted,ttfb_ms,ttlb_ms,total_bytes,server,redirect_location,timestamp" > "$CSV_LOG"
fi

echo "Starting domain scan from $LIST_FILE"
echo "Results will be logged to $OUTPUT_LOG and $CSV_LOG"
echo "=========================================="

# Read each domain from the list
while IFS= read -r domain || [[ -n "$domain" ]]; do
    # Skip empty lines and comments
    [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]] && continue
    
    echo "Testing domain: $domain"
    
    # Run quic_client.sh and capture output
    output=$(./quic_client.sh "$domain" 2>&1)
    
    # Extract information from output using grep and awk
    # Check for final status in redirect success message first
    final_status_from_redirect=$(echo "$output" | grep -o "Redirect followed successfully ([0-9]*)" | grep -o "[0-9]*")
    
    if [[ -n "$final_status_from_redirect" ]]; then
        # If redirect was followed successfully, use that status
        status_code="$final_status_from_redirect"
    else
        # Otherwise get the last status code from headers
        status_code=$(echo "$output" | grep -o ":status [0-9]*" | awk '{print $2}' | tail -1)
    fi
    
    # Check for various geo-restriction indicators
    geo_restricted=$(echo "$output" | grep -q "Geo-restriction detected" && echo "true" || echo "false")
    
    # Get timing values (use the last ones in case of redirects)
    ttfb=$(echo "$output" | grep -o "TTFB(ms): [0-9]*" | awk -F: '{print $2}' | tr -d ' ' | tail -1)
    ttlb=$(echo "$output" | grep -o "TTLB(ms): [0-9]*" | awk -F: '{print $2}' | tr -d ' ' | tail -1)
    total_bytes=$(echo "$output" | grep -o "total received bytes: [0-9]*" | awk '{print $4}' | tail -1)
    
    # Get server from the first occurrence
    server=$(echo "$output" | grep "server " | head -1 | awk '{print $2}')
    
    # Only record location if final status is still a redirect (3XX)
    if [[ "$status_code" =~ ^3[0-9][0-9]$ ]]; then
        location=$(echo "$output" | grep "location " | tail -1 | awk '{print $2}')
    else
        location="N/A"
    fi
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Handle cases where values might be empty
    [[ -z "$status_code" ]] && status_code="N/A"
    [[ -z "$ttfb" ]] && ttfb="N/A"
    [[ -z "$ttlb" ]] && ttlb="N/A"
    [[ -z "$total_bytes" ]] && total_bytes="N/A"
    [[ -z "$server" ]] && server="N/A"
    [[ -z "$location" ]] && location="N/A"
    
    # Log to text file
    {
        echo "Domain: $domain"
        echo "Status Code: $status_code"
        echo "Geo-restricted: $geo_restricted"
        echo "TTFB (ms): $ttfb"
        echo "TTLB (ms): $ttlb"
        echo "Total Bytes: $total_bytes"
        echo "Server: $server"
        echo "Redirect Location: $location"
        echo "Timestamp: $timestamp"
        echo "----------------------------------------"
    } >> "$OUTPUT_LOG"
    
    # Log to CSV file
    echo "\"$domain\",\"$status_code\",\"$geo_restricted\",\"$ttfb\",\"$ttlb\",\"$total_bytes\",\"$server\",\"$location\",\"$timestamp\"" >> "$CSV_LOG"
    
    echo "  Status: $status_code, Geo-restricted: $geo_restricted, TTFB: ${ttfb}ms, TTLB: ${ttlb}ms"
    
    # Small delay to avoid overwhelming the server
    sleep 1
    
done < "$LIST_FILE"

echo "=========================================="
echo "Scan completed!"
echo "Results saved to:"
echo "  - Text log: $OUTPUT_LOG"
echo "  - CSV log: $CSV_LOG"
echo "Total domains processed: $(wc -l < "$LIST_FILE")"
