#!/bin/bash

# Geo-detection scanner with parallel workers
# Usage: ./scan_geo_detector.sh --interface=eth0 --input=text.file --num=3 --parallel=4 --save-html

# Default values
INTERFACE=""
INPUT_FILE=""
NUM_REQUESTS=1
PARALLEL=1
SAVE_HTML=false
QUIET=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --interface=*)
      INTERFACE="${1#*=}"
      shift
      ;;
    --input=*)
      INPUT_FILE="${1#*=}"
      shift
      ;;
    --num=*)
      NUM_REQUESTS="${1#*=}"
      shift
      ;;
    --parallel=*)
      PARALLEL="${1#*=}"
      shift
      ;;
    --save-html)
      SAVE_HTML=true
      shift
      ;;
    --quiet)
      QUIET=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Validate required arguments
if [[ -z "$INPUT_FILE" ]]; then
  echo "Error: --input is required"
  echo ""
  echo "Usage: $0 --input=<file> [options]"
  echo ""
  echo "Required:"
  echo "  --input=<file>           Input file with one domain per line"
  echo ""
  echo "Options:"
  echo "  --interface=<name>       Network interface to use (e.g., eth0, nordlynx)"
  echo "  --num=<number>           Number of requests per domain (default: 1)"
  echo "  --parallel=<number>      Number of parallel workers (default: 1)"
  echo "  --save-html              Save HTML responses"
  echo "  --quiet                  Quieter output"
  echo ""
  echo "Examples:"
  echo "  $0 --input=domains.txt --num=3 --parallel=4"
  echo "  $0 --input=domains.txt --interface=nordlynx --parallel=8 --save-html"
  exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: Input file not found: $INPUT_FILE"
  exit 1
fi

# Count total domains
TOTAL_DOMAINS=$(wc -l < "$INPUT_FILE")
echo "Total domains to scan: $TOTAL_DOMAINS"
echo "Parallel workers: $PARALLEL"
echo "Requests per domain: $NUM_REQUESTS"
[[ "$SAVE_HTML" == "true" ]] && echo "HTML saving: enabled" || echo "HTML saving: disabled"
[[ -n "$INTERFACE" ]] && echo "Network interface: $INTERFACE"
echo ""

# Create timestamp directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR="scan_results/${TIMESTAMP}"
mkdir -p "$WORK_DIR"

# Create html subdirectory if HTML saving is enabled
if [[ "$SAVE_HTML" == "true" ]]; then
  mkdir -p "${WORK_DIR}/html"
fi

echo "Working directory: $WORK_DIR"
echo ""

# Split input file into parts
echo "Splitting input file into $PARALLEL parts..."
LINES_PER_PART=$(( (TOTAL_DOMAINS + PARALLEL - 1) / PARALLEL ))

split -l "$LINES_PER_PART" -d -a 3 "$INPUT_FILE" "${WORK_DIR}/part_"

# Count actual parts created (in case file was smaller than expected)
PARTS_CREATED=$(ls -1 "${WORK_DIR}"/part_* 2>/dev/null | wc -l)
echo "Created $PARTS_CREATED part files with ~$LINES_PER_PART domains each"
echo ""

# Function to process one part
process_part() {
  local PART_FILE=$1
  local WORKER_NUM=$2
  local CPU_CORE=$3
  
  local CSV_FILE="${WORK_DIR}/worker_${WORKER_NUM}.csv"
  
  # Build quic_client options
  local QUIC_OPTS=""
  [[ -n "$INTERFACE" ]] && QUIC_OPTS="$QUIC_OPTS --interface-name=$INTERFACE"
  [[ "$QUIET" == "true" ]] && QUIC_OPTS="$QUIC_OPTS --quiet"
  
  # Read domains from part file and process each
  local PROCESSED=0
  while IFS= read -r domain; do
    # Skip empty lines and comments
    [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]] && continue
    
    # Build command for this domain (with --disable-port-changes for multiple requests)
    local CMD="./quic_client.sh --url=$domain --save-csv=$CSV_FILE --num-requests=$NUM_REQUESTS --disable-port-changes $QUIC_OPTS"
    
    # Add HTML saving if enabled
    if [[ "$SAVE_HTML" == "true" ]]; then
      CMD="$CMD --save-html=${WORK_DIR}/html/${domain}.html"
    fi
    
    # Execute with error handling (suppress output)
    if ! $CMD > /dev/null 2>&1; then
      echo "[Worker $WORKER_NUM] Failed to scan: $domain"
    fi
    
    ((PROCESSED++))
  done < "$PART_FILE"
  
  echo "[Worker $WORKER_NUM] Completed $PROCESSED domains (CPU core $CPU_CORE)"
}

export -f process_part
export WORK_DIR INTERFACE NUM_REQUESTS SAVE_HTML QUIET

# Launch workers with CPU affinity
echo "Launching $PARTS_CREATED workers..."
WORKER_PIDS=()
WORKER_NUM=0

for PART_FILE in "${WORK_DIR}"/part_*; do
  CPU_CORE=$(( WORKER_NUM % $(nproc) ))
  
  echo "Starting Worker $WORKER_NUM on CPU core $CPU_CORE (processing $(basename $PART_FILE))..."
  
  # Launch worker with taskset
  taskset -c "$CPU_CORE" bash -c "process_part '$PART_FILE' $WORKER_NUM $CPU_CORE" &
  WORKER_PIDS+=($!)
  
  ((WORKER_NUM++))
done

echo ""
echo "All workers started. Waiting for completion..."
echo ""

# Wait for all workers and track completion
COMPLETED=0
FAILED=0
for i in "${!WORKER_PIDS[@]}"; do
  PID="${WORKER_PIDS[$i]}"
  if wait "$PID"; then
    ((COMPLETED++))
  else
    ((FAILED++))
    echo "Warning: Worker $((i+1)) with PID $PID had errors (but may have partial results)"
  fi
done

echo ""
echo "Workers completed: $COMPLETED / ${#WORKER_PIDS[@]}"
[[ $FAILED -gt 0 ]] && echo "Workers with errors: $FAILED (check logs for details)"
echo ""

# Merge CSV files
MERGED_CSV="${WORK_DIR}/merged_results.csv"
echo "Merging CSV results into: $MERGED_CSV"

FIRST_FILE=true
for CSV_FILE in "${WORK_DIR}"/worker_*.csv; do
  if [[ ! -f "$CSV_FILE" ]]; then
    continue
  fi
  
  if [[ "$FIRST_FILE" == "true" ]]; then
    # Copy first file with header
    cat "$CSV_FILE" > "$MERGED_CSV"
    FIRST_FILE=false
  else
    # Skip header for subsequent files
    tail -n +2 "$CSV_FILE" >> "$MERGED_CSV"
  fi
done

# Count results
if [[ -f "$MERGED_CSV" ]]; then
  RESULT_COUNT=$(tail -n +2 "$MERGED_CSV" | wc -l)
  echo "Total results in merged CSV: $RESULT_COUNT"
  echo ""
  echo "Results saved to: $MERGED_CSV"
  
  # Cleanup temporary files
  echo ""
  echo "Cleaning up temporary files..."
  rm -f "${WORK_DIR}"/part_*
  rm -f "${WORK_DIR}"/worker_*.csv
  echo "Removed part_* and worker_*.csv files"
  
  # Show summary statistics
  echo ""
  echo "=== Summary ==="
  echo "CSV file: $MERGED_CSV"
  echo "HTML files: ${WORK_DIR}/html/ ($([[ "$SAVE_HTML" == "true" ]] && find "${WORK_DIR}/html" -name "*.html" -type f 2>/dev/null | wc -l || echo 0) files)"
else
  echo "Warning: No results to merge"
fi

echo ""
echo "Scan complete!"
