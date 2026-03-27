#!/bin/bash

# QUIC server / client configuration
source config.sh

# Parse command line arguments
URL=""
EXTRA_FLAGS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --url=*)
      URL="${1#*=}"
      shift
      ;;
    --url)
      URL="$2"
      shift 2
      ;;
    --*)
      # Pass through all other flags (convert dashes to underscores, keep = format)
      if [[ "$1" == *"="* ]]; then
        FLAG_NAME="${1%%=*}"  # Get part before =
        FLAG_VALUE="${1#*=}"  # Get part after =
        FLAG_NAME="${FLAG_NAME#--}"  # Remove --
        FLAG_NAME="${FLAG_NAME//-/_}"  # Convert dashes to underscores
        EXTRA_FLAGS="$EXTRA_FLAGS --$FLAG_NAME=$FLAG_VALUE"
      else
        FLAG_NAME="${1#--}"
        FLAG_NAME="${FLAG_NAME//-/_}"
        EXTRA_FLAGS="$EXTRA_FLAGS --$FLAG_NAME"
      fi
      shift
      ;;
    *)
      # If no flags, treat as URL for backward compatibility
      if [[ -z "$URL" ]]; then
        URL="$1"
      fi
      shift
      ;;
  esac
done

# Check if URL is provided
if [[ -z "$URL" ]]; then
  echo "Usage: $0 --url=<domain> [options]"
  echo "   or: $0 <domain> (for backward compatibility)"
  echo ""
  echo "Options:"
  echo "  --url=<domain>           Domain to connect to"
  echo "  --host=<host_ip>         Override host IP"
  echo "  --save-csv=<filename>    Save scan results to CSV file"
  echo "  --save-html=<path>       Save HTML response to specified path (e.g., output.html or dir/file.html)"
  echo "  --quiet                  Quieter output"
  echo ""
  echo "Examples:"
  echo "  $0 --url=example.com"
  echo "  $0 --url=example.com --host=1.2.3.4"
  echo "  $0 --url=example.com --save-csv=results.csv --save-html=example.html"
  echo "  $0 example.com (old format)"
  exit 1
fi

# Build the command
CMD="./bazel-bin/quiche/quic_client --disable_certificate_verification"

# Add any extra flags
if [[ -n "$EXTRA_FLAGS" ]]; then
  CMD="$CMD $EXTRA_FLAGS"
fi

# Add the URL (ensure it has https:// prefix)
if [[ ! "$URL" =~ ^https?:// ]]; then
  URL="https://$URL"
fi

CMD="$CMD $URL"

# Execute the command
echo "Executing: $CMD"
$CMD