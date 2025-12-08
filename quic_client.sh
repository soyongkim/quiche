#!/bin/bash

# QUIC server / client configuration
source config.sh

# Parse command line arguments
URL=""
HOST=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --url=*)
      URL="${1#*=}"
      shift
      ;;
    --host=*)
      HOST="${1#*=}"
      shift
      ;;
    --url)
      URL="$2"
      shift 2
      ;;
    --host)
      HOST="$2"
      shift 2
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
  echo "Usage: $0 --url=<domain> [--host=<host_ip>]"
  echo "   or: $0 <domain> (for backward compatibility)"
  echo ""
  echo "Examples:"
  echo "  $0 --url=example.com"
  echo "  $0 --url=example.com --host=1.2.3.4"
  echo "  $0 example.com (old format)"
  exit 1
fi

# Build the command
CMD="./bazel-bin/quiche/quic_client --disable_certificate_verification"

# Add host parameter if provided
if [[ -n "$HOST" ]]; then
  CMD="$CMD --host=$HOST"
fi

# Add the URL (ensure it has https:// prefix)
if [[ ! "$URL" =~ ^https?:// ]]; then
  URL="https://$URL"
fi

CMD="$CMD $URL"

# Execute the command
echo "Executing: $CMD"
$CMD