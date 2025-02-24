#!/bin/bash
set -e
set -o pipefail

# Check if remote host is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <remote_host>"
  exit 1
fi

REMOTE_HOST="$1"

# Source the common configuration (assumes config.sh is in the same directory)
source "$(dirname "$0")/config.sh"

# Determine the SSH option: if SSH_KEY_PATH is defined and non-empty, use it; otherwise, leave it empty.
if [ -n "$SSH_KEY_PATH" ]; then
  SSH_OPTION="-i $SSH_KEY_PATH"
else
  SSH_OPTION=""
fi

echo "Building Quiche..."
bazel build //... || { echo "Bazel build failed"; exit 1; }

# Send build output to the remote build destination
echo "Deploying build output to ${REMOTE_HOST}..."
scp $SSH_OPTION -r bazel-bin ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH} || { echo "Failed to send build output"; exit 1; }

# Deploy scripts to the remote script destination
echo "Deploying scripts to ${REMOTE_HOST}..."
scp $SSH_OPTION quic_server.sh quic_client.sh masque_proxy.sh ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH} || { echo "Failed to send scripts"; exit 1; }

# Deploy quic server requirements to the remote script destination
echo "Deploying server requirements to ${REMOTE_HOST}..."
scp $SSH_OPTION -r certs quic-data ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH} || { echo "Failed to send server requirements"; exit 1; }

echo "Build and deployment completed successfully!"