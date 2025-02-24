#!/bin/bash
set -e
set -o pipefail

# for Deloyment
REMOTE_HOST=("0.0.0.0" "0.0.0.0")
REMOTE_USER="root"
REMOTE_PATH="/your/path/quiche_deployment"
SSH_KEY_PATH="${HOME}/.ssh/private_key"


# Validate that at least one remote host is configured
if [ ${#REMOTE_HOST[@]} -eq 0 ]; then
  echo "No remote hosts configured in config.sh."
  exit 1
fi

# Determine SSH options (skip -i if SSH_KEY_PATH is empty)
if [ -n "$SSH_KEY_PATH" ]; then
  SSH_OPTION="-i $SSH_KEY_PATH"
else
  SSH_OPTION=""
fi

echo "Building Quiche..."
bazel build //... || { echo "Bazel build failed"; exit 1; }

# Deploy build output, scripts, and server requirements to each remote host
for host in "${REMOTE_HOST[@]}"; do
  echo "Deploying build output to ${host}..."
  scp $SSH_OPTION -r bazel-bin "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to deploy build output to ${host}"; exit 1; }
  scp $SSH_OPTION quic_server.sh quic_client.sh masque_proxy.sh masque_client.sh config.sh "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to send scripts to ${host}"; exit 1; }
  scp $SSH_OPTION -r certs quic-data "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to send server requirements to ${host}"; exit 1; }
done

echo "Build and deployment completed successfully!"