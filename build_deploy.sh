#!/bin/bash
set -e
set -o pipefail

# For Deployment
REMOTE_HOST=("0.0.0.0" "0.0.0.0")
REMOTE_USER="root"
REMOTE_PATH="/your/path/quiche_deployment"
SSH_KEY_PATH="${HOME}/.ssh/your_private_key"

# Validate that at least one remote host is configured
if [ ${#REMOTE_HOST[@]} -eq 0 ]; then
  echo "No remote hosts configured."
  exit 1
fi

# Determine SSH options (skip -i if SSH_KEY_PATH is empty)
if [ -n "$SSH_KEY_PATH" ]; then
  SSH_OPTION="-i $SSH_KEY_PATH"
else
  SSH_OPTION=""
fi

echo "Building Quiche..."
bazel build //quiche:quic_server //quiche:quic_client //quiche:masque_server //quiche:masque_client || { echo "Bazel build failed"; exit 1; }

# Ensure the remote device has the expected directory structure:
# Create ${REMOTE_PATH}/bazel-bin/quiche on each remote host.
for host in "${REMOTE_HOST[@]}"; do
  echo "Creating remote directory ${REMOTE_PATH}/bazel-bin/quiche on ${host}..."
  ssh $SSH_OPTION "${REMOTE_USER}@${host}" "mkdir -p ${REMOTE_PATH}/bazel-bin/quiche" || { echo "Failed to create remote directory on ${host}"; exit 1; }
done

# Deploy the built binaries and additional files
for host in "${REMOTE_HOST[@]}"; do
  echo "Deploying build output to ${host}..."
  scp $SSH_OPTION bazel-bin/quiche/masque_server "${REMOTE_USER}@${host}:${REMOTE_PATH}/bazel-bin/quiche/" || { echo "Failed to deploy masque_server to ${host}"; exit 1; }
  scp $SSH_OPTION bazel-bin/quiche/masque_client "${REMOTE_USER}@${host}:${REMOTE_PATH}/bazel-bin/quiche/" || { echo "Failed to deploy masque_client to ${host}"; exit 1; }
  scp $SSH_OPTION bazel-bin/quiche/quic_server "${REMOTE_USER}@${host}:${REMOTE_PATH}/bazel-bin/quiche/" || { echo "Failed to deploy quic_server to ${host}"; exit 1; }
  scp $SSH_OPTION bazel-bin/quiche/quic_client "${REMOTE_USER}@${host}:${REMOTE_PATH}/bazel-bin/quiche/" || { echo "Failed to deploy quic_client to ${host}"; exit 1; }
  
  echo "Deploying scripts to ${host}..."
  scp $SSH_OPTION quic_server.sh quic_client.sh masque_proxy.sh masque_client.sh config.sh "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to deploy scripts to ${host}"; exit 1; }
  
  echo "Deploying server requirements to ${host}..."
  scp $SSH_OPTION -r certs quic-data "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to deploy server requirements to ${host}"; exit 1; }
done

echo "Build and deployment completed successfully!"
