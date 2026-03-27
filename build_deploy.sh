#!/bin/bash
set -e
set -o pipefail

# For Deployment
REMOTE_HOST=("130.104.229.71" "0.0.0.0")
REMOTE_USER="root"
REMOTE_PATH="/root/Workspace/quiche_binary"
SSH_KEY_PATH="${HOME}/.ssh/id_rsa"

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
bazel build //quiche:quic_server //quiche:quic_client //quiche:masque_server //quiche:masque_client //quiche:proxy_tcp_client || { echo "Bazel build failed"; exit 1; }

# Ensure the remote device has the expected directory structure and deploy files
for host in "${REMOTE_HOST[@]}"; do
  if [[ "$host" == "0.0.0.0" ]]; then
    echo "Skipping host 0.0.0.0..."
    continue
  fi

  echo "Setting up ${host}..."

  # Create required directory on remote host
  ssh $SSH_OPTION "${REMOTE_USER}@${host}" "mkdir -p ${REMOTE_PATH}/bazel-bin/quiche" || { echo "Failed to create remote directory on ${host}"; exit 1; }

  # Deploy binaries
  for binary in masque_server masque_client quic_server quic_client proxy_tcp_client; do
    scp $SSH_OPTION "bazel-bin/quiche/${binary}" "${REMOTE_USER}@${host}:${REMOTE_PATH}/bazel-bin/quiche/" || { echo "Failed to deploy ${binary} to ${host}"; exit 1; }
  done

  # Deploy scripts
  scp $SSH_OPTION quic_server.sh quic_client.sh masque_proxy.sh masque_client.sh config.sh tcp_client.sh "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to deploy scripts to ${host}"; exit 1; }

  # Deploy server requirements
  scp $SSH_OPTION -r certs quic-data "${REMOTE_USER}@${host}:${REMOTE_PATH}" || { echo "Failed to deploy server requirements to ${host}"; exit 1; }

done

echo "Build and deployment completed successfully!"
