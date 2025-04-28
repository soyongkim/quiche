#!/bin/bash
set -e
set -o pipefail

echo "Building Quiche..."
bazel build //quiche:quic_server //quiche:quic_client //quiche:masque_server //quiche:masque_client || { echo "Bazel build failed"; exit 1; }

echo "Build completed successfully!"
