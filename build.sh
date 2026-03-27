#!/bin/bash
set -e
set -o pipefail

export CC=$(which gcc)
export CXX=$(which g++)

echo "Building Quiche..."
bazel build --repo_env=CC=$CC --repo_env=CXX=$CXX --repo_env=PATH=$PATH //quiche:quic_server //quiche:quic_client //quiche:masque_server //quiche:masque_client || { echo "Bazel build failed"; exit 1; }

echo "Build completed successfully!"
