#!/bin/bash

set -e
set -o pipefail

echo "Installing Build-essential..."
sudo apt install build-essential -y || { echo "Failed to install build-essential"; exit 1; }
sudo apt install libicu-dev -y || { echo "Failed to install libicu-dev"; exit 1; }

echo "Checking for Bazel installation..."
if command -v bazel &> /dev/null; then
    BAZEL_VERSION=$(bazel --version | head -n1)
    echo "Bazel is already installed: $BAZEL_VERSION"
else
    echo "Installing Bazel dependencies..."
    sudo apt install apt-transport-https curl gnupg -y
    curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
    sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
    sudo apt update -y && sudo apt install bazel-7.0.0 -y
    
    echo "Creating symlink for bazel..."
    sudo ln -sf /usr/bin/bazel-7.0.0 /usr/bin/bazel || { echo "Failed to create bazel symlink"; exit 1; }
fi

echo "Verifying C++ compiler installation..."
if ! command -v gcc &> /dev/null; then
    echo "ERROR: gcc not found in PATH"
    exit 1
fi
gcc --version
export CC=$(which gcc)
export CXX=$(which g++)
export PATH=$PATH
echo "Using CC=$CC and CXX=$CXX"

echo "Cleaning Bazel cache to reset compiler configuration..."
bazel clean --expunge || { echo "Bazel clean failed"; exit 1; }

echo "Running Bazel sync..."
bazel sync --repo_env=CC=$CC --repo_env=CXX=$CXX --repo_env=PATH=$PATH || { echo "Bazel sync failed"; exit 1; }

echo "Building Quiche..."
bazel build --repo_env=CC=$CC --repo_env=CXX=$CXX --repo_env=PATH=$PATH //quiche:quic_server //quiche:quic_client //quiche:masque_server //quiche:masque_client || { echo "Bazel build failed"; exit 1; }

echo "Quiche build completed successfully!"