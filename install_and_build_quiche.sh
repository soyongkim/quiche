#!/bin/bash

set -e
set -o pipefail

echo "Installing Build-essential..."
sudo apt install build-essential -y || { echo "Failed to install build-essential"; exit 1; }
sudo apt install libicu-dev -y || { echo "Failed to install libicu-dev"; exit 1; }

echo "Installing Bazel dependencies..."
sudo apt install apt-transport-https curl gnupg -y
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
sudo apt update -y && sudo apt install bazel-7.0.0 -y


echo "Running Bazel sync..."
bazel sync || { echo "Bazel sync failed"; exit 1; }

echo "Building Quiche..."
bazel build //quiche:quic_server //quiche:quic_client //quiche:masque_server //quiche:masque_client || { echo "Bazel build failed"; exit 1; }

echo "Quiche build completed successfully!"