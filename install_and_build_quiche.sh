#!/bin/bash

set -e
set -o pipefail

echo "Installing Bazel dependencies..."
sudo apt install apt-transport-https curl gnupg -y || { echo "Failed to install Bazel dependencies"; exit 1; }
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel-archive-keyring.gpg || { echo "Failed to fetch Bazel GPG key"; exit 1; }
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings || { echo "Failed to move Bazel keyring"; exit 1; }
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list || { echo "Failed to add Bazel repository"; exit 1; }
sudo apt update -y || { echo "Failed to update package list"; exit 1; }
sudo apt install bazel-7.0.0 -y || { echo "Failed to install Bazel"; exit 1; }
sudo apt full-upgrade -y || { echo "Failed to upgrade packages"; exit 1; }
sudo apt install libicu-dev -y || { echo "Failed to install libicu-dev"; exit 1; }

echo "Installing Build-essential..."
sudo apt install build-essential -y || { echo "Failed to install build-essential"; exit 1; }


echo "Running Bazel sync..."
bazel sync || { echo "Bazel sync failed"; exit 1; }

echo "Building Quiche..."
bazel build //... || { echo "Bazel build failed"; exit 1; }

echo "Quiche build completed successfully!"