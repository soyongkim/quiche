#!/bin/sh

# Copyright 2015 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script generates a CA and leaf cert which can be used for the
# quic_server.

set -e  # Stop execution on error

try() {
  "$@" || (e=$?; echo "Error executing: $@" >&2; exit $e)
}

# Cleanup existing files and create directories
try rm -rf out
try mkdir -p out

# Initialize OpenSSL CA database
try /bin/sh -c "echo 01 > out/2048-sha256-root-serial"
try touch out/2048-sha256-root-index.txt
try touch out/2048-sha256-root-index.txt.attr  # Ensure index attr file exists

# Generate the root private key
try openssl genrsa -out out/2048-sha256-root.key 2048

# Generate the root certificate signing request (CSR)
try openssl req \
  -new \
  -key out/2048-sha256-root.key \
  -out out/2048-sha256-root.req \
  -config ca.cnf \
  -subj "/CN=QUIC Server Root CA"

# Self-sign the root certificate
try openssl x509 \
  -req -days 1000 \
  -in out/2048-sha256-root.req \
  -signkey out/2048-sha256-root.key \
  -extfile ca.cnf \
  -extensions ca_cert \
  -out out/2048-sha256-root.pem

# Generate the leaf private key
try openssl genrsa -out out/leaf_cert.key 2048

# Generate the leaf certificate request (CSR)
try openssl req \
  -new \
  -key out/leaf_cert.key \
  -out out/leaf_cert.req \
  -config leaf.cnf \
  -subj "/C=US/ST=California/L=Mountain View/O=QUIC Server/CN=127.0.0.1"

# Convert the leaf private key to PKCS#8 DER format (ensure it's unencrypted)
try openssl pkcs8 \
  -topk8 \
  -outform DER \
  -inform PEM \
  -in out/leaf_cert.key \
  -out out/leaf_cert.pkcs8 \
  -nocrypt

# Sign the leaf certificate with the root CA
try openssl ca \
  -batch \
  -days 3 \
  -extensions user_cert \
  -in out/leaf_cert.req \
  -out out/leaf_cert.pem \
  -config ca.cnf

# Verify the certificates
try openssl x509 -in out/leaf_cert.pem -text -noout
try openssl rsa -in out/leaf_cert.key -check
