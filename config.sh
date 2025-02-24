#!/bin/bash
# config.sh: Central configuration file for common settings

# for Deloyment
REMOTE_HOST= ("0.0.0.0" "0.0.0.0")
REMOTE_USER="root"
REMOTE_PATH="your/path/"
SSH_KEY_PATH="${HOME}/.ssh/your_private_key"

# QUIC server
SERVER_HOST="smalldragon.net"
SERVER_PORT="6121"

# MASQUE proxy
MASQUE_HOST="0.0.0.0"
MASQUE_PORT="9661"
