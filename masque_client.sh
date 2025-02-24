# QUIC server / client configuration
source config.sh

./bazel-bin/quiche/masque_client --disable_certificate_verification $MASQUE_HOST:$MASQUE_PORT https://$SERVER_HOST:$SERVER_PORT