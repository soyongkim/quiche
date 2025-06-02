# QUIC server / client configuration
source config.sh

./bazel-bin/quiche/quic_client --disable_certificate_verification https://$SERVER_HOST:$SERVER_PORT