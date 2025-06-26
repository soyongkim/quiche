# QUIC server / client configuration
source config.sh

# ./bazel-bin/quiche/quic_client --disable_certificate_verification https://$SERVER_HOST:$SERVER_PORT


./bazel-bin/quiche/quic_client --disable_certificate_verification https://$1
# ./bazel-bin/quiche/quic_client --disable_certificate_verification https://$1 2>&1 | tee -a client_output.txt