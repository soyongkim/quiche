source config.sh

# QUIC server / client configuration
./bazel-bin/quiche/quic_client  \
    --disable_certificate_verification \
    --server_connection_id_length=16 \
    --client_connection_id_length=8 \
    --initial_mtu=1200 \
    --interface_name=$MAIN_IF \
    --alt_interface_name=$ALT_IF \
    --quic_version=$QUIC_VERSION \
    https://$SERVER_HOST:$SERVER_PORT