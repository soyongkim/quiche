source migration_config.sh

# QUIC server / client configuration
./bazel-bin/quiche/quic_client --disable_certificate_verification --host=51.140.54.218 https://$SERVER_HOST:$SERVER_PORT --interface_name=$MAIN_IF --alt_interface_name=$ALT_IF