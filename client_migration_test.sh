source migration_config.sh

# QUIC server / client configuration
./bazel-bin/quiche/quic_client --disable_certificate_verification https://$SERVER_HOST:$SERVER_PORT --main_path=$MAIN_IF --alt_path=$ALT_IF