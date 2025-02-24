# QUIC server / client configuration
source config.sh

./bazel-bin/quiche/quic_server  --quic_response_cache_dir=quic-data/$SERVER_HOST --certificate_file=certs/out/leaf_cert.pem --key_file=certs/out/leaf_cert.pkcs8