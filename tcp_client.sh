source config.sh

./bazel-bin/quiche/proxy_tcp_client https://localhost:4433 --v=1 --disable_certificate_verification=true --connect_target=$SERVER_HOST:$SERVER_PORT