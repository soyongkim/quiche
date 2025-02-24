# quic build results
# Usage: ./send_output.sh <ip_address>
scp -i ~/.ssh/soyong_ssh_key -r bazel-bin root@$1:/root/Workspace/quiche_build/bazel-bin

# running scripts 
scp -i ~/.ssh/soyong_ssh_key quic_server.sh quic_client.sh masque_proxy.sh root@$1:/root/Workspace/quiche_server

# quic server requirements
scp -i ~/.ssh/soyong_ssh_key -r certs quic-data root@$1:/root/Workspace/quiche_server 