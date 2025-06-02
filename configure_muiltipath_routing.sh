# #!/bin/bash

# WLAN_IF=$1
# TUN_IF=$2

# if [[ -z "$WLAN_IF" || -z "$TUN_IF" ]]; then
#   echo "Usage: $0 <wlan_interface> <tun_interface>"
#   exit 1
# fi

# # Get dynamic IPs
# UCL_IP=$(ip -4 addr show "$WLAN_IF" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
# VPN_IP=$(ip -4 addr show "$TUN_IF"  | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

# if [[ -z "$UCL_IP" || -z "$VPN_IP" ]]; then
#   echo "[ERROR] Could not find IP for one of the interfaces"
#   exit 1
# fi

# echo "[INFO] UCL IP  = $UCL_IP on $WLAN_IF"
# echo "[INFO] VPN IP  = $VPN_IP on $TUN_IF"

# # Remove ALL ip rules referencing table 130 or 10, regardless of source IP
# for table in 130 10; do
#   echo "[INFO] Cleaning existing ip rules for table $table..."
#   ip rule show | grep "lookup $table" | while read -r rule; do
#     PRIO=$(echo "$rule" | awk -F: '{print $1}')
#     sudo ip rule del priority "$PRIO"
#     echo "  Deleted rule: $rule"
#   done
#   sudo ip route flush table "$table"
# done

# # Add new rules
# sudo ip rule add from "$UCL_IP" table 130
# sudo ip rule add from "$VPN_IP" table 10

# # Copy routes associated with the interface into the custom table
# copy_routes() {
#   local IFACE=$1
#   local TABLE=$2
#   echo "[INFO] Copying routes from main table for $IFACE into table $TABLE..."

#   ip route show table main | grep "dev $IFACE" | while read -r route; do
#     echo "  + $route"
#     sudo ip route add $route table $TABLE
#   done
# }

# # Remove routes from main table if they belong to a specific interface
# remove_main_table_routes() {
#   local IFACE=$1
#   echo "[INFO] Removing routes from main table for $IFACE..."
#   ip route show table main | grep "dev $IFACE" | while read -r route; do
#     echo "  - Removing from main table: $route"
#     sudo ip route del $route
#   done
# }

# # Copy and clean up routes
# copy_routes "$WLAN_IF" 130
# copy_routes "$TUN_IF" 10

# # Remove copied VPN routes from the main table
# remove_main_table_routes "$TUN_IF"


# echo
# echo "==================== ROUTING CONFIGURATION SUMMARY ===================="
# echo
# echo "[1] ip rule list:"
# ip rule show | grep -E 'lookup (10|130)' || echo "  (none)"
# echo
# echo "[2] Table 130 (Wi-Fi) Routes:"
# ip route show table 130 || echo "  (empty)"
# echo
# echo "[3] Table 10 (VPN) Routes:"
# ip route show table 10 || echo "  (empty)"
# echo
# echo "[4] Main Routing Table:"
# ip route show
# echo
# echo "========================================================================="
# echo "[DONE] Source-based routing configured and verified."