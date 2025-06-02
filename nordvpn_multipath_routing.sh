# This script sets up multipath routing for NordVPN on Linux.

# Delete existing NordVPN firewall rules
sudo iptables -F

# Delete existing NordVPN routing rules
sudo ip rule del fwmark 0xe1f1


# NordVPN resolution configuration
# sudo resolvectl domain nordlynx "google.com"

#!/bin/bash

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <primary_interface> <secondary_interface> [tertiary_interface]"
  exit 1
fi

MAIN_IF=$1
SECOND_IF=$2
if [[ $# -eq 3 ]]; then
  THIRD_IF=$3
fi

# Define table numbers
TABLE1=10
TABLE2=20
TABLE3=30

get_ip() {
  local IFACE=$1
  ip -4 addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1
}

# Get dynamic IPs
MAIN_IP=$(get_ip "$MAIN_IF")
SECOND_IP=$(get_ip "$SECOND_IF")
if [[ -n "$THIRD_IF" ]]; then
  THIRD_IP=$(get_ip "$THIRD_IF")
fi

if [[ -z "$MAIN_IP" || -z "$SECOND_IP" || ( -n "$THIRD_IF" && -z "$THIRD_IP" ) ]]; then
  echo "[ERROR] Could not find IP for one of the interfaces"
  exit 1
fi

echo "[INFO] MAIN IP  = $MAIN_IP on $MAIN_IF"
echo "[INFO] SECOND IP  = $SECOND_IP on $SECOND_IF"
if [[ -n "$THIRD_IF" ]]; then
  echo "[INFO] THIRD IP = $THIRD_IP on $THIRD_IF"
fi

# Remove ALL ip rules referencing table numbers (10, 20, 30)
for table in $TABLE1 $TABLE2 $TABLE3; do
  echo "[INFO] Cleaning existing ip rules for table $table..."
  ip rule show | grep "lookup $table" | while read -r rule; do
    PRIO=$(echo "$rule" | awk -F: '{print $1}')
    sudo ip rule del priority "$PRIO"
    echo "  Deleted rule: $rule"
  done
  sudo ip route flush table "$table"
done

# Add new IP rules
sudo ip rule add from "$MAIN_IP" table $TABLE1
sudo ip rule add from "$SECOND_IP" table $TABLE2
if [[ -n "$THIRD_IF" ]]; then
  sudo ip rule add from "$THIRD_IP" table $TABLE3
fi

# Copy routes associated with the interface into the custom table
copy_routes() {
  local IFACE=$1
  local TABLE=$2
  echo "[INFO] Copying routes from main table for $IFACE into table $TABLE..."
  ip route show table main | grep "dev $IFACE" | while read -r route; do
    echo "  + $route"
    sudo ip route add $route table $TABLE
  done
}

# Remove routes from the main table if they belong to a specific interface
remove_main_table_routes() {
  local IFACE=$1
  echo "[INFO] Removing routes from main table for $IFACE..."
  ip route show table main | grep "dev $IFACE" | while read -r route; do
    echo "  - Removing from main table: $route"
    sudo ip route del $route
  done
}


# Modify route metric to deprioritize secondary and tertiary interfaces
modify_route_metric() {
  local IFACE=$1
  local METRIC=200  # Set a higher metric for secondary/tertiary interfaces

  echo "[INFO] Modifying metric for $IFACE to deprioritize it..."

  # Loop through the routes for the specified interface
  ip route show table main | grep "dev $IFACE" | while read -r route; do
    # If the route is the default route, apply the metric change
    if [[ $route == *"default"* ]]; then
      # Modify the default route to have a higher metric for secondary/tertiary interfaces
      echo "  - Modifying default route for $IFACE to metric $METRIC"
      sudo ip route del $route
      sudo ip route add $route metric $METRIC
    else
      # For non-default routes, modify the metric to deprioritize the interface
      if [[ $route == *"metric"* ]]; then
        # Remove the old route
        ROUTE_DEST=$(echo "$route" | awk '{print $1}')
        echo "  - Removing previous route without the updated metric: $route"
        sudo ip route del $ROUTE_DEST

        # Modify route metric and add back with the new metric
        MOD_ROUTE=$(echo "$route" | sed -E "s/metric [0-9]+/metric $METRIC/")
        echo "  + Adding updated route: $MOD_ROUTE"
        sudo ip route add $MOD_ROUTE
      else
        # If no metric was set, add the route with the new metric
        MOD_ROUTE="$route metric $METRIC"
        echo "  + Adding route with new metric: $MOD_ROUTE"
        sudo ip route add $MOD_ROUTE
      fi
    fi
  done
}

# Copy and clean up routes in the correct order
copy_routes "$MAIN_IF" $TABLE1
copy_routes "$SECOND_IF" $TABLE2
if [[ -n "$THIRD_IF" ]]; then
  copy_routes "$THIRD_IF" $TABLE3
fi


sudo ip route add default dev nordlynx table 20

echo
echo "==================== ROUTING CONFIGURATION SUMMARY ===================="
echo
echo "[1] ip rule list:"
ip rule show | grep -E "lookup ($TABLE1|$TABLE2|$TABLE3)" || echo "  (none)"
echo
echo "[2] Table $TABLE1 (Primary Interface) Routes:"
ip route show table $TABLE1 || echo "  (empty)"
echo
echo "[3] Table $TABLE2 (Secondary Interface) Routes:"
ip route show table $TABLE2 || echo "  (empty)"
if [[ -n "$THIRD_IF" ]]; then
  echo
  echo "[4] Table $TABLE3 (Tertiary Interface) Routes:"
  ip route show table $TABLE3 || echo "  (empty)"
fi
echo
echo "[5] Main Routing Table:"
route -n
echo
echo "========================================================================="
echo "[DONE] Source-based routing configured and verified."
