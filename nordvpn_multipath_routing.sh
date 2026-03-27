#!/usr/bin/env bash
#
# nordvpn_multipath_routing.sh
#
# Usage examples
#   sudo ./nordvpn_multipath_routing.sh eth0 --ssh eth1
#   sudo ./nordvpn_multipath_routing.sh eth0 wlan0 --ssh eth1
#
# What it does
#   • For every interface you list *before* --ssh  ➜  traffic that
#     originates with that interface’s **source-IP** bypasses NordVPN
#     and goes out over that interface directly.
#   • --ssh <iface>                                ➜  keeps inbound
#     SSH on that interface working (and lets any
#     packets *from* that IP bypass the VPN too).
#   • Everything else (un-marked) continues to be
#     forced through nordlynx because of the rule
#     “not fwmark 0xe1f1 lookup 205” that NordVPN
#     installed for its kill-switch.
#
# Tested on Ubuntu 22.04 with NordVPN v3.17+ and
# classic iptables (not nftables).
# ------------------------------------------------------------

set -euo pipefail

die()   { echo "❌ $*" >&2; exit 1; }
log()   { echo "▶ $*"; }
root()  { [[ $EUID -eq 0 ]] || die "Run as root"; }

root

#──────────── Parse arguments ────────────────────────────────
direct_ifaces=()
ssh_iface=""

while (( $# )); do
    case "$1" in
        --ssh)
            shift
            [[ $# -ge 1 ]] || die "--ssh needs an interface name"
            ssh_iface=$1
            ;;
        *)
            direct_ifaces+=("$1")
            ;;
    esac
    shift
done

(( ${#direct_ifaces[@]} >= 1 && ${#direct_ifaces[@]} <= 2 )) \
    || die "Specify one or two direct interfaces before --ssh"

[[ -n $ssh_iface ]] || die "Missing --ssh <iface>"

# Ensure interfaces exist
for i in "${direct_ifaces[@]}" "$ssh_iface" nordlynx; do
    ip link show "$i" &>/dev/null || die "Interface $i not found"
done

#──────────── Gather interface data ──────────────────────────
get_ipv4() { ip -4 -o addr show "$1" | awk '{print $4}' | cut -d/ -f1; }
get_gw()   { ip route show default 0.0.0.0/0 dev "$1" \
               | awk '/default/ {print $3}'; }

declare -A IP GW
for i in "${direct_ifaces[@]}"; do
    IP[$i]=$(get_ipv4 "$i")  || die "No IPv4 on $i"
    GW[$i]=$(get_gw   "$i")  || die "No default GW on $i"
done
IP[$ssh_iface]=$(get_ipv4 "$ssh_iface") || die "No IPv4 on $ssh_iface"

# nordlynx source-IP (for optional tests)
WG_IP=$(get_ipv4 nordlynx)

log "Direct interfaces  : ${direct_ifaces[*]}"
log "SSH interface      : $ssh_iface"
log "nordlynx address   : $WG_IP"
for i in "${!IP[@]}"; do log "$i address       : ${IP[$i]} (gw ${GW[$i]:-N/A})"; done

#──────────── Add custom routing tables ──────────────────────
table_base=100
rt_tables=/etc/iproute2/rt_tables

add_table_line() {
    # id $1 name $2
    grep -qE "^$1[[:space:]]+$2$" "$rt_tables" 2>/dev/null \
        || echo "$1 $2" >> "$rt_tables"
}

for idx in "${!direct_ifaces[@]}"; do
    iface=${direct_ifaces[$idx]}
    tid=$((table_base + idx))
    tname="nvpn_${iface}"
    add_table_line "$tid" "$tname"

    ip route flush table "$tid" &>/dev/null || true
    ip route add default via "${GW[$iface]}" dev "$iface" table "$tid"
    # add connected networks so replies keep source-IP
    ip route show dev "$iface" proto kernel \
        | while read -r net _; do
              ip route add "$net" dev "$iface" table "$tid"
          done
    log "Table $tid ($tname) → $iface ready"
done

#──────────── Policy rules (priority 1000+) ──────────────────
rule_prio=1000
for idx in "${!direct_ifaces[@]}"; do
    iface=${direct_ifaces[$idx]}
    tid=$((table_base + idx))
    ip rule del prio $rule_prio 2>/dev/null || true
    ip rule add prio $rule_prio from "${IP[$iface]}/32" lookup "$tid"
    ((rule_prio++))
done
# SSH interface rule
ip rule del prio $rule_prio 2>/dev/null || true
ip rule add prio $rule_prio from "${IP[$ssh_iface]}/32" lookup main
log "Policy rules installed"

#──────────── iptables marks & accepts ───────────────────────
mark=0xe1f1

for src in "${IP[@]}"; do
    iptables -t mangle -C OUTPUT -s "$src" -j MARK --set-mark $mark 2>/dev/null \
        || iptables -t mangle -A OUTPUT -s "$src" -j MARK --set-mark $mark
done

# Ensure one global ACCEPT for the mark (if not already)
iptables -C OUTPUT -m connmark --mark $mark -j ACCEPT 2>/dev/null \
    || iptables -A OUTPUT -m connmark --mark $mark -j ACCEPT

# SSH inbound keep-alive
iptables -C INPUT -i "$ssh_iface" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -i "$ssh_iface" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -i "$ssh_iface" -p tcp --dport 22 -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -i "$ssh_iface" -p tcp --dport 22 -j ACCEPT

log "iptables rules added (mark $mark)"

#──────────── Show summary ───────────────────────────────────
echo
log "Resulting rpdb:"
ip rule show | head -n 15
echo
log "Test examples:"
echo "  curl --interface ${IP[${direct_ifaces[0]}]} https://ipwho.is"
[[ ${#direct_ifaces[@]} -eq 2 ]] && \
echo "  curl --interface ${IP[${direct_ifaces[1]}]} https://ipwho.is"
echo "  curl --interface $WG_IP https://ipwho.is"
echo
log "Done ✔ – split-tunnel ready."
