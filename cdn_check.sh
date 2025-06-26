#!/bin/bash
# script.sh: Identify possible CDN provider for a given domain.

if [ $# -ne 1 ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

DOMAIN=$1

echo "🔍 Checking CDN for: $DOMAIN"
echo "----------------------------------"

# 1️⃣ Resolve the domain to an IP
IP=$(dig +short $DOMAIN | head -n 1)

if [ -z "$IP" ]; then
  echo "❌ Could not resolve IP for $DOMAIN"
  exit 1
fi

echo "✅ IP Address: $IP"

# 2️⃣ WHOIS lookup
echo "----------------------------------"
echo "📄 WHOIS Lookup:"
whois $IP | grep -E 'OrgName|Organization|netname|descr|owner' || echo "   (No WHOIS info found)"

# 3️⃣ ASN lookup via BGP
echo "----------------------------------"
echo "📡 ASN Info:"
curl -s "https://api.bgpview.io/ip/$IP" | jq '.data | {asn: .prefixes[0].asn.asn, name: .prefixes[0].asn.name}' || echo "   (No ASN info found)"

# 4️⃣ Reverse DNS lookup
echo "----------------------------------"
echo "🔎 Reverse DNS:"
PTR=$(dig +short -x $IP)
if [ -n "$PTR" ]; then
  echo "PTR Record: $PTR"
else
  echo "   (No PTR record found)"
fi

echo "----------------------------------"
echo "🚀 Analysis Completed!"
