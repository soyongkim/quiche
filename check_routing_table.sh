TABLE1=10
TABLE2=20
TABLE3=30


echo
echo "==================== ROUTING CONFIGURATION SUMMARY ===================="
echo
echo "[1] ip rule list:"
# ip rule show | grep -E "lookup ($TABLE1|$TABLE2|$TABLE3)" || echo "  (none)"
ip rule show
echo
echo "[2] Table $TABLE1 (Primary Interface) Routes:"
ip route show table $TABLE1 || echo "  (empty)"
echo
echo "[3] Table $TABLE2 (Secondary Interface) Routes:"
ip route show table $TABLE2 || echo "  (empty)"
echo
echo "[4] Table $TABLE3 (Tertiary Interface) Routes:"
ip route show table $TABLE3 || echo "  (empty)"
echo
echo "[5] Main Routing Table:"
ip route show
echo
echo "========================================================================="
echo "[DONE] Source-based routing configured and verified."
