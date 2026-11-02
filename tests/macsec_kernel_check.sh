#!/bin/bash
set -euo pipefail

OUT=${1:?rendered config dir}
HERE=$(cd "$(dirname "$0")" && pwd)
PROBE="python3 $HERE/macsec_probe.py"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends nftables iproute2 python3 wpasupplicant >/dev/null 2>&1

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

ip netns add peer
ip netns add guarded
ip link add vpeer netns peer type veth peer name vguard netns guarded
ip -n peer link set vpeer up
ip -n guarded link set vguard up
ip -n peer link set lo up
ip -n guarded link set lo up
PEER_MAC=$(ip -n peer -br link show vpeer | awk '{print $3}')
GUARD_MAC=$(ip -n guarded -br link show vguard | awk '{print $3}')

probe_table() {
  local ns=$1 dev=$2 prio=$3 chain=$4
  local rules=""
  for t in "0x0800 ipv4" "0x0806 arp" "0x86dd ipv6" "0x8100 vlan" "0x88a8 qinq" "0x88cc lldp" "0x888e eapol" "0x88e5 macsec"; do
    set -- $t
    rules+="    ether type $1 counter comment \"$2\""$'\n'
  done
  ip netns exec "$ns" nft -f - << EOF
table netdev probe {
  chain $chain {
    type filter hook ingress device "$dev" priority $prio; policy accept;
$rules  }
}
EOF
}

expect_only_mka_macsec() {
  local label=$1 counts=$2 arrived=$3
  python3 - "$label" "$counts" "$arrived" << 'EOF'
import json, sys
label, counts, arrived = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
allowed = {"eapol", "macsec"}
for kind, n in arrived.items():
    if n == 0:
        sys.exit(f"{label}: no {kind} frames arrived, test is not measuring anything")
for kind, n in counts.items():
    if kind in allowed and n == 0:
        sys.exit(f"{label}: guard dropped {kind}")
    if kind not in allowed and n != 0:
        sys.exit(f"{label}: guard passed {n} {kind} frames")
print(f"PASS: {label}: only EAPOL and MACsec pass {counts}")
EOF
}

ip netns exec guarded nft -f "$OUT/guard.nft"
ip netns exec guarded nft -f "$OUT/guard.nft" || fail "guard re-apply is not idempotent"
pass "guard applies twice (atomic replace)"
probe_table guarded vguard -600 before
ip netns exec guarded nft add chain netdev probe after "{ type filter hook ingress device \"vguard\" priority -400; policy accept; }"
for t in "0x0800 ipv4" "0x0806 arp" "0x86dd ipv6" "0x8100 vlan" "0x88a8 qinq" "0x88cc lldp" "0x888e eapol" "0x88e5 macsec"; do
  set -- $t
  ip netns exec guarded nft add rule netdev probe after ether type "$1" counter comment "\"$2\""
done
ip netns exec peer $PROBE send vpeer "$GUARD_MAC"
before=$(ip netns exec guarded $PROBE counters probe before)
after=$(ip netns exec guarded $PROBE counters probe after)
expect_only_mka_macsec "ingress" "$after" "$before"

ip -n guarded addr add 10.66.0.2/24 dev vguard
ip -n peer addr add 10.66.0.1/24 dev vpeer
if ip netns exec peer ping -c 2 -W 1 10.66.0.2 >/dev/null 2>&1; then
  fail "plaintext ping crossed the guarded uplink"
fi
pass "plaintext IPv4 to an addressed, guarded uplink is dropped"

ip netns exec peer nft delete table netdev probe 2>/dev/null || true
probe_table peer vpeer -600 arrived
ip netns exec guarded $PROBE send vguard "$PEER_MAC"
arrived=$(ip netns exec peer $PROBE counters probe arrived)
expect_only_mka_macsec "egress" "$arrived" '{"eapol": 3, "macsec": 3}'

ip netns exec guarded nft -f "$OUT/guard_ingress.nft"
if ip netns exec guarded nft list table netdev mesh_macsec_guard | grep -q egress; then
  fail "ingress-only guard left an egress chain"
fi
ip netns exec guarded nft -f "$OUT/guard.nft"
pass "guard switches between ingress-only and ingress+egress"

ip netns add client
ip netns add server
ip netns add bridge
ip -n bridge link add br0 type bridge
ip -n bridge link set br0 up
for side in client server; do
  ip link add "v$side" netns "$side" type veth peer name "p$side" netns bridge
  ip -n bridge link set "p$side" master br0
  ip -n bridge link set "p$side" up
  ip -n "$side" link set "v$side" up
  ip -n "$side" link set lo up
done
ip -n client addr add 10.77.0.1/24 dev vclient
ip -n server addr add 10.77.0.2/24 dev vserver
ip -n client addr add fd77::1/64 dev vclient nodad
ip -n server addr add fd77::2/64 dev vserver nodad

measure() {
  local addr=$1 port=$2
  ip netns exec server $PROBE serve "$addr" "$port" > /tmp/serve.out &
  local pid=$!
  local client
  client=$(ip netns exec client $PROBE connect "$addr" "$port")
  wait $pid
  echo "$(cat /tmp/serve.out) $client"
}

read -r base4_s base4_c < <(measure 10.77.0.2 7001)
read -r base6_s base6_c < <(measure fd77::2 7002)
ip netns exec bridge nft -f "$OUT/mss.nft"
read -r clamp4_s clamp4_c < <(measure 10.77.0.2 7003)
read -r clamp6_s clamp6_c < <(measure fd77::2 7004)
echo "MSS v4 unclamped server/client $base4_s/$base4_c, clamped $clamp4_s/$clamp4_c"
echo "MSS v6 unclamped server/client $base6_s/$base6_c, clamped $clamp6_s/$clamp6_c"
[ "$base4_s" -gt 1428 ] || fail "baseline IPv4 MSS already small ($base4_s); test not meaningful"
[ "$clamp4_s" -le 1428 ] && [ "$clamp4_c" -le 1428 ] || fail "IPv4 SYN/SYN-ACK not clamped to 1428"
[ "$clamp6_s" -le 1408 ] && [ "$clamp6_c" -le 1408 ] || fail "IPv6 SYN/SYN-ACK not clamped to 1408"
pass "bridge MSS clamp fits TCP in a 1468 byte MACsec link (IPv4 and IPv6, both directions)"

for conf in wpa_leaf.conf wpa_main.conf; do
  log=$(timeout 5 wpa_supplicant -dd -D macsec_linux -i lo -c "$OUT/$conf" 2>&1 || true)
  if echo "$log" | grep -qiE "unknown network field|failed to parse|Invalid|Line [0-9]+: "; then
    echo "$log" | grep -iE "line|unknown|invalid|failed" >&2
    fail "wpa_supplicant rejected $conf"
  fi
  echo "$log" | grep -q "MKA-CAK - hexdump(len=32)" || fail "$conf: 256-bit CAK not loaded"
  echo "$log" | grep -q "MKA-CKN - hexdump(len=16)" || fail "$conf: CKN not loaded"
  pass "wpa_supplicant $(wpa_supplicant -v | head -1 | awk '{print $2}') parses $conf"
done

echo "ALL KERNEL CHECKS PASSED"
