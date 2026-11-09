#!/bin/bash
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TEST_DIR=$(mktemp -d)
BRIF="$TEST_DIR/brif"
trap 'mkdir -p "$BRIF"; touch "$BRIF/macsec0"; sleep 1.2; rm -rf "$TEST_DIR"' EXIT

FAKE_BIN="$TEST_DIR/bin"
COMMAND_LOG="$TEST_DIR/commands.log"
NFT_INPUT="$TEST_DIR/nft.input"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/command" << 'FAKE'
#!/bin/bash
name=$(basename "$0")
printf '%s %s\n' "$name" "$*" >> "$COMMAND_LOG"
if [ "$name" = nft ] && [ "${1:-}" = -f ]; then
  cat >> "$NFT_INPUT"
fi
case "$*" in
  "-br link show dev eth1") printf '%s\n' "eth1 UP 7a:11:22:33:44:55" ;;
  "-br link show dev br0") printf '%s\n' "br0 DOWN 9a:66:77:88:99:aa" ;;
esac
FAKE
chmod +x "$FAKE_BIN/command"
for command in ip iptables iptables-legacy conntrack sysctl dhclient nft; do
  ln -s command "$FAKE_BIN/$command"
done

CONFIG="$TEST_DIR/interfaces.json"
printf '%s\n' '[{"Name":"eth1","Type":"Uplink","Enabled":true,"MACOverride":"00:11:22:33:44:55"}]' > "$CONFIG"
FLAG="$TEST_DIR/macsec_required"

run_rules() {
  : > "$COMMAND_LOG"
  : > "$NFT_INPUT"
  (
    cd "$TEST_DIR"
    PATH="$FAKE_BIN:$PATH" COMMAND_LOG="$COMMAND_LOG" NFT_INPUT="$NFT_INPUT" \
      MESH_MACSEC_FLAG="$FLAG" MESH_BRIF_DIR="$BRIF" \
      WANIF=eth1 LANIF='' DOCKERIF=docker0 DOCKERNET=172.17.0.0/16 INTERFACES_CONFIG="$CONFIG" \
      bash "$REPO_DIR/mesh_rules.sh" > /dev/null
  )
}

fail() {
  echo "FAIL: $*" >&2
  cat "$COMMAND_LOG" >&2
  exit 1
}

wait_for_log() {
  local line=$1
  for _ in $(seq 1 50); do
    grep -Fxq "$line" "$COMMAND_LOG" && return 0
    sleep 0.1
  done
  return 1
}

rm -f "$FLAG"
run_rules
grep -Fxq 'ip link set dev eth1 master br0' "$COMMAND_LOG" || fail "plaintext uplink not bridged"
grep -Fxq 'ip link set dev eth1 up' "$COMMAND_LOG" || fail "plaintext uplink not brought up"
grep -Fxq 'dhclient br0' "$COMMAND_LOG" || fail "plaintext DHCP not started"
grep -q mesh_macsec_guard "$NFT_INPUT" && fail "guard installed without MACsec"
grep -Fq 'nomaster' "$COMMAND_LOG" && fail "plaintext uplink unbridged"

touch "$FLAG"
mkdir -p "$BRIF"
rm -f "$BRIF"/*
run_rules
grep -Fxq 'ip link set dev eth1 master br0' "$COMMAND_LOG" && fail "raw uplink bridged while MACsec is required"
grep -Fxq 'ip link set dev eth1 nomaster' "$COMMAND_LOG" || fail "raw uplink not removed from the bridge"
grep -Fxq 'sysctl -w net/ipv6/conf/eth1/disable_ipv6=1' "$COMMAND_LOG" || fail "IPv6 left enabled on raw uplink"
grep -Fxq 'ip link set dev eth1 up' "$COMMAND_LOG" && fail "raw uplink brought up before the plugin guards it"
grep -Fq 'table netdev mesh_macsec_guard' "$NFT_INPUT" || fail "guard table missing"
grep -Fq 'type filter hook ingress device "eth1" priority -500; policy drop;' "$NFT_INPUT" || fail "guard does not drop by default on eth1"
grep -Fq 'ether type { 0x888e, 0x88e5, 0x88b5 } accept' "$NFT_INPUT" || fail "guard does not admit MKA, MACsec and control frames"
guard_accepts=$(sed -n '/table netdev mesh_macsec_guard/,/^}/p' "$NFT_INPUT" | grep -c accept)
[ "$guard_accepts" -eq 1 ] || fail "guard accepts more than MKA and MACsec"
guard_line=$(grep -n 'nft -f -' "$COMMAND_LOG" | tail -1 | cut -d: -f1)
accept_line=$(grep -nFx 'iptables -P INPUT ACCEPT' "$COMMAND_LOG" | cut -d: -f1)
[ "$guard_line" -lt "$accept_line" ] || fail "INPUT opened before the guard"
sleep 0.5
grep -Fxq 'dhclient br0' "$COMMAND_LOG" && fail "DHCP started before a secured uplink existed"

touch "$BRIF/macsec0"
wait_for_log 'dhclient br0' || fail "DHCP not started once the MACsec port was bridged"

rm -f "$BRIF"/*
touch "$BRIF/wlan0.4096"
run_rules
sleep 0.5
grep -Fxq 'dhclient br0' "$COMMAND_LOG" && fail "an AP/VLAN port was mistaken for the uplink"
touch "$BRIF/macsec3"
wait_for_log 'dhclient br0' || fail "DHCP not started for macsec3"

rm -f "$BRIF"/*
run_rules
touch "$BRIF/eth1"
wait_for_log 'dhclient br0' || fail "DHCP not started after revert to plaintext"

rm -f "$BRIF"/*
run_rules
touch "$BRIF/mshvx0"
wait_for_log 'dhclient br0' || fail "DHCP not started once the WireGuard VXLAN port was bridged"

echo "mesh_rules MACsec tests passed"
