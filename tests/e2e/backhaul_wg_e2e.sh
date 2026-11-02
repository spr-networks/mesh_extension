#!/bin/bash
set -uo pipefail

REPO=${REPO:-/repo}
MESH=${MESH:-/e2e-bin/mesh}
E2E=$REPO/tests/e2e
W=/tmp/e2ewg
L=$W/leaf
M=$W/main
STA_MAC=02:5a:00:00:00:03
FAILED=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

dump() {
  echo "---- main log"; tail -30 $W/main.log
  echo "---- leaf log"; tail -30 $W/leaf.log
  ip netns exec main wg show 2>&1 | head -20
  ip netns exec leaf wg show 2>&1 | head -20
  ip -n leaf -o link show master br0
}

die() { echo "FAIL: $*"; dump; exit 1; }

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

api() {
  local prefix=$1 method=$2 path=$3 data=${4:-}
  curl -s -S --max-time 120 --fail-with-body --unix-socket "$prefix/state/plugins/mesh/socket" \
    -X "$method" ${data:+-d "$data"} "http://localhost$path"
}

wait_for() {
  local secs=$1; shift
  for _ in $(seq 1 "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

field() {
  api "$1" GET /macsec/status | python3 -c "import json,sys; s=json.load(sys.stdin); print(s['Links'][0].get('$2','') if s['Links'] else '')"
}

bridge_state() { echo "br=$(ip -n main -br link show dev mshbr0 2>&1 | awk '{print $3}') eth1=$(ip -n main -br link show dev eth1 | awk '{print $3}') tables=$(nsx main nft list tables 2>&1 | tr '\n' ' ')"; }
main_bridge_ok() {
  local port; port=$(ip -n main -d link show dev "$1")
  [[ $port == *"master mshbr0"* && $port == *"isolated on"* ]] \
    && [ "$(ip -n main -br link show dev mshbr0 | awk '{print $3}')" = "$(ip -n main -br link show dev eth1 | awk '{print $3}')" ] \
    && [[ $(nsx main nft list table bridge mesh_bridge_guard) == *"ether saddr"* ]]
}
leaf_secured() { [ "$(field $L Secured)" = "True" ]; }
main_secured() { [ "$(field $M Secured)" = "True" ]; }
main_underlay() { [ "$(field $M Underlay)" = "$1" ]; }
ports() { ip -n leaf -o link show master br0 | awk -F': ' '{print $2}' | cut -d@ -f1; }
mtu() { ip -n "$1" -j link show dev "$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["mtu"])'; }
station_ping() { nsx sta ping -c "${1:-2}" -W 2 "${@:2}" 10.88.0.1 >/dev/null 2>&1; }
capture_start() { nsx atk tcpdump -i eth9 -U -w "$1" >/dev/null 2>&1 & CAPTURE=$!; sleep 2; }
capture_stop() { sleep 1; kill $CAPTURE 2>/dev/null; wait $CAPTURE 2>/dev/null; }

for m in wireguard vxlan veth bridge nf_tables; do modprobe $m 2>/dev/null; done
rm -rf $W
mkdir -p $W/fakebin $L/configs/base $L/configs/mesh $L/configs/auth $L/state/plugins/mesh \
  $M/configs/base $M/configs/mesh $M/configs/auth $M/state/plugins/mesh
for c in dhclient iptables iptables-legacy conntrack; do printf '#!/bin/sh\nexit 0\n' > $W/fakebin/$c; chmod +x $W/fakebin/$c; done
TOKEN=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')

for ns in sw main leaf sta atk lan; do ip netns add $ns; ip -n $ns link set lo up; done
for ns in main leaf sta atk lan; do nsx $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; done
ip -n sw link add sw0 type bridge ageing_time 0
ip -n sw link set sw0 mtu 9000
ip -n sw link set sw0 up
ip link add p-main netns sw type veth peer name eth1 netns main
ip link add p-leaf netns sw type veth peer name eth0 netns leaf
ip link add p-atk netns sw type veth peer name eth9 netns atk
ip link add p-lan netns sw type veth peer name eth5 netns lan
for p in p-main p-leaf p-atk p-lan; do
  ip -n sw link set $p mtu 9000
  ip -n sw link set $p master sw0
  ip -n sw link set $p up
done
ip -n main link set eth1 up
ip -n main addr add 10.88.0.1/24 dev eth1
ip -n main addr add 10.89.0.1/24 dev eth1
ip -n lan link set eth5 up
ip -n lan addr add 10.89.0.2/24 dev eth5
ip -n atk link set eth9 up
ip link add wlan0.4096 netns leaf type veth peer name sta0 netns sta
ip -n sta link set sta0 address $STA_MAC
ip -n sta link set sta0 up
ip -n sta addr add 10.88.0.3/24 dev sta0

printf '[{"Name":"PLUS-MESH-API-DOWNHAUL-TOKEN","Token":"%s"}]' "$TOKEN" > $L/configs/auth/auth_tokens.json
echo '[]' > $M/configs/auth/auth_tokens.json
touch $L/state/plugins/mesh/enabled
echo 'WANIF=eth0' > $L/configs/base/config.sh
echo 'WANIF=wan0' > $M/configs/base/config.sh

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=spr-e2e-ca -keyout $W/ca.key -out $W/ca.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=10.88.0.2 -keyout $W/leaf.key -out $W/leaf.csr 2>/dev/null
echo 'subjectAltName=IP:10.88.0.2' > $W/ext
openssl x509 -req -in $W/leaf.csr -CA $W/ca.crt -CAkey $W/ca.key -CAcreateserial -days 2 -extfile $W/ext -out $W/leaf.crt 2>/dev/null
python3 -c 'import json,sys; print(json.dumps({"LeafRouters":[{"APIToken":sys.argv[1],"IP":"10.88.0.2","TLSCA":open(sys.argv[2]).read()}]}))' \
  "$TOKEN" $W/ca.crt > $M/configs/mesh/config.json

nsx leaf env PATH=$W/fakebin:$PATH WANIF=eth0 LANIF= DOCKERIF=docker0 DOCKERNET=172.17.0.0/16 \
  INTERFACES_CONFIG=/nonexistent MESH_MACSEC_FLAG=$L/configs/base/mesh_macsec_required \
  bash $REPO/mesh_rules.sh > $W/rules.log 2>&1
nsx leaf ip addr add 10.88.0.2/24 dev br0
nsx leaf ip link set wlan0.4096 up
LEAF_BR_MAC=$(ip -n leaf -br link show dev br0 | awk '{print $3}')

nsx leaf env TEST_PREFIX=$L WANIF=eth0 $MESH > $W/leaf.log 2>&1 &
LEAF_PLUGIN=$!
nsx main env TEST_PREFIX=$M WANIF=wan0 $MESH > $W/main.log 2>&1 &
nsx leaf python3 $E2E/leaf_api_proxy.py 10.88.0.2 "$TOKEN" $L/state/plugins/mesh/socket $W/leaf.crt $W/leaf.key > $W/proxy.log 2>&1 &
wait_for 30 test -S $L/state/plugins/mesh/socket -a -S $M/state/plugins/mesh/socket || die "plugins did not start"
api $L PUT /stationConnect "{\"Event\":\"AP-STA-CONNECTED\",\"Iface\":\"wlan0.4096\",\"Mac\":\"$STA_MAC\"}" >/dev/null
wait_for 20 station_ping 1 || die "station cannot reach main over the plaintext uplink"

ENABLE=$(api $M PUT /leafRouter/backhaul '{"IP":"10.88.0.2","Enable":true}') || die "WireGuard enable failed: $ENABLE"
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["LeafRouters"][0]["MACsec"]["Mode"])' $M/configs/mesh/config.json)" = wireguard ] \
  && pass "enable defaults to the WireGuard backhaul" || fail "enable did not choose WireGuard"

wait_for 120 leaf_secured || die "WireGuard tunnel never came up on the node"
wait_for 60 main_secured || die "WireGuard tunnel never came up on the main router"
MAIN_VX=$(field $M Member)
pass "WireGuard tunnel up, main router VXLAN interface $MAIN_VX"
[ "$(field $M Interface)" = mshbr0 ] && main_bridge_ok $MAIN_VX \
  && pass "main router bridges $MAIN_VX into mshbr0, isolated, with eth1's MAC and the node MAC guard" \
  || fail "main bridge: interface=$(field $M Interface) $(bridge_state) port=$(ip -n main -d link show dev $MAIN_VX | grep -o 'master [^ ]*\|isolated [a-z]*' | tr '\n' ' ')"
nsx main ip addr del 10.88.0.1/24 dev eth1
nsx main ip addr add 10.88.0.1/24 dev mshbr0

ports | grep -qx eth0 && fail "raw uplink still bridged" || pass "raw uplink removed from br0"
ports | grep -qx mshvx0 && pass "VXLAN port bridged into br0" || fail "VXLAN port not bridged"
GUARD=$(nsx leaf nft list table netdev mesh_macsec_guard 2>&1)
echo "$GUARD" | grep -q "udp sport 51821" && pass "WireGuard guard installed on the node" || fail "guard missing: $GUARD"

wait_for 30 station_ping 1 || fail "station cannot reach main over WireGuard without jumbo frames"
[ "$(mtu main eth1)" = 1500 ] && [ "$(mtu leaf eth0)" = 1500 ] && [ "$(mtu leaf mshvx0)" = 1390 ] \
  && wait_for 30 nsx leaf nft list table bridge mesh_macsec_mss && station_ping 2 -M do -s 1362 \
  && ! station_ping 1 -M do -s 1363 \
  && pass "jumbo frames off by default: ports stay at 1500, stations get 1390 with the MSS clamp" \
  || fail "jumbo off: main eth1=$(mtu main eth1) leaf eth0=$(mtu leaf eth0) vx=$(mtu leaf mshvx0)"
ip -n sta route get 10.88.0.1 | grep -q 'mtu 1390' \
  && pass "stations learn the 1390 byte path MTU from the bridged VXLAN port" \
  || fail "no path MTU feedback to stations: $(ip -n sta route get 10.88.0.1 | tr '\n' ' ')"
nsx sta ip route flush cache
JUMBO=$(api $M PUT /leafRouter/backhaul/jumbo '{"IP":"10.88.0.2","Jumbo":true}') || fail "jumbo on failed: $JUMBO"

wait_for 120 main_underlay 9000 && pass "jumbo frame test found a 9000 byte path" || fail "jumbo frame test result: $(field $M Underlay)"
wait_for 30 sh -c "[ \"\$(ip -n leaf -j link show dev mshvx0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0][\"mtu\"])')\" = 1500 ]" \
  && [ "$(mtu main $MAIN_VX)" = 1500 ] && [ "$(mtu main eth1)" = 9000 ] && [ "$(mtu leaf eth0)" = 9000 ] \
  && pass "jumbo underlay carries full 1500 byte frames for stations" || fail "MTUs main eth1=$(mtu main eth1) vx=$(mtu main $MAIN_VX) leaf eth0=$(mtu leaf eth0) vx=$(mtu leaf mshvx0)"
nsx leaf nft list table bridge mesh_macsec_mss >/dev/null 2>&1 && fail "MSS clamp left on a jumbo link" || pass "no MSS clamp on a jumbo link"
wait_for 15 sh -c "ip -n main -4 route show dev eth1 | grep '^10.89.0.0/24' | grep -q 'mtu lock 1500'" \
  && ! nsx main ping -c 1 -W 1 -M do -s 1473 10.89.0.2 >/dev/null 2>&1 \
  && nsx main ping -c 2 -W 2 -s 1572 10.89.0.2 >/dev/null 2>&1 \
  && pass "plaintext LAN host on the 9000 byte parent still gets at most 1500 byte packets" || fail "plaintext LAN route MTU not pinned"

wait_for 30 station_ping 1 || fail "station cannot reach main over WireGuard"
station_ping 2 -M do -s 1472 && pass "AP/VLAN station sends full 1500 byte packets over WireGuard" || fail "1500 byte DF ping failed"

LEAF_ETH0_MAC=$(ip -n leaf -br link show dev eth0 | awk '{print $3}')
capture_start $W/enc.pcap
station_ping 5 -i 0.2
station_ping 2 -M do -s 1472
capture_stop
STA_SEEN=$(tcpdump -r $W/enc.pcap -nn -e "ether host $STA_MAC or ether host $LEAF_BR_MAC or host 10.88.0.3 or host 10.88.0.1" 2>/dev/null | wc -l)
OTHER=$(tcpdump -r $W/enc.pcap -nn -e "ether src $LEAF_ETH0_MAC and not (udp port 51821) and not arp and not ether proto 0x88b5" 2>/dev/null | wc -l)
WG=$(tcpdump -r $W/enc.pcap -nn "udp port 51821" 2>/dev/null | wc -l)
[ "$STA_SEEN" = 0 ] && [ "$OTHER" = 0 ] && [ "$WG" -gt 0 ] \
  && pass "wire tap sees $WG WireGuard packets, no station MAC or address, no plaintext" || fail "wire exposure: station=$STA_SEEN other=$OTHER wg=$WG"

nsx atk ip addr add 10.88.0.9/24 dev eth9
nsx atk ip neigh replace 10.88.0.3 lladdr $STA_MAC dev eth9
nsx sta tcpdump -i sta0 -U -w $W/sta.pcap >/dev/null 2>&1 & STA_CAPTURE=$!
sleep 2
nsx atk ping -c 3 -W 1 10.88.0.3 >/dev/null 2>&1 && fail "attacker reached the station in plaintext"
nsx atk ip addr add 169.254.83.9/32 dev eth9
nsx atk ip route add 169.254.83.2/32 dev eth9
nsx atk ping -c 3 -W 1 169.254.83.2 >/dev/null 2>&1 && fail "attacker reached the node underlay address"
sleep 1; kill $STA_CAPTURE; wait $STA_CAPTURE 2>/dev/null
[ "$(tcpdump -r $W/sta.pcap -nn host 10.88.0.9 2>/dev/null | wc -l)" = 0 ] \
  && pass "plaintext injected on the wire never reaches the station or the node" || fail "injection reached the station"

ip -n sw link set p-leaf mtu 1500
RESULT=$(api $M PUT /leafRouter/backhaul/mtu '{"IP":"10.88.0.2"}') || fail "jumbo test request failed: $RESULT"
echo "$RESULT" | python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if (r["UnderlayMTU"],r["Jumbo"],r["LinkMTU"])==(1500,False,1390) else 1)' \
  && pass "jumbo frame test detects a 1500 byte switch: $RESULT" || fail "unexpected result on a 1500 byte switch: $RESULT"
wait_for 30 nsx leaf nft list table bridge mesh_macsec_mss && wait_for 30 station_ping 1 \
  && station_ping 2 -M do -s 1362 \
  && pass "1500 byte switch: link stays up at 1390 with the MSS clamp" || fail "link broken after dropping to a 1500 byte switch"
ip -n sw link set p-leaf mtu 9000
RESULT=$(api $M PUT /leafRouter/backhaul/mtu '{"IP":"10.88.0.2"}') || fail "jumbo re-test failed: $RESULT"
echo "$RESULT" | grep -q '"Jumbo":true' && wait_for 30 station_ping 2 -M do -s 1472 \
  && pass "re-test restores the jumbo underlay" \
  || fail "re-test did not restore jumbo: $RESULT main eth1=$(mtu main eth1) wg=$(mtu main wgmesh) vx=$(mtu main $MAIN_VX) leaf eth0=$(mtu leaf eth0) wg=$(mtu leaf wgmesh) vx=$(mtu leaf mshvx0)"

capture_start $W/restart.pcap
kill -9 $LEAF_PLUGIN
sleep 2
nsx leaf env TEST_PREFIX=$L WANIF=eth0 $MESH >> $W/leaf.log 2>&1 &
LEAF_PLUGIN=$!
wait_for 60 leaf_secured && wait_for 30 station_ping 1 && pass "node plugin restart keeps the WireGuard backhaul" || fail "no recovery after node plugin restart"
capture_stop
[ "$(tcpdump -r $W/restart.pcap -nn -e "ether host $STA_MAC or host 10.88.0.3" 2>/dev/null | wc -l)" = 0 ] \
  && pass "no plaintext during the node restart" || fail "plaintext during restart"

ports_at_1500() { [ "$(mtu main eth1)" = 1500 ] && [ "$(mtu leaf eth0)" = 1500 ] && [ "$(mtu leaf mshvx0)" = 1390 ]; }
JUMBO=$(api $M PUT /leafRouter/backhaul/jumbo '{"IP":"10.88.0.2","Jumbo":false}') || fail "jumbo off failed: $JUMBO"
wait_for 30 ports_at_1500 && [ -z "$(field $M Underlay)" ] && wait_for 30 station_ping 2 -M do -s 1362 \
  && pass "turning jumbo frames off restores both ports to 1500 and keeps the link up" \
  || fail "jumbo off: main eth1=$(mtu main eth1) leaf eth0=$(mtu leaf eth0) vx=$(mtu leaf mshvx0) underlay=$(field $M Underlay)"

underlay_routes() { echo "leaf: $(ip -n leaf -4 route show dev eth0 | tr '\n' ' ') main: $(ip -n main -4 route show dev eth1 | tr '\n' ' ')"; }
ip -n leaf link set eth0 down; sleep 2; ip -n leaf link set eth0 up
wait_for 30 station_ping 1 && pass "link recovers after the node uplink goes down and up" \
  || fail "no recovery after the node uplink went down and up: $(underlay_routes)"
ip -n main link set eth1 down; sleep 2; ip -n main link set eth1 up
wait_for 30 station_ping 1 && pass "link recovers after the main router port goes down and up" \
  || fail "no recovery after the main router port went down and up: $(underlay_routes)"

nsx sw nft -f - << 'EOF'
table bridge block {
  chain forward {
    type filter hook forward priority 0; policy accept;
    udp dport 51821 drop
  }
}
EOF
OFF=$(api $M PUT /leafRouter/backhaul '{"IP":"10.88.0.2","Enable":false}') || fail "off with the tunnel blocked failed: $OFF"
nsx sw nft delete table bridge block
nsx main ip addr add 10.88.0.1/24 dev eth1 2>/dev/null
wait_for 60 sh -c "ip -n leaf -o link show master br0 | grep -q ' eth0'" \
  && ! ip -n leaf link show wgmesh >/dev/null 2>&1 && ! ip -n main link show wgmesh >/dev/null 2>&1 \
  && [ ! -f $L/configs/base/mesh_macsec_required ] && wait_for 30 station_ping 1 \
  && pass "turning WireGuard off on the main router also turns it off on the node while the tunnel is blocked" \
  || fail "WireGuard off did not restore the plaintext uplink"
! ip -n main link show mshbr0 >/dev/null 2>&1 && ! nsx main nft list table bridge mesh_bridge_guard >/dev/null 2>&1 \
  && pass "main bridge and its guard removed with the last link" || fail "mshbr0 or its guard left behind: $(bridge_state) status=$(api $M GET /macsec/status)"

if [ $FAILED = 0 ]; then
  echo "ALL WIREGUARD E2E CHECKS PASSED"
  exit 0
fi
dump
exit 1
