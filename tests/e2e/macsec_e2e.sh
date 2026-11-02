#!/bin/bash
set -uo pipefail

REPO=${REPO:-/repo}
MESH=${MESH:-/e2e-bin/mesh}
E2E=$REPO/tests/e2e
W=/tmp/e2e
L=$W/leaf
M=$W/main
STA_MAC=02:5a:00:00:00:03
FAILED=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

dump() {
  echo "---- main log"; tail -40 $W/main.log
  echo "---- leaf log"; tail -40 $W/leaf.log
  echo "---- proxy log"; tail -20 $W/proxy.log
  ip -n leaf -d link show type macsec
  ip -n main -d link show type macsec
  ip -n leaf -o link show master br0
}

die() { echo "FAIL: $*"; dump; exit 1; }

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

api() {
  local prefix=$1 method=$2 path=$3 data=${4:-}
  curl -s -S --max-time 60 --fail-with-body --unix-socket "$prefix/state/plugins/mesh/socket" \
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

status_field() {
  api "$1" GET /macsec/status | python3 -c "import json,sys; s=json.load(sys.stdin); print(s['Links'][0].get('$2','') if s['Links'] else '')"
}

leaf_secured() { [ "$(status_field $L Secured)" = "True" ]; }
main_secured() { [ "$(status_field $M Secured)" = "True" ]; }
ports() { ip -n leaf -o link show master br0 | awk -F': ' '{print $2}' | cut -d@ -f1; }
mtu() { ip -n "$1" -j link show dev "$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["mtu"])'; }
station_ping() { nsx sta ping -c "${1:-2}" -W 2 "${@:2}" 10.88.0.1 >/dev/null 2>&1; }

capture_start() { nsx atk tcpdump -i eth9 -U -w "$1" >/dev/null 2>&1 & CAPTURE=$!; sleep 2; }
capture_stop() { sleep 1; kill $CAPTURE 2>/dev/null; wait $CAPTURE 2>/dev/null; }

plaintext_leak() {
  local pcap=$1
  tcpdump -r "$pcap" -nn "host 10.88.0.3 or (ether host $STA_MAC and not ether proto 0x88e5 and not ether proto 0x888e) or (ether src $LEAF_ETH0_MAC and not ether proto 0x88e5 and not ether proto 0x888e)" 2>/dev/null | wc -l
}

for m in macsec veth bridge nf_tables; do modprobe $m 2>/dev/null; done
rm -rf $W
mkdir -p $W/fakebin $L/configs/base $L/configs/mesh $L/configs/auth $L/state/plugins/mesh \
  $M/configs/base $M/configs/mesh $M/configs/auth $M/state/plugins/mesh
for c in dhclient iptables iptables-legacy conntrack; do printf '#!/bin/sh\nexit 0\n' > $W/fakebin/$c; chmod +x $W/fakebin/$c; done

TOKEN=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')

for ns in sw main leaf sta atk lan; do ip netns add $ns; ip -n $ns link set lo up; done
for ns in main leaf sta atk lan; do nsx $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; done
ip -n sw link add sw0 type bridge ageing_time 0 group_fwd_mask 8
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
ports | grep -qx eth0 || die "plaintext boot did not bridge the uplink"

nsx leaf env TEST_PREFIX=$L WANIF=eth0 $MESH > $W/leaf.log 2>&1 &
LEAF_PLUGIN=$!
nsx main env TEST_PREFIX=$M WANIF=wan0 $MESH > $W/main.log 2>&1 &
nsx leaf python3 $E2E/leaf_api_proxy.py 10.88.0.2 "$TOKEN" $L/state/plugins/mesh/socket $W/leaf.crt $W/leaf.key > $W/proxy.log 2>&1 &
wait_for 30 test -S $L/state/plugins/mesh/socket -a -S $M/state/plugins/mesh/socket || die "plugins did not start"

api $L PUT /stationConnect "{\"Event\":\"AP-STA-CONNECTED\",\"Iface\":\"wlan0.4096\",\"Mac\":\"$STA_MAC\"}" >/dev/null
bridge -n leaf -d link show dev wlan0.4096 | grep -q "isolated on" && pass "AP/VLAN station port is bridged and isolated" || fail "station port not isolated"

wait_for 20 station_ping 1 || die "station cannot reach main over the plaintext uplink"
capture_start $W/plain.pcap
station_ping 3
capture_stop
[ "$(tcpdump -r $W/plain.pcap -nn host 10.88.0.3 2>/dev/null | wc -l)" -gt 0 ] \
  && pass "baseline: wire tap sees plaintext station traffic before MACsec" \
  || die "wire tap sees nothing; the capture position is broken"

ENABLE=$(api $M PUT /leafRouter/macsec '{"IP":"10.88.0.2","Enable":true,"Mode":"macsec"}') || die "enable handshake failed: $ENABLE"
pass "main enabled MACsec through the TLS handshake with the leaf"

wait_for 180 leaf_secured || die "leaf never secured"
wait_for 60 main_secured || die "main never secured"
pass "MKA secured the link on both routers"

MAIN_SECY=$(status_field $M Interface)
LEAF_SECY=$(status_field $L Interface)
LEAF_ETH0_MAC=$(ip -n leaf -br link show dev eth0 | awk '{print $3}')
nsx main ip addr del 10.88.0.1/24 dev eth1
nsx main ip addr add 10.88.0.1/24 dev $MAIN_SECY

[ "$(mtu leaf eth0)" = 1500 ] && [ "$(mtu main eth1)" = 1500 ] && [ "$(mtu leaf $LEAF_SECY)" = 1468 ] \
  && pass "jumbo frames off by default: ports stay at 1500, secYs carry 1468" \
  || fail "jumbo off: leaf eth0=$(mtu leaf eth0) secY=$(mtu leaf $LEAF_SECY) main eth1=$(mtu main eth1)"
wait_for 30 station_ping 1 || fail "station cannot reach main over MACsec without jumbo frames"
JUMBO=$(api $M PUT /leafRouter/backhaul/jumbo '{"IP":"10.88.0.2","Jumbo":true}') || fail "jumbo on failed: $JUMBO"
secys_carry_1500() { [ "$(mtu leaf eth0)" = 1532 ] && [ "$(mtu leaf $LEAF_SECY)" = 1500 ] && [ "$(mtu main eth1)" = 1532 ] && [ "$(mtu main $MAIN_SECY)" = 1500 ]; }
wait_for 30 secys_carry_1500

[ "$(api $L GET /macsec/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["Confirmed"])')" = "True" ] \
  && pass "leaf confirmed the association" || fail "leaf not confirmed"
[ "$(api $M GET /macsec/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["Strict"])')" = "True" ] \
  && pass "main reports strict mode" || fail "main not strict"
ports | grep -qx eth0 && fail "raw uplink still bridged" || pass "raw uplink removed from br0"
ports | grep -qx "$LEAF_SECY" && pass "secY $LEAF_SECY bridged into br0" || fail "secY not bridged"
nsx leaf nft list table netdev mesh_macsec_guard >/dev/null 2>&1 && pass "guard table installed on the leaf" || fail "guard table missing"
[ -f $L/configs/base/mesh_macsec_required ] && pass "boot flag written to configs/base" || fail "boot flag missing"
[ "$(mtu leaf eth0)" = 1532 ] && [ "$(mtu leaf $LEAF_SECY)" = 1500 ] && [ "$(mtu main eth1)" = 1532 ] && [ "$(mtu main $MAIN_SECY)" = 1500 ] \
  && pass "parents raised to 1532, secYs carry 1500" || fail "MTUs leaf eth0=$(mtu leaf eth0) secY=$(mtu leaf $LEAF_SECY) main eth1=$(mtu main eth1) secY=$(mtu main $MAIN_SECY)"
bridge -n leaf -d link show dev wlan0.4096 | grep -q "isolated on" && pass "station port still isolated" || fail "isolation lost"
wait_for 15 sh -c "ip -n main -4 route show dev eth1 | grep '^10.89.0.0/24' | grep -q 'mtu lock 1500'" \
  && ! nsx main ping -c 1 -W 1 -M do -s 1473 10.89.0.2 >/dev/null 2>&1 \
  && nsx main ping -c 2 -W 2 -s 1572 10.89.0.2 >/dev/null 2>&1 \
  && [ "$(mtu lan eth5)" = 1500 ] \
  && pass "plaintext LAN host on the raised parent still gets at most 1500 byte packets" || fail "plaintext LAN route MTU not pinned: $(ip -n main -4 route show dev eth1 | tr '\n' ';')"

wait_for 30 station_ping 1 || die "station cannot reach main over MACsec"
station_ping 2 -M do -s 1472 && pass "AP/VLAN station sends full 1500 byte packets over MACsec" || fail "1500 byte DF ping failed"

capture_start $W/enc.pcap
station_ping 5 -i 0.2
station_ping 2 -M do -s 1472
capture_stop
LEAKS=$(plaintext_leak $W/enc.pcap)
MACSEC_FRAMES=$(tcpdump -r $W/enc.pcap -nn 'ether proto 0x88e5' 2>/dev/null | wc -l)
[ "$LEAKS" = 0 ] && [ "$MACSEC_FRAMES" -gt 0 ] \
  && pass "wire tap sees $MACSEC_FRAMES MACsec frames and no plaintext" || fail "plaintext on the wire: $LEAKS frames"

nsx atk ip addr add 10.88.0.9/24 dev eth9
nsx atk ip neigh replace 10.88.0.3 lladdr $STA_MAC dev eth9
nsx atk ip neigh replace 10.88.0.2 lladdr $LEAF_BR_MAC dev eth9
nsx sta tcpdump -i sta0 -U -w $W/sta.pcap >/dev/null 2>&1 & STA_CAPTURE=$!
sleep 2
nsx atk ping -c 3 -W 1 10.88.0.3 >/dev/null 2>&1 && fail "attacker reached the station in plaintext"
nsx atk ping -c 3 -W 1 10.88.0.2 >/dev/null 2>&1 && fail "attacker reached the leaf in plaintext"
sleep 1; kill $STA_CAPTURE; wait $STA_CAPTURE 2>/dev/null
[ "$(tcpdump -r $W/sta.pcap -nn host 10.88.0.9 2>/dev/null | wc -l)" = 0 ] \
  && pass "plaintext injected on the wire never reaches the station or leaf" || fail "injected frames reached the station"

LATE0=$(python3 $E2E/frames.py stat main $MAIN_SECY InPktsLate)
REPLAYED=$(nsx atk python3 $E2E/frames.py replay $W/enc.pcap $STA_MAC eth9 5)
sleep 2
LATE1=$(python3 $E2E/frames.py stat main $MAIN_SECY InPktsLate)
[ "$REPLAYED" -gt 0 ] && [ $((LATE1 - LATE0)) -ge "$REPLAYED" ] \
  && pass "replayed MACsec frames rejected ($((LATE1 - LATE0)) late)" || fail "replay not rejected: sent $REPLAYED late $LATE0->$LATE1"

BAD0=$(python3 $E2E/frames.py stat main $MAIN_SECY InPktsNotValid)
TAMPERED=$(nsx atk python3 $E2E/frames.py tamper $W/enc.pcap $STA_MAC eth9 5)
sleep 2
BAD1=$(python3 $E2E/frames.py stat main $MAIN_SECY InPktsNotValid)
[ "$TAMPERED" -gt 0 ] && [ $((BAD1 - BAD0)) -ge "$TAMPERED" ] \
  && pass "tampered MACsec frames rejected ($((BAD1 - BAD0)) not valid)" || fail "tampering not rejected: sent $TAMPERED notvalid $BAD0->$BAD1"
station_ping 2 && pass "link still works after replay and tampering" || fail "link broken by injected frames"

CKN=$(grep mka_ckn $M/run/spr-mesh-macsec/main-2.conf | cut -d= -f2)
CAK=$(grep mka_cak $M/run/spr-mesh-macsec/main-2.conf | cut -d= -f2)
sed -e "s/mka_cak=.*/mka_cak=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')/" \
    -e "s/mka_priority=.*/mka_priority=0/" -e "s/macsec_port=.*/macsec_port=9/" \
    $M/run/spr-mesh-macsec/main-2.conf > $W/rogue.conf
nsx atk wpa_supplicant -D macsec_linux -i eth9 -c $W/rogue.conf > $W/rogue.log 2>&1 & ROGUE=$!
sleep 20
RXSC=$(ip -n main macsec show $MAIN_SECY | grep -c "RXSC:")
ROGUE_UP=$(ip -n atk -d link show type macsec | grep -c "<.*,UP")
[ "$RXSC" = 1 ] && [ "$ROGUE_UP" = 0 ] && leaf_secured && station_ping 2 \
  && pass "rogue MKA participant with the sniffed CKN and a wrong CAK cannot join" || fail "rogue participant: main rxsc=$RXSC rogue up=$ROGUE_UP"
kill $ROGUE 2>/dev/null; wait $ROGUE 2>/dev/null

for prefix in $L $M; do
  STATUS=$(api $prefix GET /macsec/status)
  if echo "$STATUS" | grep -q -e "$TOKEN" -e "$CAK"; then fail "status leaks key material"; fi
done
pass "status endpoints carry no token or CAK"

ip -n sw link set sw0 type bridge group_fwd_mask 0
capture_start $W/blocked.pcap
sleep 25
station_ping 3
capture_stop
LEAKS=$(plaintext_leak $W/blocked.pcap)
ports | grep -qx eth0 && fail "leaf re-bridged its raw uplink while MKA was blocked"
[ "$LEAKS" = 0 ] && nsx leaf nft list table netdev mesh_macsec_guard >/dev/null 2>&1 \
  && [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["LeafMACsec"]["Confirmed"])' $L/configs/mesh/config.json)" = True ] \
  && pass "blocking MKA causes no plaintext and no downgrade (secured=$(status_field $L Secured))" || fail "MKA blocking weakened the link: leaks=$LEAKS"
ip -n sw link set sw0 type bridge group_fwd_mask 8
wait_for 120 leaf_secured && wait_for 60 main_secured && wait_for 30 station_ping 1 \
  && pass "link recovers once 802.1X frames pass again" || fail "link did not recover"

capture_start $W/restart.pcap
kill -9 $LEAF_PLUGIN
pkill -9 -f "$L/run/spr-mesh-macsec/leaf.conf"
sleep 3
nsx leaf env TEST_PREFIX=$L WANIF=eth0 $MESH >> $W/leaf.log 2>&1 &
LEAF_PLUGIN=$!
wait_for 180 leaf_secured && wait_for 60 main_secured && wait_for 30 station_ping 1 \
  && pass "leaf plugin crash and restart recovers the secured link" || fail "no recovery after leaf plugin restart"
capture_stop
ports | grep -qx eth0 && fail "raw uplink bridged after restart"
[ "$(plaintext_leak $W/restart.pcap)" = 0 ] && pass "no plaintext during the leaf restart" || fail "plaintext during restart"

ip -n sw link set sw0 type bridge group_fwd_mask 0
wait_for 90 sh -c "[ \"\$(curl -s --unix-socket $L/state/plugins/mesh/socket http://localhost/macsec/status | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s[\"Links\"][0][\"Secured\"])')\" = False ]" \
  || fail "link did not break while 802.1X frames were blocked"
OFF=$(api $M PUT /leafRouter/macsec '{"IP":"10.88.0.2","Enable":false}') || fail "disable with the link down failed: $OFF"
nsx main ip addr add 10.88.0.1/24 dev eth1 2>/dev/null
wait_for 60 sh -c "ip -n leaf -o link show master br0 | grep -q ' eth0'" \
  && wait_for 30 station_ping 1 && [ ! -f $L/configs/base/mesh_macsec_required ] \
  && ! nsx leaf nft list table netdev mesh_macsec_guard >/dev/null 2>&1 \
  && pass "turning MACsec off on the main router also turns it off on the node while the encrypted link is down" \
  || fail "node stayed on MACsec after the main router turned it off with the link down"
ip -n sw link set sw0 type bridge group_fwd_mask 8

ENABLE=$(api $M PUT /leafRouter/macsec '{"IP":"10.88.0.2","Enable":true,"Mode":"macsec"}') || fail "re-enable after wire disable failed: $ENABLE"
wait_for 180 leaf_secured && wait_for 60 main_secured || fail "link did not secure again"
MAIN_SECY=$(status_field $M Interface)
nsx main ip addr del 10.88.0.1/24 dev eth1 2>/dev/null
nsx main ip addr add 10.88.0.1/24 dev $MAIN_SECY
wait_for 30 station_ping 1 || fail "station unreachable after re-enabling MACsec"

DISABLE=$(api $M PUT /leafRouter/macsec '{"IP":"10.88.0.2","Enable":false}') || fail "disable failed: $DISABLE"
nsx main ip addr add 10.88.0.1/24 dev eth1 2>/dev/null
wait_for 60 sh -c "ip -n leaf -o link show master br0 | grep -q ' eth0'" \
  && wait_for 30 station_ping 1 && [ ! -f $L/configs/base/mesh_macsec_required ] \
  && ! nsx leaf nft list table netdev mesh_macsec_guard >/dev/null 2>&1 \
  && [ "$(mtu leaf eth0)" = 1500 ] \
  && pass "disable over the encrypted link returns the leaf to the plaintext uplink" || fail "disable did not restore the plaintext uplink"

ENABLE=$(api $M PUT /leafRouter/macsec '{"IP":"10.88.0.2","Enable":true,"Mode":"macsec"}') || fail "re-enable failed: $ENABLE"
wait_for 180 leaf_secured || fail "re-enabled link never secured"
api $L PUT /leafMode/disable >/dev/null || fail "leaf mode reset failed"
wait_for 30 sh -c "[ ! -f $L/configs/base/mesh_macsec_required ] && ! ip -n leaf -d link show type macsec | grep -q macsec" \
  && ! nsx leaf nft list table netdev mesh_macsec_guard >/dev/null 2>&1 \
  && [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["LeafMACsec"]["Enabled"])' $L/configs/mesh/config.json)" = False ] \
  && pass "resetting leaf mode tears MACsec down and clears its config" || fail "leaf mode reset left MACsec state behind"
api $L PUT /leafMode/enable >/dev/null
sleep 10
! ip -n leaf -d link show type macsec | grep -q macsec && [ ! -f $L/configs/base/mesh_macsec_required ] \
  && pass "re-entering leaf mode does not resurrect the old association" || fail "old association came back"

if [ $FAILED = 0 ]; then
  echo "ALL E2E CHECKS PASSED"
  exit 0
fi
dump
exit 1
