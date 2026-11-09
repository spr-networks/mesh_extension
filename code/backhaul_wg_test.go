package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestWGPub(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func TestWGKeyAndPSK(t *testing.T) {
	setupMACsecEnv(t, false)
	pub, err := loadOrCreateWGKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseWGKey(pub); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(meshWGKeyPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("private key file %v %v", err, st)
	}
	again, _ := loadOrCreateWGKey()
	if again != pub {
		t.Fatal("key not persisted")
	}
	data, _ := os.ReadFile(meshWGKeyPath)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()) != pub {
		t.Fatal("public key does not match the stored private key")
	}
	if raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Fatal("private key not clamped")
	}

	psk, err := deriveWGPSK(testPairingToken, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	again2, _ := deriveWGPSK(testPairingToken, testNonce)
	other, _ := deriveWGPSK(testPairingToken, strings.Repeat("ab", macsecNonceLen))
	if psk != again2 || psk == other {
		t.Fatal("PSK not deterministic per association")
	}
	if _, err := parseWGKey(psk); err != nil {
		t.Fatal(err)
	}
	cak := mustKeys(t, testPairingToken, testNonce).CAK
	if psk == base64.StdEncoding.EncodeToString(cak) {
		t.Fatal("PSK reuses the CAK")
	}
	if _, err := deriveWGPSK("short", testNonce); err == nil {
		t.Fatal("weak secret accepted")
	}
}

func TestRenderLeafGuardWG(t *testing.T) {
	rules, err := renderLeafGuardWG("eth0", 7, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type filter hook ingress device "eth0" priority -500; policy drop;`,
		"ether type arp arp daddr ip 169.254.83.7 accept",
		"ether type 0x88b5 accept",
		"ip saddr 169.254.83.1 ip daddr 169.254.83.7 udp sport 51821 udp dport 51821 accept",
		"ip saddr 169.254.83.7 ip daddr 169.254.83.1 udp sport 51821 udp dport 51821 accept",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "0x888e") || strings.Contains(rules, "0x88e5") {
		t.Error("WireGuard guard admits MACsec frames")
	}
	if strings.Count(rules, "accept") != 6 {
		t.Errorf("unexpected accepts:\n%s", rules)
	}
	for _, bad := range []string{`eth0" ; flush ruleset ; "`, "", "-eth0"} {
		if _, err := renderLeafGuardWG(bad, 7, true); err == nil {
			t.Errorf("accepted interface %q", bad)
		}
	}
	for _, port := range []int{0, 1, 255, 1000} {
		if _, err := renderLeafGuardWG("eth0", port, true); err == nil {
			t.Errorf("accepted port %d", port)
		}
	}
}

func TestWGInnerMTU(t *testing.T) {
	for underlay, want := range map[int]int{1500: 1390, 1600: 1490, 1610: 1500, 9000: 1500} {
		if got := wgInnerMTU(underlay); got != want {
			t.Errorf("underlay %d: %d want %d", underlay, got, want)
		}
	}
}

func wgLeafConfig(env *macsecTestEnv, mainPub string, confirmed bool) MeshConfig {
	return MeshConfig{LeafMACsec: LeafSideMACsec{
		Enabled:       true,
		Mode:          backhaulWireGuard,
		Confirmed:     confirmed,
		KeyNonce:      testNonce,
		LinkMTU:       wgInnerMTU(1500),
		Jumbo:         true,
		Port:          2,
		MainPublicKey: mainPub,
		EnabledAt:     env.clock.Add(-macsecApplyDelay).Unix(),
	}}
}

func TestLeafWireGuardBringUp(t *testing.T) {
	env := setupMACsecEnv(t, true)
	mainPub := newTestWGPub(t)
	writeMeshConfig(t, wgLeafConfig(env, mainPub, false))
	env.m.reconcile()
	ops := env.sys.Ops()

	guard := indexOf(ops, "nft guard-wg+egress")
	unbridge := indexOf(ops, "nomaster eth0")
	wg := indexOf(ops, "cmd ip link add wgmesh type wireguard")
	if guard < 0 || unbridge < 0 || wg < 0 || guard > wg || unbridge > wg {
		t.Fatalf("tunnel created before the uplink was guarded and unbridged: %v", ops)
	}
	for _, want := range []string{
		"mtu eth0 9000",
		"cmd ip addr replace 169.254.83.2/32 dev eth0",
		"cmd ip route replace 169.254.83.1/32 dev eth0 src 169.254.83.2",
		"cmd wg set wgmesh private-key " + meshWGKeyPath + " listen-port 51821",
		"cmd ip addr replace 169.254.84.2/32 dev wgmesh",
		"cmd ip link add mshvx0 type vxlan id 2 local 169.254.84.2 remote 169.254.84.1 dstport 4789 nolearning",
		"mtu mshvx0 1390",
		"mtu wgmesh 1440",
		"nft mss 1350",
	} {
		if !contains(ops, want) {
			t.Errorf("missing %q in %v", want, ops)
		}
	}
	peer := indexOf(ops, "cmd wg set wgmesh peer "+mainPub)
	if peer < 0 || !strings.Contains(ops[peer], "allowed-ips 169.254.84.1/32 endpoint 169.254.83.1:51821") {
		t.Fatalf("main router peer not configured: %v", ops)
	}
	if indexOf(ops, "mka") >= 0 || contains(ops, "master eth0 br0") || contains(ops, "master mshvx0 br0") {
		t.Fatalf("unexpected bridge/MKA operations before the tunnel is up: %v", ops)
	}
	if !macsecRequiredFlagSet() {
		t.Fatal("boot flag not written")
	}

	before := len(env.sys.Ops())
	env.m.reconcile()
	if indexOf(env.sys.Ops()[before:], "cmd wg set") >= 0 {
		t.Fatal("WireGuard reconfigured every pass")
	}

	env.sys.handshakes = map[string]int64{mainPub: env.clock.Unix()}
	env.m.reconcile()
	if !contains(env.sys.Ops(), "master mshvx0 br0") {
		t.Fatalf("VXLAN port not bridged once the tunnel is up: %v", env.sys.Ops())
	}
	if !readMeshConfig().LeafMACsec.Confirmed {
		t.Fatal("tunnel up but not confirmed")
	}
	if s := env.m.Status(); !s.Links[0].Secured || s.Links[0].Mode != backhaulWireGuard || s.Links[0].Interface != meshVXLANLeaf {
		t.Fatalf("status %+v", s)
	}
}

func TestLeafWireGuardRevertTearsDown(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, wgLeafConfig(env, newTestWGPub(t), false))
	env.m.reconcile()
	env.clock = env.clock.Add(macsecConfirmTimeout + time.Second)
	env.m.reconcile()
	if readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("never-connected tunnel did not revert")
	}
	ops := env.sys.Ops()
	for _, want := range []string{"del mshvx0", "del wgmesh", "cmd ip addr del 169.254.83.2/32 dev eth0", "nft-del netdev " + macsecGuardTable, "master eth0 br0"} {
		if !contains(ops, want) {
			t.Errorf("missing %q in %v", want, ops)
		}
	}
	if indexOf(ops, "del wgmesh") > indexOf(ops, "master eth0 br0") {
		t.Fatal("uplink rejoined the bridge before the tunnel was removed")
	}
}

func TestLeafWireGuardConfirmedFailsClosed(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, wgLeafConfig(env, newTestWGPub(t), true))
	env.m.reconcile()
	env.clock = env.clock.Add(24 * time.Hour)
	env.m.reconcile()
	if !readMeshConfig().LeafMACsec.Enabled || contains(env.sys.Ops(), "master eth0 br0") {
		t.Fatal("confirmed WireGuard leaf reverted to the plaintext uplink")
	}
}

func wgMainConfig(t *testing.T, underlay int) (MeshConfig, string) {
	config := mainConfigWithLeaves(1, 1)
	pub := newTestWGPub(t)
	config.LeafRouters[0].MACsec.Mode = backhaulWireGuard
	config.LeafRouters[0].MACsec.LeafPublicKey = pub
	config.LeafRouters[0].MACsec.UnderlayMTU = underlay
	config.LeafRouters[0].MACsec.LinkMTU = wgInnerMTU(underlayOrDefault(underlay))
	return config, pub
}

func TestMainWireGuardBringUpAndCleanup(t *testing.T) {
	env := setupMACsecEnv(t, false)
	env.sys.routes = map[string][]routeEntry{"eth1": {{Family: 4, Dst: "192.168.2.4/30", Protocol: "kernel", Scope: "link"}}}
	config, leafPub := wgMainConfig(t, 9000)
	writeMeshConfig(t, config)
	env.m.reconcile()
	ops := env.sys.Ops()
	for _, want := range []string{
		"mtu eth1 9000",
		"cmd ip addr replace 169.254.83.1/32 dev eth1",
		"cmd ip route replace 169.254.83.2/32 dev eth1 src 169.254.83.1",
		"cmd ip link add wgmesh type wireguard",
		"cmd ip addr replace 169.254.84.1/32 dev wgmesh",
		"cmd ip route replace 169.254.84.2/32 dev wgmesh src 169.254.84.1",
		"cmd ip link add mshvx2 type vxlan id 2 local 169.254.84.1 remote 169.254.84.2 dstport 4789 nolearning",
		"mtu wgmesh 8940",
	} {
		if !contains(ops, want) {
			t.Errorf("missing %q in %v", want, ops)
		}
	}
	for _, op := range ops {
		if strings.Contains(op, "192.168.2.4/30") {
			t.Fatalf("plaintext LAN route touched: %v", ops)
		}
	}
	peer := indexOf(ops, "cmd wg set wgmesh peer "+leafPub)
	if peer < 0 || !strings.Contains(ops[peer], "allowed-ips 169.254.84.2/32 endpoint 169.254.83.2:51821") {
		t.Fatalf("leaf peer not configured: %v", ops)
	}
	status := env.m.Status()
	if !status.Strict || status.Links[0].Interface != meshBridge || status.Links[0].Member != "mshvx2" || status.Links[0].Mode != backhaulWireGuard || status.Links[0].Secured {
		t.Fatalf("status %+v", status)
	}
	if l, ok := env.sys.infos["mshvx2"]; !ok || l.MTU != 1500 {
		t.Fatalf("VXLAN MTU on a jumbo underlay should be 1500: %+v", l)
	}
	env.clock = env.clock.Add(macsecNoPeerAfter + time.Second)
	env.m.reconcile()
	if e := env.m.Status().Links[0].Error; e != "Encrypted Link (WireGuard) not up on eth1" {
		t.Fatalf("no actionable error for a missing WireGuard peer: %q", e)
	}

	env.sys.handshakes = map[string]int64{leafPub: env.clock.Unix()}
	env.m.reconcile()
	if !env.m.Status().Links[0].Secured {
		t.Fatal("tunnel up but status not secured")
	}

	writeMeshConfig(t, MeshConfig{LeafRouters: []LeafRouter{{IP: config.LeafRouters[0].IP, APIToken: config.LeafRouters[0].APIToken}}})
	env.m.reconcile()
	ops = env.sys.Ops()
	for _, want := range []string{"cmd wg set wgmesh peer " + leafPub + " remove", "del mshvx2", "del wgmesh", "cmd ip addr del 169.254.83.1/32 dev eth1"} {
		if !contains(ops, want) {
			t.Errorf("cleanup missing %q in %v", want, ops)
		}
	}
}

func probeResponder(t *testing.T, keys macsecCtlKeys, maxSize int) func([]byte) []byte {
	nodeMAC, _ := net.ParseMAC("7a:11:22:33:44:55")
	return func(frame []byte) []byte {
		cmd, src, challenge, total, ok := parseMACsecCtlFrameSized(frame, keys)
		if !ok || cmd != macsecCtlProbe || total-14 > maxSize {
			return nil
		}
		return buildMACsecCtlFrameSized(src, nodeMAC, macsecCtlProbeReply, keys, challenge, total)
	}
}

func TestJumboFrameTest(t *testing.T) {
	for _, pathMTU := range []int{9000, 1500, 4000} {
		env := setupMACsecEnv(t, false)
		info := env.sys.infos["eth1"]
		info.MTU = 9000
		env.sys.infos["eth1"] = info
		config, _ := wgMainConfig(t, 0)
		writeMeshConfig(t, config)
		leaf := config.LeafRouters[0]
		env.sys.reply = probeResponder(t, testCtlKeys(t, leaf.APIToken, leaf.MACsec.KeyNonce), pathMTU)
		got, err := env.m.testUnderlayMTU(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if got > pathMTU || pathMTU-got > 8 {
			t.Errorf("path MTU %d measured as %d", pathMTU, got)
		}
	}
}

func TestJumboFrameTestEndpointUpdatesBothRouters(t *testing.T) {
	env := setupMACsecEnv(t, false)
	info := env.sys.infos["eth1"]
	info.MTU = 9000
	env.sys.infos["eth1"] = info
	config, _ := wgMainConfig(t, 0)
	writeMeshConfig(t, config)
	leaf := config.LeafRouters[0]
	env.sys.reply = probeResponder(t, testCtlKeys(t, leaf.APIToken, leaf.MACsec.KeyNonce), 9000)
	calls := stubLeaf(t, goodLeafReply, nil)

	rec := doJSON(t, leafRouterMTUTest, http.MethodPut, leafMACsecRequest{IP: leaf.IP})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	result := macsecMTUResult{}
	json.Unmarshal(rec.Body.Bytes(), &result)
	if !result.Jumbo || result.UnderlayMTU != 9000 || result.LinkMTU != 1500 {
		t.Fatalf("result %+v", result)
	}
	saved := readMeshConfig().LeafRouters[0].MACsec
	if saved.UnderlayMTU != 9000 || saved.LinkMTU != 1500 {
		t.Fatalf("main config %+v", saved)
	}
	if len(*calls) != 1 || (*calls)[0].request.UnderlayMTU != 9000 || (*calls)[0].request.KeyNonce != leaf.MACsec.KeyNonce {
		t.Fatalf("node not told the new MTU: %+v", *calls)
	}

	env.sys.reply = nil
	rec = doJSON(t, leafRouterMTUTest, http.MethodPut, leafMACsecRequest{IP: leaf.IP})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), errMTUProbeNoReply.Error()) {
		t.Fatalf("silent node not reported: %d %s", rec.Code, rec.Body)
	}
}

func TestLeafAnswersSignedProbesOnly(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, wgLeafConfig(env, newTestWGPub(t), true))
	env.m.reconcile()
	eth0 := env.sys.infos["eth0"].MAC
	env.sys.mu.Lock()
	delete(env.sys.infos, "eth0")
	env.sys.mu.Unlock()
	keys := testCtlKeys(t, testPairingToken, testNonce)
	challenge := bytes.Repeat([]byte{5}, macsecCtlChallengeLen)
	probe := buildMACsecCtlFrameSized(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, testMainMAC, macsecCtlProbe, keys, challenge, 9014)
	env.m.handleLeafCtl("eth0", probe)
	if len(env.sys.frames) != 1 || len(env.sys.frames[0]) != 9014 {
		t.Fatalf("probe not echoed at full size without a link lookup: %d frames", len(env.sys.frames))
	}
	cmd, from, echoed, total, ok := parseMACsecCtlFrameSized(env.sys.frames[0], keys)
	if !ok || cmd != macsecCtlProbeReply || total != 9014 || !bytes.Equal(echoed, challenge) || from.String() != eth0.String() {
		t.Fatal("probe reply invalid")
	}
	forged := buildMACsecCtlFrameSized(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, testMainMAC, macsecCtlProbe,
		testCtlKeys(t, testPairingToken, strings.Repeat("ab", macsecNonceLen)), challenge, 9014)
	env.m.handleLeafCtl("eth0", forged)
	if len(env.sys.frames) != 1 {
		t.Fatal("answered a probe from another association")
	}
	resized := append([]byte{}, probe...)
	resized[14+len(macsecCtlMagic)+1+macsecCKNLen+macsecCtlChallengeLen+1] ^= 0x01
	env.m.handleLeafCtl("eth0", resized)
	if len(env.sys.frames) != 1 {
		t.Fatal("answered a probe whose declared size was altered")
	}
}

func TestLeafAnswersProbesDuringReconcile(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, wgLeafConfig(env, newTestWGPub(t), true))
	env.m.reconcile()
	keys := testCtlKeys(t, testPairingToken, testNonce)
	probe := buildMACsecCtlFrameSized(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, testMainMAC, macsecCtlProbe, keys,
		bytes.Repeat([]byte{6}, macsecCtlChallengeLen), 1514)
	env.m.mu.Lock()
	done := make(chan struct{})
	go func() {
		env.m.handleLeafCtl("eth0", probe)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		env.m.mu.Unlock()
		t.Fatal("probe reply waited for a running reconcile")
	}
	env.m.mu.Unlock()
	env.sys.mu.Lock()
	defer env.sys.mu.Unlock()
	if len(env.sys.frames) != 1 {
		t.Fatalf("%d replies", len(env.sys.frames))
	}
}

func TestEnableWireGuardHandshake(t *testing.T) {
	setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	calls := stubLeaf(t, goodLeafReply, nil)
	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	sent := (*calls)[0].request
	if sent.Mode != backhaulWireGuard || sent.Port != 2 || sent.PeerMTU != 0 {
		t.Fatalf("request %+v", sent)
	}
	if _, err := parseWGKey(sent.MainPublicKey); err != nil {
		t.Fatal("main public key missing")
	}
	saved := readMeshConfig().LeafRouters[0].MACsec
	if saved.Mode != backhaulWireGuard || saved.LeafPublicKey != goodLeafReply.LeafPublicKey || saved.LinkMTU != 1390 {
		t.Fatalf("saved %+v", saved)
	}
	if strings.Contains(rec.Body.String(), sent.MainPublicKey) && strings.Contains(rec.Body.String(), "PRIVATE") {
		t.Fatal("unexpected key material in response")
	}

	bad := goodLeafReply
	bad.LeafPublicKey = "not-a-key"
	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	stubLeaf(t, bad, nil)
	if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true}); rec.Code != 400 {
		t.Fatalf("invalid leaf key accepted: %d", rec.Code)
	}
}

func TestMACsecPeerWireGuard(t *testing.T) {
	setupMACsecEnv(t, true)
	mainPub := newTestWGPub(t)
	good := macsecPeerRequest{Token: testPairingToken, Enable: true, KeyNonce: testNonce, Mode: backhaulWireGuard, Port: 3, MainPublicKey: mainPub}
	rec := doJSON(t, macsecPeer, http.MethodPut, good)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	reply := macsecPeerResponse{}
	json.Unmarshal(rec.Body.Bytes(), &reply)
	if _, err := parseWGKey(reply.LeafPublicKey); err != nil || reply.LinkMTU != 1390 || reply.MaxMTU != 9000 {
		t.Fatalf("reply %+v", reply)
	}
	cfg := readMeshConfig().LeafMACsec
	if cfg.Mode != backhaulWireGuard || cfg.Port != 3 || cfg.MainPublicKey != mainPub || cfg.Confirmed {
		t.Fatalf("saved %+v", cfg)
	}
	for name, mutate := range map[string]func(*macsecPeerRequest){
		"bad key":        func(r *macsecPeerRequest) { r.MainPublicKey = "x" },
		"port too large": func(r *macsecPeerRequest) { r.Port = 255 },
		"port zero":      func(r *macsecPeerRequest) { r.Port = 0 },
		"tiny underlay":  func(r *macsecPeerRequest) { r.UnderlayMTU = 1000 },
		"huge underlay":  func(r *macsecPeerRequest) { r.UnderlayMTU = 65000 },
	} {
		req := good
		mutate(&req)
		if rec := doJSON(t, macsecPeer, http.MethodPut, req); rec.Code != 400 {
			t.Errorf("%s accepted: %d", name, rec.Code)
		}
	}
	unsupported := setupMACsecEnv(t, true)
	unsupported.sys.probeWGErr = errors.New("no module")
	if rec := doJSON(t, macsecPeer, http.MethodPut, good); rec.Code != 400 {
		t.Fatalf("enabled on a leaf without WireGuard: %d", rec.Code)
	}
}

func TestJumboOffLeavesPortMTUAlone(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config, leafPub := wgMainConfig(t, 9000)
	config.LeafRouters[0].MACsec.Jumbo = false
	writeMeshConfig(t, config)
	env.m.reconcile()
	ops := env.sys.Ops()
	for _, op := range ops {
		if strings.HasPrefix(op, "mtu eth1") || strings.HasPrefix(op, "cmd ethtool") {
			t.Fatalf("port touched without jumbo frames: %v", ops)
		}
	}
	if !contains(ops, "mtu wgmesh 1440") || env.sys.infos["mshvx2"].MTU != 1390 {
		t.Fatalf("tunnel sized for a jumbo underlay: %v", ops)
	}
	env.sys.handshakes = map[string]int64{leafPub: env.clock.Unix()}
	env.m.reconcile()
	if st := env.m.Status().Links[0]; !st.Secured || st.Underlay != 0 || st.LinkMTU != 1390 {
		t.Fatalf("status %+v", st)
	}
}

func TestLeafJumboOffKeepsUplinkMTU(t *testing.T) {
	env := setupMACsecEnv(t, true)
	config := wgLeafConfig(env, newTestWGPub(t), false)
	config.LeafMACsec.Jumbo = false
	config.LeafMACsec.UnderlayMTU = 9000
	writeMeshConfig(t, config)
	env.m.reconcile()
	ops := env.sys.Ops()
	if indexOf(ops, "mtu eth0 9000") >= 0 {
		t.Fatalf("uplink raised without jumbo frames: %v", ops)
	}
	if !contains(ops, "mtu wgmesh 1440") || !contains(ops, "mtu mshvx0 1390") || !contains(ops, "nft mss 1350") {
		t.Fatalf("tunnel not sized for a 1500 byte uplink: %v", ops)
	}
}

func TestJumboOffRestoresPortAndRenegotiates(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config, _ := wgMainConfig(t, 9000)
	writeMeshConfig(t, config)
	env.m.reconcile()
	if env.sys.infos["eth1"].MTU != 9000 || indexOf(env.sys.Ops(), "cmd ethtool -r eth1") >= 0 {
		t.Fatalf("jumbo raise: %v", env.sys.Ops())
	}
	config.LeafRouters[0].MACsec.Jumbo = false
	writeMeshConfig(t, config)
	env.m.reconcile()
	ops := env.sys.Ops()
	restore := indexOf(ops, "mtu eth1 1500")
	if restore < 0 || indexOf(ops, "cmd ethtool -r eth1") < restore {
		t.Fatalf("port not restored and renegotiated: %v", ops)
	}
}

func TestJumboTestWaitsForTheLinkToSettle(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config, _ := wgMainConfig(t, 0)
	writeMeshConfig(t, config)
	env.m.reconcile()
	leaf := config.LeafRouters[0]
	if env.m.jumboTestDue(leaf, true) {
		t.Fatal("tested while the port was renegotiating")
	}
	env.clock = env.clock.Add(meshJumboSettle)
	if !env.m.jumboTestDue(leaf, true) {
		t.Fatal("jumbo link never tested")
	}
	if env.m.jumboTestDue(leaf, false) {
		t.Fatal("tested a link that is not up")
	}
	off := leaf
	cfg := *leaf.MACsec
	cfg.Jumbo = false
	off.MACsec = &cfg
	if env.m.jumboTestDue(off, true) {
		t.Fatal("tested with jumbo frames off")
	}
	tested := leaf
	cfg = *leaf.MACsec
	cfg.UnderlayMTU = 9000
	tested.MACsec = &cfg
	if env.m.jumboTestDue(tested, true) {
		t.Fatal("retested an already measured link")
	}
}

func TestJumboSwitchUpdatesBothRouters(t *testing.T) {
	setupMACsecEnv(t, false)
	config, _ := wgMainConfig(t, 0)
	config.LeafRouters[0].MACsec.Jumbo = false
	writeMeshConfig(t, config)
	leaf := config.LeafRouters[0]
	calls := stubLeaf(t, goodLeafReply, nil)

	if rec := doJSON(t, leafRouterJumbo, http.MethodPut, leafMACsecRequest{IP: leaf.IP, Jumbo: true}); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	saved := readMeshConfig().LeafRouters[0].MACsec
	if !saved.Jumbo || saved.UnderlayMTU != 0 || saved.KeyNonce != leaf.MACsec.KeyNonce {
		t.Fatalf("main config %+v", saved)
	}
	if len(*calls) != 1 || !(*calls)[0].request.Jumbo || (*calls)[0].request.KeyNonce != leaf.MACsec.KeyNonce || (*calls)[0].request.Mode != backhaulWireGuard {
		t.Fatalf("node not told: %+v", *calls)
	}
	if rec := doJSON(t, leafRouterJumbo, http.MethodPut, leafMACsecRequest{IP: leaf.IP, Jumbo: true}); rec.Code != 200 || len(*calls) != 1 {
		t.Fatalf("unchanged setting resent: %d %+v", rec.Code, *calls)
	}

	measured := readMeshConfig()
	measured.LeafRouters[0].MACsec.UnderlayMTU = 9000
	measured.LeafRouters[0].MACsec.LinkMTU = 1500
	writeMeshConfig(t, measured)
	if rec := doJSON(t, leafRouterJumbo, http.MethodPut, leafMACsecRequest{IP: leaf.IP, Jumbo: false}); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	saved = readMeshConfig().LeafRouters[0].MACsec
	if saved.Jumbo || saved.UnderlayMTU != 0 || saved.LinkMTU != 1390 {
		t.Fatalf("main config %+v", saved)
	}
	if len(*calls) != 2 || (*calls)[1].request.Jumbo || (*calls)[1].request.UnderlayMTU != 0 {
		t.Fatalf("node not told: %+v", *calls)
	}

	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	if rec := doJSON(t, leafRouterJumbo, http.MethodPut, leafMACsecRequest{IP: leaf.IP, Jumbo: true}); rec.Code != 400 {
		t.Fatalf("jumbo set on an unencrypted link: %d", rec.Code)
	}
}

func TestWireGuardUnderlayRouteReturnsAfterLinkBounce(t *testing.T) {
	for _, leaf := range []bool{true, false} {
		env := setupMACsecEnv(t, leaf)
		dev, route := "eth1", "cmd ip route replace 169.254.83.2/32 dev eth1 src 169.254.83.1"
		if leaf {
			dev, route = "eth0", "cmd ip route replace 169.254.83.1/32 dev eth0 src 169.254.83.2"
			writeMeshConfig(t, wgLeafConfig(env, newTestWGPub(t), false))
		} else {
			config, _ := wgMainConfig(t, 9000)
			writeMeshConfig(t, config)
		}
		if !contains(reconcileOps(env), route) || contains(reconcileOps(env), route) {
			t.Fatalf("leaf=%v: underlay route not added once: %v", leaf, env.sys.Ops())
		}
		env.sys.mu.Lock()
		env.sys.routes[dev] = nil
		env.sys.mu.Unlock()
		if ops := reconcileOps(env); !contains(ops, route) {
			t.Fatalf("leaf=%v: underlay route not restored after %s went down and up: %v", leaf, dev, ops)
		}
	}
}
