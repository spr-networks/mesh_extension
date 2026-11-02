package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func doJSON(t *testing.T, handler http.HandlerFunc, method string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "/", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func peerEnable(nonce string) macsecPeerRequest {
	return macsecPeerRequest{Token: testPairingToken, Enable: true, KeyNonce: nonce, PeerMTU: 1500}
}

func TestMACsecPeerRequiresPairingToken(t *testing.T) {
	env := setupMACsecEnv(t, true)
	confirmed := enabledLeafConfig(env, true)
	writeMeshConfig(t, confirmed)

	for name, token := range map[string]string{
		"missing":    "",
		"wrong":      strings.Repeat("x", len(testPairingToken)),
		"prefix":     testPairingToken[:len(testPairingToken)-1],
		"extended":   testPairingToken + "x",
		"other case": strings.ToUpper(testPairingToken),
	} {
		disable := macsecPeerRequest{Token: token, Enable: false}
		if rec := doJSON(t, macsecPeer, http.MethodPut, disable); rec.Code != http.StatusForbidden {
			t.Errorf("%s token: disable returned %d", name, rec.Code)
		}
		enable := peerEnable(strings.Repeat("ab", macsecNonceLen))
		enable.Token = token
		if rec := doJSON(t, macsecPeer, http.MethodPut, enable); rec.Code != http.StatusForbidden {
			t.Errorf("%s token: enable returned %d", name, rec.Code)
		}
	}
	if got := readMeshConfig().LeafMACsec; got != confirmed.LeafMACsec {
		t.Fatalf("unauthenticated request changed MACsec state: %+v", got)
	}
}

func TestMACsecPeerRequiresLeafMode(t *testing.T) {
	setupMACsecEnv(t, false)
	if rec := doJSON(t, macsecPeer, http.MethodPut, peerEnable(testNonce)); rec.Code != 400 {
		t.Fatalf("main router accepted a leaf enable: %d", rec.Code)
	}
}

func TestMACsecPeerValidatesInput(t *testing.T) {
	setupMACsecEnv(t, true)
	cases := map[string]macsecPeerRequest{
		"short nonce":  peerEnable(testNonce[:10]),
		"bad nonce":    peerEnable(strings.Repeat("zz", macsecNonceLen)),
		"low mtu":      {Token: testPairingToken, Enable: true, KeyNonce: testNonce, PeerMTU: 576},
		"high mtu":     {Token: testPairingToken, Enable: true, KeyNonce: testNonce, PeerMTU: 9000},
		"missing mtu":  {Token: testPairingToken, Enable: true, KeyNonce: testNonce},
		"empty nonce":  {Token: testPairingToken, Enable: true, PeerMTU: 1500},
		"nonce inject": peerEnable(testNonce[:60] + "\nab"),
	}
	for name, request := range cases {
		if rec := doJSON(t, macsecPeer, http.MethodPut, request); rec.Code != 400 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("invalid request enabled MACsec")
	}
}

func TestMACsecPeerRefusesWhenUnsupported(t *testing.T) {
	env := setupMACsecEnv(t, true)
	env.sys.probeErr = errors.New("no macsec module")
	rec := doJSON(t, macsecPeer, http.MethodPut, peerEnable(testNonce))
	if rec.Code != 400 || readMeshConfig().LeafMACsec.Enabled {
		t.Fatalf("enabled on an unsupported leaf: %d", rec.Code)
	}
}

func TestMACsecPeerEnableAndConfirmLifecycle(t *testing.T) {
	env := setupMACsecEnv(t, true)
	info := env.sys.infos["eth0"]
	info.MaxMTU = 1500
	env.sys.infos["eth0"] = info

	rec := doJSON(t, macsecPeer, http.MethodPut, peerEnable(testNonce))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	reply := macsecPeerResponse{}
	json.Unmarshal(rec.Body.Bytes(), &reply)
	if reply.Version != macsecProtocolVersion || reply.BridgeMAC != "00:11:22:33:44:55" || reply.MaxMTU != 1468 || reply.LinkMTU != 1468 {
		t.Fatalf("reply %+v", reply)
	}
	if strings.Contains(rec.Body.String(), testPairingToken) {
		t.Fatal("reply echoes the pairing token")
	}
	cfg := readMeshConfig().LeafMACsec
	if !cfg.Enabled || cfg.Confirmed || cfg.KeyNonce != testNonce || cfg.LinkMTU != 1468 || cfg.EnabledAt == 0 {
		t.Fatalf("persisted %+v", cfg)
	}

	cfg.Confirmed = true
	writeMeshConfig(t, MeshConfig{LeafMACsec: cfg})
	doJSON(t, macsecPeer, http.MethodPut, peerEnable(testNonce))
	if !readMeshConfig().LeafMACsec.Confirmed {
		t.Fatal("re-sent enable reset confirmation")
	}
	doJSON(t, macsecPeer, http.MethodPut, peerEnable(strings.Repeat("ef", macsecNonceLen)))
	if readMeshConfig().LeafMACsec.Confirmed {
		t.Fatal("new CAK inherited confirmation")
	}

	disable := macsecPeerRequest{Token: testPairingToken, Enable: false}
	if rec := doJSON(t, macsecPeer, http.MethodPut, disable); rec.Code != 200 {
		t.Fatalf("disable %d", rec.Code)
	}
	if readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("disable ignored")
	}
}

type leafCall struct {
	leaf    LeafRouter
	request macsecPeerRequest
}

func stubLeaf(t *testing.T, reply macsecPeerResponse, err error) *[]leafCall {
	calls := &[]leafCall{}
	macsecCallLeaf = func(leaf LeafRouter, request macsecPeerRequest) (macsecPeerResponse, error) {
		*calls = append(*calls, leafCall{leaf, request})
		return reply, err
	}
	return calls
}

var goodLeafReply = macsecPeerResponse{Version: macsecProtocolVersion, BridgeMAC: "00:11:22:33:44:55", MaxMTU: 1500, LinkMTU: 1500, LeafPublicKey: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="}

func TestLeafRouterMACsecEnable(t *testing.T) {
	setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(2, 0))
	calls := stubLeaf(t, goodLeafReply, nil)

	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true, Mode: "macsec"})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(*calls) != 1 {
		t.Fatalf("leaf calls %d", len(*calls))
	}
	sent := (*calls)[0].request
	leaf := readMeshConfig().LeafRouters[0]
	if sent.Token != leaf.APIToken || !sent.Enable || sent.PeerMTU != 1468 || sent.Jumbo {
		t.Fatalf("new link should start without jumbo frames: %+v", sent)
	}
	if _, err := decodeMACsecNonce(sent.KeyNonce); err != nil {
		t.Fatal(err)
	}
	m := leaf.MACsec
	if m == nil || !m.Enabled || m.Port != 2 || m.Parent != "eth1" || m.KeyNonce != sent.KeyNonce || m.LeafMAC != "00:11:22:33:44:55" || m.LinkMTU != 1468 || m.Jumbo {
		t.Fatalf("persisted %+v", m)
	}
	if strings.Contains(rec.Body.String(), leaf.APIToken) || strings.Contains(rec.Body.String(), m.KeyNonce) {
		t.Fatal("response leaks key material")
	}

	doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.11", Enable: true, Mode: "macsec"})
	second := readMeshConfig().LeafRouters[1].MACsec
	if second == nil || second.Port != 3 || second.KeyNonce == m.KeyNonce {
		t.Fatalf("second leaf %+v", second)
	}

	doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true, Mode: "macsec"})
	if again := readMeshConfig().LeafRouters[0].MACsec; again.KeyNonce != m.KeyNonce || again.Port != m.Port {
		t.Fatalf("re-enable rotated keys: %+v", again)
	}
}

func TestLeafRouterMACsecMTUCap(t *testing.T) {
	setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	calls := stubLeaf(t, macsecPeerResponse{Version: macsecProtocolVersion, BridgeMAC: "00:11:22:33:44:55", MaxMTU: 1500}, nil)
	for _, bad := range []int{1279, 1501, -1} {
		if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true, MTU: bad, Mode: "macsec"}); rec.Code != 400 {
			t.Errorf("MTU %d accepted", bad)
		}
	}
	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true, MTU: 1468, Mode: "macsec"})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := (*calls)[len(*calls)-1].request.PeerMTU; got != 1468 {
		t.Fatalf("leaf told %d", got)
	}
	if got := readMeshConfig().LeafRouters[0].MACsec.LinkMTU; got != 1468 {
		t.Fatalf("link MTU %d", got)
	}
}

func TestLeafRouterMACsecRejectsBadLeafReplies(t *testing.T) {
	setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	bad := map[string]macsecPeerResponse{
		"old leaf":      {Version: 0, BridgeMAC: "00:11:22:33:44:55", MaxMTU: 1500},
		"bad mac":       {Version: macsecProtocolVersion, BridgeMAC: "not-a-mac", MaxMTU: 1500},
		"eui64 mac":     {Version: macsecProtocolVersion, BridgeMAC: "00:11:22:33:44:55:66:77", MaxMTU: 1500},
		"tiny mtu":      {Version: macsecProtocolVersion, BridgeMAC: "00:11:22:33:44:55", MaxMTU: 500},
		"missing reply": {},
	}
	for name, reply := range bad {
		stubLeaf(t, reply, nil)
		if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true}); rec.Code != 400 {
			t.Errorf("%s: %d", name, rec.Code)
		}
		if readMeshConfig().LeafRouters[0].MACsec != nil {
			t.Fatalf("%s: persisted", name)
		}
	}
	stubLeaf(t, goodLeafReply, errors.New("refused"))
	if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true}); rec.Code != 400 {
		t.Errorf("leaf refusal: %d", rec.Code)
	}
}

func TestLeafRouterMACsecValidation(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	calls := stubLeaf(t, goodLeafReply, nil)
	cases := map[string]leafMACsecRequest{
		"bad ip":          {IP: "192.168.2.10/../../x", Enable: true},
		"unknown leaf":    {IP: "192.168.2.99", Enable: true},
		"bad parent":      {IP: "192.168.2.10", Enable: true, Parent: "eth1;reboot"},
		"wan parent":      {IP: "192.168.2.10", Enable: true, Parent: "eth0"},
		"bridge parent":   {IP: "192.168.2.10", Enable: true, Parent: "br0"},
		"missing parent":  {IP: "192.168.2.10", Enable: true, Parent: "eth9"},
		"macsec parent":   {IP: "192.168.2.10", Enable: true, Parent: "macsec7"},
		"option injected": {IP: "192.168.2.10", Enable: true, Parent: "-x"},
	}
	env.sys.links = append(env.sys.links, macsecLink{Name: "macsec7", Parent: "eth1"})
	for name, request := range cases {
		if rec := doJSON(t, leafRouterMACsec, http.MethodPut, request); rec.Code < 400 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("leaf contacted for invalid requests: %d", len(*calls))
	}

	env.sys.probeErr = errors.New("no module")
	if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true, Mode: "macsec"}); rec.Code != 400 {
		t.Fatalf("enabled without kernel support: %d", rec.Code)
	}
	env.sys.probeErr = nil
	env.sys.probeWGErr = errors.New("no wireguard")
	if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true}); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Encrypted Link (WireGuard) unsupported on this router") {
		t.Fatalf("enabled WireGuard without kernel support: %d %s", rec.Code, rec.Body)
	}
	env.sys.probeWGErr = nil

	setLeafRouter(true)
	env.sys.probeErr = nil
	if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: true}); rec.Code != 400 {
		t.Fatalf("leaf accepted main-side enable: %d", rec.Code)
	}
}

func TestLeafRouterMACsecDisable(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))

	stubLeaf(t, macsecPeerResponse{}, errors.New("unreachable"))
	env.sys.sendErr = errors.New("no socket")
	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: false})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Encrypted Link (MACsec) is off on this router and did not get confirmation from node. Check mesh node at 192.168.2.10") {
		t.Fatalf("unconfirmed disable not reported: %d %s", rec.Code, rec.Body)
	}
	if readMeshConfig().LeafRouters[0].MACsec != nil {
		t.Fatal("turning MACsec off must always turn it off on the main router")
	}

	env.sys.sendErr = nil
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	calls := stubLeaf(t, macsecPeerResponse{Version: 1}, nil)
	doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: false})
	if len(env.sys.frames) != 0 {
		t.Fatal("wire disable used although the node answered over HTTPS")
	}
	if len(*calls) != 1 || (*calls)[0].request.Enable || (*calls)[0].request.Token == "" {
		t.Fatalf("leaf not told to disable: %+v", *calls)
	}
	if readMeshConfig().LeafRouters[0].MACsec != nil {
		t.Fatal("not disabled")
	}
}

func TestLeafRouterDeleteReleasesMACsec(t *testing.T) {
	setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 1)
	writeMeshConfig(t, config)
	calls := stubLeaf(t, macsecPeerResponse{Version: 1}, nil)

	wrong := LeafRouter{IP: config.LeafRouters[0].IP, APIToken: strings.Repeat("y", 43)}
	doJSON(t, leafRouter, http.MethodDelete, wrong)
	if len(*calls) != 0 || len(readMeshConfig().LeafRouters) != 1 {
		t.Fatal("wrong token released or removed the leaf")
	}

	doJSON(t, leafRouter, http.MethodDelete, config.LeafRouters[0])
	if len(*calls) != 1 || (*calls)[0].request.Enable {
		t.Fatalf("leaf not released: %+v", *calls)
	}
	if len(readMeshConfig().LeafRouters) != 0 {
		t.Fatal("leaf not removed")
	}
}

func TestPendingMACsecCompletesWhenLeafReturns(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 0)
	config.LeafRouters[0].MACsecPending = true
	writeMeshConfig(t, config)

	stubLeaf(t, macsecPeerResponse{}, errors.New("leaf 192.168.2.10 refused Encrypted Link (MACsec) change: 400 mesh bridge unavailable"))
	retryPendingMACsec()
	if got := readMeshConfig().LeafRouters[0]; !got.MACsecPending || got.MACsec != nil {
		t.Fatalf("pending request lost on failure: %+v", got)
	}
	env.m.reconcile()
	status := env.m.Status()
	if status.Strict || len(status.Links) != 1 || !status.Links[0].Pending || !strings.Contains(status.Links[0].Error, "mesh bridge unavailable") {
		t.Fatalf("status %+v", status)
	}
	if indexOf(env.sys.Ops(), "mka") >= 0 {
		t.Fatal("MKA started for a pending leaf")
	}

	calls := stubLeaf(t, goodLeafReply, nil)
	retryPendingMACsec()
	got := readMeshConfig().LeafRouters[0]
	if got.MACsecPending || got.MACsec == nil || !got.MACsec.Enabled || len(*calls) != 1 {
		t.Fatalf("pending request not completed: %+v", got)
	}
	env.m.reconcile()
	if s := env.m.Status(); !s.Strict || s.Links[0].Pending || s.Links[0].Error != "" {
		t.Fatalf("status after completion %+v", s)
	}

	retryPendingMACsec()
	if len(*calls) != 1 {
		t.Fatal("retried an enabled leaf")
	}
}

func TestDisableCancelsPendingMACsec(t *testing.T) {
	setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 0)
	config.LeafRouters[0].MACsecPending = true
	writeMeshConfig(t, config)
	calls := stubLeaf(t, goodLeafReply, nil)
	if rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: "192.168.2.10", Enable: false}); rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	if readMeshConfig().LeafRouters[0].MACsecPending || len(*calls) != 0 {
		t.Fatal("pending request not cancelled")
	}
	retryPendingMACsec()
	if len(*calls) != 0 {
		t.Fatal("cancelled request retried")
	}
}
