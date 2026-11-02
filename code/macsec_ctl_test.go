package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

var testMainMAC, _ = net.ParseMAC("7a:11:22:33:44:66")

func testCtlKeys(t *testing.T, secret, nonce string) macsecCtlKeys {
	t.Helper()
	keys, err := deriveMACsecCtlKeys(secret, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestMACsecCtlFrameRoundTrip(t *testing.T) {
	keys := testCtlKeys(t, testPairingToken, testNonce)
	challenge := bytes.Repeat([]byte{7}, macsecCtlChallengeLen)
	dst, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	frame := buildMACsecCtlFrame(dst, testMainMAC, macsecCtlDisable, keys, challenge)
	if len(frame) != macsecCtlFrameLen || frame[12] != 0x88 || frame[13] != 0xb5 {
		t.Fatalf("frame %x", frame)
	}
	cmd, src, echoed, ok := parseMACsecCtlFrame(frame, keys)
	if !ok || cmd != macsecCtlDisable || src.String() != testMainMAC.String() || !bytes.Equal(echoed, challenge) {
		t.Fatalf("round trip failed: %v %v %x %v", cmd, src, echoed, ok)
	}

	if buildMACsecCtlFrame(dst, nil, macsecCtlDisable, keys, challenge) != nil || buildMACsecCtlFrame(dst[:4], testMainMAC, macsecCtlDisable, keys, challenge) != nil {
		t.Fatal("frame built without a 6 byte address")
	}

	cak := mustKeys(t, testPairingToken, testNonce).CAK
	if bytes.Equal(keys.Key, cak) {
		t.Fatal("control key reuses the CAK")
	}

	otherLeaf := testCtlKeys(t, testPairingToken[:len(testPairingToken)-1]+"b", testNonce)
	oldAssociation := testCtlKeys(t, testPairingToken, strings.Repeat("ab", macsecNonceLen))
	for name, k := range map[string]macsecCtlKeys{"other leaf": otherLeaf, "old association": oldAssociation} {
		if _, _, _, ok := parseMACsecCtlFrame(frame, k); ok {
			t.Errorf("%s accepted the frame", name)
		}
	}
	forged := buildMACsecCtlFrame(dst, testMainMAC, macsecCtlDisable, macsecCtlKeys{CKN: keys.CKN, Key: bytes.Repeat([]byte{1}, 32)}, challenge)
	if _, _, _, ok := parseMACsecCtlFrame(forged, keys); ok {
		t.Error("frame signed with a guessed key accepted")
	}
	for i := 14; i < len(frame); i++ {
		tampered := append([]byte{}, frame...)
		tampered[i] ^= 0x01
		if _, _, _, ok := parseMACsecCtlFrame(tampered, keys); ok {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, _, _, ok := parseMACsecCtlFrame(frame[:len(frame)-1], keys); ok {
		t.Error("truncated frame accepted")
	}
}

func signedDisable(t *testing.T, keys macsecCtlKeys) []byte {
	dst, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	return buildMACsecCtlFrame(dst, testMainMAC, macsecCtlDisable, keys, bytes.Repeat([]byte{9}, macsecCtlChallengeLen))
}

func TestLeafDisablesOnSignedWireFrame(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	keys := testCtlKeys(t, testPairingToken, testNonce)

	if !env.m.handleLeafCtl("eth0", signedDisable(t, keys)) {
		t.Fatal("signed disable ignored")
	}
	if len(env.sys.frames) != 1 {
		t.Fatalf("no acknowledgement sent: %d frames", len(env.sys.frames))
	}
	cmd, _, echoed, ok := parseMACsecCtlFrame(env.sys.frames[0], keys)
	if !ok || cmd != macsecCtlAck || !bytes.Equal(echoed, bytes.Repeat([]byte{9}, macsecCtlChallengeLen)) {
		t.Fatal("acknowledgement does not echo the challenge")
	}
	if !bytes.Equal(env.sys.frames[0][:6], testMainMAC) {
		t.Fatal("acknowledgement not addressed to the main router")
	}
	if readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("node kept MACsec after a signed disable")
	}
	env.m.reconcile()
	if !contains(env.sys.Ops(), "master eth0 br0") || macsecRequiredFlagSet() {
		t.Fatalf("node did not return to the plaintext uplink: %v", env.sys.Ops())
	}

	if !env.m.handleLeafCtl("eth0", signedDisable(t, keys)) || len(env.sys.frames) != 2 {
		t.Fatal("repeated disable inside the ack window not acknowledged")
	}
}

func TestLeafIgnoresForgedOrStaleWireFrames(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	keys := testCtlKeys(t, testPairingToken, testNonce)
	dst, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	cases := map[string][]byte{
		"other leaf key":  signedDisable(t, testCtlKeys(t, testPairingToken[:len(testPairingToken)-1]+"b", testNonce)),
		"old association": signedDisable(t, testCtlKeys(t, testPairingToken, strings.Repeat("ab", macsecNonceLen))),
		"ack not disable": buildMACsecCtlFrame(dst, testMainMAC, macsecCtlAck, keys, bytes.Repeat([]byte{9}, macsecCtlChallengeLen)),
		"truncated":       signedDisable(t, keys)[:40],
	}
	for name, frame := range cases {
		if env.m.handleLeafCtl("eth0", frame) {
			t.Errorf("%s accepted", name)
		}
	}
	if len(env.sys.frames) != 0 {
		t.Fatal("acknowledged an invalid frame")
	}
	if !readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("invalid frame disabled MACsec")
	}
}

func ackAs(t *testing.T, keys macsecCtlKeys) func([]byte) []byte {
	return func(frame []byte) []byte {
		cmd, src, challenge, ok := parseMACsecCtlFrame(frame, keys)
		if !ok || cmd != macsecCtlDisable {
			return nil
		}
		leafMAC, _ := net.ParseMAC("7a:11:22:33:44:55")
		return buildMACsecCtlFrame(src, leafMAC, macsecCtlAck, keys, challenge)
	}
}

func TestMainDisableFallsBackToWireWhenNodeUnreachable(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 1)
	writeMeshConfig(t, config)
	stubLeaf(t, macsecPeerResponse{}, errors.New("unreachable"))
	leaf := config.LeafRouters[0]
	env.sys.reply = ackAs(t, testCtlKeys(t, leaf.APIToken, leaf.MACsec.KeyNonce))

	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: leaf.IP, Enable: false})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if readMeshConfig().LeafRouters[0].MACsec != nil {
		t.Fatal("main kept MACsec after the node acknowledged")
	}
	if len(env.sys.frames) == 0 || !bytes.Equal(env.sys.frames[0][:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatal("disable not sent on the wire")
	}
}

func TestMainWireDisableWithoutAckStillTurnsMainOff(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 1)
	writeMeshConfig(t, config)
	stubLeaf(t, macsecPeerResponse{}, errors.New("unreachable"))

	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: config.LeafRouters[0].IP, Enable: false})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Encrypted Link (MACsec) is off on this router and did not get confirmation from node. Check mesh node at "+config.LeafRouters[0].IP) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if readMeshConfig().LeafRouters[0].MACsec != nil {
		t.Fatal("a sent disable must also turn the main router off")
	}
	if len(env.sys.frames) == 0 {
		t.Fatal("no disable frame sent")
	}
}

func TestMainWireDisableWithoutAckNamesWireGuard(t *testing.T) {
	setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 1)
	config.LeafRouters[0].MACsec.Mode = backhaulWireGuard
	writeMeshConfig(t, config)
	stubLeaf(t, macsecPeerResponse{}, errors.New("unreachable"))

	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: config.LeafRouters[0].IP, Enable: false})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Encrypted Link (WireGuard) is off on this router and did not get confirmation from node. Check mesh node at "+config.LeafRouters[0].IP) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if readMeshConfig().LeafRouters[0].MACsec != nil {
		t.Fatal("main router kept WireGuard after it was turned off")
	}
}

func TestMainWireDisableSendFailure(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 1)
	writeMeshConfig(t, config)
	stubLeaf(t, macsecPeerResponse{}, errors.New("unreachable"))
	env.sys.sendErr = errors.New("no socket")

	rec := doJSON(t, leafRouterMACsec, http.MethodPut, leafMACsecRequest{IP: config.LeafRouters[0].IP, Enable: false})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Encrypted Link (MACsec) is off on this router and did not get confirmation from node. Check mesh node at "+config.LeafRouters[0].IP) {
		t.Fatalf("unconfirmed disable not reported: %d %s", rec.Code, rec.Body)
	}
	if readMeshConfig().LeafRouters[0].MACsec != nil {
		t.Fatal("main router kept MACsec after it was turned off")
	}
}
