package main

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testPairingToken = "0123456789abcdef0123456789abcdef0123456789a"

var testNonce = hex.EncodeToString([]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
})

func mustKeys(t *testing.T, secret, nonce string) macsecKeys {
	t.Helper()
	keys, err := deriveMACsecKeys(secret, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestDeriveMACsecKeysKnownAnswer(t *testing.T) {
	keys := mustKeys(t, testPairingToken, testNonce)
	if got := hex.EncodeToString(keys.CAK); got != "36d094b3d508426fac4d62184bed75664df156dd93d71853559238f82196ee0e" {
		t.Fatalf("CAK = %s", got)
	}
	if got := hex.EncodeToString(keys.CKN); got != "c43bf08499d81d3f8d1b7d89d9bdc1c2" {
		t.Fatalf("CKN = %s", got)
	}
}

func TestDeriveMACsecKeysSeparation(t *testing.T) {
	base := mustKeys(t, testPairingToken, testNonce)
	again := mustKeys(t, testPairingToken, testNonce)
	if !bytes.Equal(base.CAK, again.CAK) || !bytes.Equal(base.CKN, again.CKN) {
		t.Fatal("derivation is not deterministic; main and leaf would disagree")
	}

	otherLeaf := mustKeys(t, testPairingToken[:len(testPairingToken)-1]+"b", testNonce)
	if bytes.Equal(base.CAK, otherLeaf.CAK) || bytes.Equal(base.CKN, otherLeaf.CKN) {
		t.Fatal("different leaves share a connectivity association")
	}

	rotatedNonce := strings.Repeat("ab", macsecNonceLen)
	rotated := mustKeys(t, testPairingToken, rotatedNonce)
	if bytes.Equal(base.CAK, rotated.CAK) || bytes.Equal(base.CKN, rotated.CKN) {
		t.Fatal("re-enabling with a new nonce did not rotate the CAK")
	}

	if bytes.Contains(base.CAK, base.CKN) {
		t.Fatal("CKN is a substring of the CAK")
	}
	if strings.Contains(hex.EncodeToString(base.CAK), hex.EncodeToString([]byte(testPairingToken))) {
		t.Fatal("CAK embeds the pairing token")
	}
}

func TestDeriveMACsecKeysRejectsWeakInput(t *testing.T) {
	cases := map[string][2]string{
		"empty secret":      {"", testNonce},
		"short secret":      {strings.Repeat("a", macsecMinSecretLen-1), testNonce},
		"empty nonce":       {testPairingToken, ""},
		"short nonce":       {testPairingToken, testNonce[:62]},
		"long nonce":        {testPairingToken, testNonce + "00"},
		"non-hex nonce":     {testPairingToken, strings.Repeat("zz", macsecNonceLen)},
		"odd length nonce":  {testPairingToken, testNonce[:63]},
		"nonce with prefix": {testPairingToken, "0x" + testNonce[:62]},
	}
	for name, c := range cases {
		if _, err := deriveMACsecKeys(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNewMACsecNonceIsRandom(t *testing.T) {
	a, err := newMACsecNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newMACsecNonce()
	if a == b {
		t.Fatal("nonces repeat")
	}
	if _, err := decodeMACsecNonce(a); err != nil {
		t.Fatal(err)
	}
}

func testInstance(t *testing.T) mkaInstance {
	return mkaInstance{ID: "leaf", Parent: "eth0", Port: 7, Priority: macsecPrioLeaf, Keys: mustKeys(t, testPairingToken, testNonce)}
}

func TestRenderWPAConfEnforcesEncryptionPolicy(t *testing.T) {
	inst := testInstance(t)
	conf, err := renderWPAConf(inst)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"eapol_version=3",
		"ap_scan=0",
		"key_mgmt=NONE",
		"macsec_policy=1",
		"macsec_integ_only=0",
		"macsec_replay_protect=1",
		"macsec_replay_window=0",
		"macsec_port=7",
		"mka_priority=255",
		"mka_cak=" + hex.EncodeToString(inst.Keys.CAK),
		"mka_ckn=" + hex.EncodeToString(inst.Keys.CKN),
	} {
		if !strings.Contains("\n"+conf, "\n"+want+"\n") && !strings.Contains(conf, "\t"+want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "macsec_csindex") {
		t.Error("macsec_csindex breaks wpa_supplicant 2.10")
	}
	if strings.Contains(conf, testPairingToken) {
		t.Error("pairing token written to wpa_supplicant config")
	}
	allowed := regexp.MustCompile(`^(#.*|[a-z_0-9]+=[0-9a-zA-Z]+|network=\{|\}|)$`)
	for _, line := range strings.Split(conf, "\n") {
		if !allowed.MatchString(strings.TrimSpace(line)) {
			t.Errorf("unexpected config line %q", line)
		}
	}
}

func TestRenderWPAConfRejectsInjection(t *testing.T) {
	good := testInstance(t)
	bad := []func(*mkaInstance){
		func(i *mkaInstance) { i.Parent = "eth0\nnetwork={" },
		func(i *mkaInstance) { i.Parent = "eth0 -B" },
		func(i *mkaInstance) { i.Parent = "-c/etc/passwd" },
		func(i *mkaInstance) { i.Parent = "" },
		func(i *mkaInstance) { i.Parent = "averyveryverylongif" },
		func(i *mkaInstance) { i.Port = 0 },
		func(i *mkaInstance) { i.Port = 65535 },
		func(i *mkaInstance) { i.Port = -1 },
		func(i *mkaInstance) { i.Priority = 256 },
		func(i *mkaInstance) { i.Priority = -1 },
		func(i *mkaInstance) { i.Keys.CAK = i.Keys.CAK[:16] },
		func(i *mkaInstance) { i.Keys.CKN = nil },
	}
	for n, mutate := range bad {
		inst := good
		inst.Keys = macsecKeys{CAK: append([]byte{}, good.Keys.CAK...), CKN: append([]byte{}, good.Keys.CKN...)}
		mutate(&inst)
		if _, err := renderWPAConf(inst); err == nil {
			t.Errorf("case %d accepted", n)
		}
	}
}

func TestMACsecSCI(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	sci, err := macsecSCI(mac, 7)
	if err != nil || sci != 0x0200000000010007 {
		t.Fatalf("sci = %#x %v", sci, err)
	}
	if _, err := macsecSCI(mac[:5], 7); err == nil {
		t.Error("short MAC accepted")
	}
	if _, err := macsecSCI(mac, 0); err == nil {
		t.Error("port 0 accepted")
	}
}

const sampleMACsecJSON = `[
 {"ifindex":9,"link":"eth1","ifname":"macsec0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"master":"br0","operstate":"UP",
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550002","protect":true,"cipher_suite":"GCM-AES-128","icv_len":16,"encoding_sa":0,"validation":"strict","offload":"off","encrypt":true,"inc_sci":true,"es":false,"scb":false,"replay_protect":true,"window":0}}},
 {"ifindex":10,"link":"eth1","ifname":"macsec1","flags":["BROADCAST","MULTICAST","M-DOWN"],"mtu":1468,
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"0x7a11223344550003","protect":true,"validation":"strict","encrypt":false,"replay_protect":true}}},
 {"ifindex":11,"link":"eth2","ifname":"macsec2","flags":["UP"],"mtu":1468,
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550002","protect":true,"validation":"check","encrypt":true,"replay_protect":true}}},
 {"ifindex":12,"link":"eth1","ifname":"macsec3","flags":["UP"],
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550004","validation":"strict","encrypt":true,"protect":false,"replay_protect":true}}},
 {"ifindex":13,"link":"eth1","ifname":"bad name","flags":["UP"],
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550005","protect":true,"validation":"strict","encrypt":true,"replay_protect":true}}},
 {"ifindex":14,"link":"eth1","ifname":"vlan5","flags":["UP"],"linkinfo":{"info_kind":"vlan"}},
 {"ifindex":15,"link":"eth1","ifname":"macsec5","flags":["UP"],
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":7,"protect":true,"validation":"strict","encrypt":true,"replay_protect":false}}},
 {"ifindex":16,"link":"eth1","ifname":"macsec6","flags":["UP"],
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550006","protect":true,"validate":"strict","encrypt":true,"replay":true}}},
 {"ifindex":17,"link":"eth1","ifname":"macsec7","flags":["UP"],
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550007","validation":"strict","encrypt":true}}},
 {"ifindex":18,"link":"eth1","ifname":"macsec8","flags":["UP"],
  "linkinfo":{"info_kind":"macsec","info_data":{"sci":"7a11223344550008","protect":true,"validation":"strict","encrypt":true}}}
]`

func TestParseMACsecLinks(t *testing.T) {
	links, err := parseMACsecLinks([]byte(sampleMACsecJSON))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]macsecLink{}
	for _, l := range links {
		byName[l.Name] = l
	}
	if _, ok := byName["bad name"]; ok {
		t.Error("invalid interface name accepted")
	}
	if _, ok := byName["vlan5"]; ok {
		t.Error("non-MACsec link accepted")
	}
	m0 := byName["macsec0"]
	if m0.Parent != "eth1" || m0.SCI != 0x7a11223344550002 || m0.Master != "br0" || m0.MTU != 1500 || !m0.Forwarding() {
		t.Errorf("macsec0 = %+v", m0)
	}
	if m1 := byName["macsec1"]; m1.SCI != 0x7a11223344550003 || m1.Secure() || m1.AdminUp {
		t.Errorf("macsec1 (encrypt off, down) = %+v", m1)
	}
	if byName["macsec2"].Secure() {
		t.Error("validate=check treated as secure")
	}
	if byName["macsec3"].Secure() {
		t.Error("protect=off treated as secure")
	}
	if m5 := byName["macsec5"]; m5.SCI != 7 || m5.Secure() {
		t.Errorf("numeric sci or replay=off mishandled: %+v", m5)
	}
	if !byName["macsec6"].Secure() {
		t.Error("older iproute2 key names not understood")
	}
	if byName["macsec7"].Secure() {
		t.Error("missing protect/replay attributes treated as secure")
	}
	if byName["macsec8"].Secure() {
		t.Error("missing replay attribute treated as secure")
	}
	if links, err := parseMACsecLinks([]byte("")); err != nil || len(links) != 0 {
		t.Error("empty output should be no links")
	}
	if _, err := parseMACsecLinks([]byte("{")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestFindMACsecLinkRequiresParentAndSCI(t *testing.T) {
	links, _ := parseMACsecLinks([]byte(sampleMACsecJSON))
	if l, ok := findMACsecLink(links, "eth1", 0x7a11223344550002); !ok || l.Name != "macsec0" {
		t.Fatalf("got %+v %v", l, ok)
	}
	if l, ok := findMACsecLink(links, "eth2", 0x7a11223344550002); !ok || l.Name != "macsec2" {
		t.Fatalf("got %+v %v", l, ok)
	}
	if _, ok := findMACsecLink(links, "eth3", 0x7a11223344550002); ok {
		t.Fatal("matched a secY on the wrong parent")
	}
	if _, ok := findMACsecLink(links, "eth1", 0x7a11223344550099); ok {
		t.Fatal("matched a secY with the wrong SCI")
	}
}

func TestMACsecMTU(t *testing.T) {
	if got := macsecCapableMTU(1500); got != 1468 {
		t.Errorf("1500 parent -> %d", got)
	}
	if got := macsecCapableMTU(1532); got != 1500 {
		t.Errorf("1532 parent -> %d", got)
	}
	if got := macsecCapableMTU(9000); got != 1500 {
		t.Errorf("jumbo parent must still cap at 1500 for bridged Wi-Fi, got %d", got)
	}
	if got, err := macsecLinkMTU(1500, 1468); err != nil || got != 1468 {
		t.Errorf("link mtu %d %v", got, err)
	}
	if got, err := macsecLinkMTU(9000, 9000); err != nil || got != 1500 {
		t.Errorf("link mtu %d %v", got, err)
	}
	if _, err := macsecLinkMTU(1500, 1000); err == nil {
		t.Error("MTU below IPv6 minimum accepted")
	}
	v4, v6 := macsecMSS(1468)
	if v4 != 1428 || v6 != 1408 {
		t.Errorf("mss %d %d", v4, v6)
	}
}

func TestAllocateMACsecPort(t *testing.T) {
	leaves := []LeafRouter{
		{IP: "a", MACsec: &LeafMACsec{Port: 2}},
		{IP: "b"},
		{IP: "c", MACsec: &LeafMACsec{Port: 4}},
	}
	if port, err := allocateMACsecPort(leaves); err != nil || port != 3 {
		t.Fatalf("port %d %v", port, err)
	}
	if port, _ := allocateMACsecPort(nil); port != macsecMainPortFirst || port == macsecLeafPort {
		t.Fatalf("first port %d", port)
	}
	full := []LeafRouter{}
	for p := macsecMainPortFirst; p <= macsecMainPortLast; p++ {
		full = append(full, LeafRouter{MACsec: &LeafMACsec{Port: p}})
	}
	if _, err := allocateMACsecPort(full); err == nil {
		t.Fatal("exhaustion not reported")
	}
}

func TestRenderLeafGuardOnlyAllowsMKAAndMACsec(t *testing.T) {
	rules, err := renderLeafGuard("eth0", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type filter hook ingress device "eth0" priority -500; policy drop;`,
		`type filter hook egress device "eth0" priority -500; policy drop;`,
		"ether type { 0x888e, 0x88e5, 0x88b5 } accept",
		"delete table netdev " + macsecGuardTable,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in\n%s", want, rules)
		}
	}
	if strings.Count(rules, "accept") != 2 {
		t.Errorf("guard accepts more than MKA and MACsec:\n%s", rules)
	}
	ingressOnly, _ := renderLeafGuard("eth0", false)
	if strings.Contains(ingressOnly, "egress") {
		t.Error("egress chain rendered when unsupported")
	}
	for _, bad := range []string{`eth0" ; flush ruleset ; "`, "eth0\n}", "", "-eth0", "eth0 eth1"} {
		if _, err := renderLeafGuard(bad, true); err == nil {
			t.Errorf("accepted interface %q", bad)
		}
	}
}

func TestRenderMSSClamp(t *testing.T) {
	rules, err := renderMSSClamp(1468)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"maxseg size > 1428 tcp option maxseg size set 1428", "maxseg size > 1408 tcp option maxseg size set 1408", "policy accept"} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q", want)
		}
	}
	if _, err := renderMSSClamp(1500); err == nil {
		t.Error("clamp rendered for a full-size link")
	}
	if _, err := renderMSSClamp(1000); err == nil {
		t.Error("clamp rendered below the minimum MTU")
	}
}

func TestExportRenderedConfigs(t *testing.T) {
	dir := os.Getenv("MACSEC_EXPORT_DIR")
	if dir == "" {
		t.Skip("MACSEC_EXPORT_DIR not set")
	}
	write := func(name, data string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	guard, err := renderLeafGuard("vguard", true)
	write("guard.nft", guard, err)
	guardIngress, err := renderLeafGuard("vguard", false)
	write("guard_ingress.nft", guardIngress, err)
	mss, err := renderMSSClamp(1468)
	write("mss.nft", mss, err)
	leaf, err := renderWPAConf(testInstance(t))
	write("wpa_leaf.conf", leaf, err)
	main := testInstance(t)
	main.Port, main.Priority = 2, macsecPrioMain
	mainConf, err := renderWPAConf(main)
	write("wpa_main.conf", mainConf, err)
}
