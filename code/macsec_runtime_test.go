package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProc struct {
	mu      sync.Mutex
	exited  bool
	stopped bool
}

func (p *fakeProc) Exited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited
}

func (p *fakeProc) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exited = true
	p.stopped = true
}

type fakeSys struct {
	mu         sync.Mutex
	ops        []string
	links      []macsecLink
	infos      map[string]linkInfo
	route      string
	probeErr   error
	egressErr  bool
	nftErr     error
	confs      map[string]string
	routes     map[string][]routeEntry
	frames     [][]byte
	inbox      [][]byte
	reply      func(frame []byte) []byte
	sendErr    error
	probeWGErr error
	handshakes map[string]int64
	wgPeers    map[string]bool
	addrs      map[string][]string
	tables     map[string]string
	procs      []*fakeProc
	nextIndex  int
}

func newFakeSys() *fakeSys {
	eth0, _ := net.ParseMAC("7a:11:22:33:44:55")
	eth1, _ := net.ParseMAC("7a:11:22:33:44:66")
	br0, _ := net.ParseMAC("00:11:22:33:44:55")
	return &fakeSys{
		infos: map[string]linkInfo{
			"eth0": {MAC: eth0, MTU: 1500, MaxMTU: 9000, Master: "br0"},
			"eth1": {MAC: eth1, MTU: 1500, MaxMTU: 9000},
			"br0":  {MAC: br0, MTU: 1500},
		},
		route: "eth1",
		confs: map[string]string{},
	}
}

func (f *fakeSys) op(format string, args ...interface{}) {
	f.ops = append(f.ops, fmt.Sprintf(format, args...))
}

func (f *fakeSys) Ops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.ops...)
}

func (f *fakeSys) Links() ([]macsecLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]macsecLink{}, f.links...), nil
}

func (f *fakeSys) LinkInfo(name string) (linkInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.infos[name]
	if !ok {
		for _, l := range f.links {
			if l.Name == name {
				return linkInfo{MTU: l.MTU, Master: l.Master}, nil
			}
		}
		return linkInfo{}, errors.New("no such device")
	}
	return info, nil
}

func (f *fakeSys) RouteDev(ip string) (string, error) {
	if f.route == "" {
		return "", errors.New("no route")
	}
	return f.route, nil
}

func (f *fakeSys) SetMTU(name string, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("mtu %s %d", name, mtu)
	if info, ok := f.infos[name]; ok {
		if info.MaxMTU > 0 && mtu > info.MaxMTU {
			return errors.New("mtu too big")
		}
		info.MTU = mtu
		f.infos[name] = info
	}
	for i := range f.links {
		if f.links[i].Name == name {
			f.links[i].MTU = mtu
		}
	}
	return nil
}

func (f *fakeSys) SetMaster(name, master string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if master == "" {
		f.op("nomaster %s", name)
	} else {
		f.op("master %s %s", name, master)
	}
	if info, ok := f.infos[name]; ok {
		info.Master = master
		f.infos[name] = info
	}
	for i := range f.links {
		if f.links[i].Name == name {
			f.links[i].Master = master
		}
	}
	return nil
}

func (f *fakeSys) SetUp(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("up %s", name)
	return nil
}

func (f *fakeSys) DeleteLink(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("del %s", name)
	delete(f.infos, name)
	kept := f.links[:0]
	for _, l := range f.links {
		if l.Name != name {
			kept = append(kept, l)
		}
	}
	f.links = kept
	return nil
}

func (f *fakeSys) DisableIPv6(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("noipv6 %s", name)
	return nil
}

func (f *fakeSys) NFT(ruleset string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nftErr != nil {
		return f.nftErr
	}
	if f.egressErr && strings.Contains(ruleset, "hook egress") {
		f.op("nft-fail egress")
		return errors.New("egress unsupported")
	}
	if f.tables == nil {
		f.tables = map[string]string{}
	}
	for _, table := range []string{macsecGuardTable, macsecMSSTable} {
		if strings.Contains(ruleset, table) {
			f.tables[table] = ruleset
		}
	}
	switch {
	case strings.Contains(ruleset, macsecGuardTable) && strings.Contains(ruleset, "udp sport 51821") && strings.Contains(ruleset, "hook egress"):
		f.op("nft guard-wg+egress")
	case strings.Contains(ruleset, macsecGuardTable) && strings.Contains(ruleset, "udp sport 51821"):
		f.op("nft guard-wg")
	case strings.Contains(ruleset, macsecGuardTable) && strings.Contains(ruleset, "hook egress"):
		f.op("nft guard+egress")
	case strings.Contains(ruleset, macsecGuardTable):
		f.op("nft guard")
	case strings.Contains(ruleset, macsecMSSTable):
		f.op("nft mss %s", regexp.MustCompile(`size set (\d+)`).FindStringSubmatch(ruleset)[1])
	default:
		f.op("nft other")
	}
	return nil
}

func (f *fakeSys) NFTDeleteTable(family, table string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("nft-del %s %s", family, table)
	delete(f.tables, table)
	return nil
}

func (f *fakeSys) NFTList(family, table string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	live, ok := f.tables[table]
	if !ok {
		return "", errors.New("no such table")
	}
	return live, nil
}

var fakePortRE = regexp.MustCompile(`macsec_port=(\d+)`)

func (f *fakeSys) StartMKA(parent, confPath string) (mkaProc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	f.confs[confPath] = string(data)
	port, _ := strconv.Atoi(fakePortRE.FindStringSubmatch(string(data))[1])
	sci, _ := macsecSCI(f.infos[parent].MAC, port)
	for _, l := range f.links {
		if l.Parent == parent && l.SCI == sci {
			return nil, errors.New("EBUSY: duplicate SCI")
		}
	}
	name := fmt.Sprintf("macsec%d", f.nextIndex)
	f.nextIndex++
	f.links = append(f.links, macsecLink{Name: name, Parent: parent, SCI: sci, MTU: f.infos[parent].MTU - macsecOverhead, Validate: "strict", Protect: true, Replay: true})
	f.op("mka %s port=%d", parent, port)
	proc := &fakeProc{}
	f.procs = append(f.procs, proc)
	return proc, nil
}

func (f *fakeSys) Probe() error { return f.probeErr }

func (f *fakeSys) ProbeWG() error { return f.probeWGErr }

func (f *fakeSys) Cmd(name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("cmd %s %s", name, strings.Join(args, " "))
	if name == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "add" {
		mac, _ := net.ParseMAC(fmt.Sprintf("02:00:00:00:%02x:%02x", len(f.infos), f.nextIndex))
		mtu := 1500
		if len(args) >= 5 && args[4] == "wireguard" {
			mtu = 1420
		}
		f.infos[args[2]] = linkInfo{MAC: mac, MTU: mtu, MaxMTU: 65535}
	}
	if name == "ip" && len(args) >= 5 && args[0] == "addr" && args[1] == "replace" {
		if f.addrs == nil {
			f.addrs = map[string][]string{}
		}
		f.addrs[args[4]] = append(f.addrs[args[4]], args[2])
	}
	if name == "wg" && len(args) >= 4 && args[0] == "set" && args[2] == "peer" {
		if f.wgPeers == nil {
			f.wgPeers = map[string]bool{}
		}
		if len(args) >= 5 && args[4] == "remove" {
			delete(f.wgPeers, args[3])
		} else {
			f.wgPeers[args[3]] = true
		}
	}
	return nil
}

func (f *fakeSys) Output(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	joined := name + " " + strings.Join(args, " ")
	switch {
	case joined == "wg show wgmesh latest-handshakes":
		if _, ok := f.infos[meshWGIface]; !ok {
			return nil, errors.New("no device")
		}
		var b strings.Builder
		for pub, ts := range f.handshakes {
			fmt.Fprintf(&b, "%s\t%d\n", pub, ts)
		}
		return []byte(b.String()), nil
	case joined == "wg show wgmesh peers":
		if _, ok := f.infos[meshWGIface]; !ok {
			return nil, errors.New("no device")
		}
		var b strings.Builder
		for pub := range f.wgPeers {
			fmt.Fprintf(&b, "%s\n", pub)
		}
		return []byte(b.String()), nil
	case joined == "ip -o link show type vxlan":
		var b strings.Builder
		i := 10
		for name := range f.infos {
			if strings.HasPrefix(name, meshVXLANPrefix) {
				fmt.Fprintf(&b, "%d: %s: <BROADCAST,MULTICAST> mtu 1500\n", i, name)
				i++
			}
		}
		return []byte(b.String()), nil
	case len(args) == 6 && name == "ip" && args[0] == "-4" && args[1] == "-o" && args[2] == "addr":
		var b strings.Builder
		for _, a := range f.addrs[args[5]] {
			fmt.Fprintf(&b, "2: %s    inet %s scope global %s\n", args[5], a, args[5])
		}
		return []byte(b.String()), nil
	}
	return nil, errors.New("unexpected output command: " + joined)
}

func (f *fakeSys) Exchange(dev string, frame []byte, timeout time.Duration, handle func([]byte) bool) error {
	if err := f.SendFrame(dev, frame); err != nil {
		return err
	}
	return f.RecvFrames(dev, timeout, handle)
}

func (f *fakeSys) SendFrame(dev string, frame []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.op("frame %s %d", dev, frame[14+len(macsecCtlMagic)])
	f.frames = append(f.frames, append([]byte{}, frame...))
	if f.reply != nil {
		if r := f.reply(frame); r != nil {
			f.inbox = append(f.inbox, r)
		}
	}
	return nil
}

func (f *fakeSys) RecvFrames(dev string, timeout time.Duration, handle func([]byte) bool) error {
	for {
		f.mu.Lock()
		if len(f.inbox) == 0 {
			f.mu.Unlock()
			return errMACsecCtlNoAck
		}
		frame := f.inbox[0]
		f.inbox = f.inbox[1:]
		f.mu.Unlock()
		if handle(frame) {
			return nil
		}
	}
}

func (f *fakeSys) Routes(dev string) ([]routeEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]routeEntry{}, f.routes[dev]...), nil
}

func (f *fakeSys) PinRouteMTU(dev string, r routeEntry, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.op("route-mtu %s %s %d", dev, r.Dst, mtu)
	for i := range f.routes[dev] {
		if f.routes[dev][i].Dst == r.Dst {
			f.routes[dev][i].MTU = mtu
		}
	}
	return nil
}

func (f *fakeSys) secure(name string, up, encrypt bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.links {
		if f.links[i].Name == name {
			f.links[i].AdminUp = up
			f.links[i].Encrypt = encrypt
		}
	}
}

func (f *fakeSys) link(name string) (macsecLink, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.links {
		if l.Name == name {
			return l, true
		}
	}
	return macsecLink{}, false
}

func indexOf(ops []string, prefix string) int {
	for i, op := range ops {
		if strings.HasPrefix(op, prefix) {
			return i
		}
	}
	return -1
}

func contains(ops []string, op string) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}

type macsecTestEnv struct {
	dir   string
	sys   *fakeSys
	m     *macsecManager
	clock time.Time
}

func setupMACsecEnv(t *testing.T, leaf bool) *macsecTestEnv {
	t.Helper()
	dir := t.TempDir()
	saved := []*string{&MeshConfigFile, &AuthTokensFile, &MESH_ENABLED_LEAF_PATH, &macsecRunDir, &macsecRequiredFlagPath, &meshBaseConfigPath, &macsecMTUStatePath, &meshWGKeyPath}
	old := make([]string, len(saved))
	for i, p := range saved {
		old[i] = *p
	}
	oldManager := gMACsec
	oldCall := macsecCallLeaf
	oldSync := meshSyncNeighbors
	meshSyncNeighbors = func() {}
	t.Cleanup(func() {
		for i, p := range saved {
			*p = old[i]
		}
		gMACsec = oldManager
		macsecCallLeaf = oldCall
		meshSyncNeighbors = oldSync
	})
	MeshConfigFile = filepath.Join(dir, "mesh.json")
	AuthTokensFile = filepath.Join(dir, "auth_tokens.json")
	MESH_ENABLED_LEAF_PATH = filepath.Join(dir, "enabled")
	macsecRunDir = filepath.Join(dir, "run", "spr-mesh-macsec")
	macsecRequiredFlagPath = filepath.Join(dir, "macsec_required")
	meshBaseConfigPath = filepath.Join(dir, "config.sh")
	macsecMTUStatePath = filepath.Join(dir, "macsec_mtu.json")
	meshWGKeyPath = filepath.Join(dir, "wg_private.key")
	t.Setenv("WANIF", "eth0")

	tokens, _ := json.Marshal([]Token{{Name: DOWNHAUL_TOKEN_NAME, Token: testPairingToken}})
	if err := os.WriteFile(AuthTokensFile, tokens, 0600); err != nil {
		t.Fatal(err)
	}
	if leaf {
		setLeafRouter(true)
	}
	env := &macsecTestEnv{dir: dir, sys: newFakeSys(), clock: time.Unix(1_800_000_000, 0)}
	env.m = newMACsecManager(env.sys)
	env.m.now = func() time.Time { return env.clock }
	env.m.noCtlLoop = true
	gMACsec = env.m
	return env
}

func writeMeshConfig(t *testing.T, config MeshConfig) {
	t.Helper()
	Configmtx.Lock()
	saveConfigLocked(config)
	Configmtx.Unlock()
}

func readMeshConfig() MeshConfig {
	Configmtx.Lock()
	defer Configmtx.Unlock()
	return loadConfigLocked()
}

func enabledLeafConfig(env *macsecTestEnv, confirmed bool) MeshConfig {
	return MeshConfig{LeafMACsec: LeafSideMACsec{
		Enabled:   true,
		Confirmed: confirmed,
		KeyNonce:  testNonce,
		LinkMTU:   1500,
		EnabledAt: env.clock.Add(-macsecApplyDelay).Unix(),
	}}
}

func TestLeafEnableNeverBridgesRawUplink(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))

	env.m.reconcile()
	ops := env.sys.Ops()

	guard := indexOf(ops, "nft guard")
	unbridge := indexOf(ops, "nomaster eth0")
	mka := indexOf(ops, "mka eth0")
	if guard < 0 || unbridge < 0 || mka < 0 {
		t.Fatalf("missing guard/unbridge/mka: %v", ops)
	}
	if !(guard < mka && unbridge < mka) {
		t.Fatalf("MKA started before the uplink was guarded and unbridged: %v", ops)
	}
	if !contains(ops, "nft guard+egress") {
		t.Errorf("egress guard not applied: %v", ops)
	}
	if !contains(ops, "noipv6 eth0") {
		t.Errorf("IPv6 left enabled on the raw uplink: %v", ops)
	}
	if !contains(ops, "mka eth0 port=1") {
		t.Errorf("leaf MKA not on port 1: %v", ops)
	}
	if !contains(ops, "mtu eth0 1532") {
		t.Errorf("uplink MTU not raised for 1500 byte Wi-Fi frames: %v", ops)
	}
	for _, op := range ops {
		if op == "master eth0 br0" {
			t.Fatalf("raw uplink bridged while MACsec is required: %v", ops)
		}
	}
	if !macsecRequiredFlagSet() {
		t.Error("mesh_rules.sh flag not written")
	}
	if l, _ := env.sys.link("macsec0"); l.Master != "" {
		t.Fatalf("unsecured secY bridged: %+v", l)
	}
	status := env.m.Status()
	if status.Role != "leaf" || !status.Enabled || status.Confirmed || status.Links[0].Secured {
		t.Fatalf("status %+v", status)
	}

	conf := filepath.Join(macsecRunDir, "leaf.conf")
	st, err := os.Stat(conf)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("conf mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(macsecRunDir); st.Mode().Perm() != 0700 {
		t.Errorf("run dir mode %v", st.Mode().Perm())
	}
	keys := mustKeys(t, testPairingToken, testNonce)
	data, _ := os.ReadFile(conf)
	if !strings.Contains(string(data), "mka_cak="+hex.EncodeToString(keys.CAK)) || !strings.Contains(string(data), "mka_priority=255") {
		t.Errorf("leaf conf wrong:\n%s", data)
	}
}

func TestLeafBridgesOnlySecuredSecY(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()

	env.sys.secure("macsec0", true, false)
	env.m.reconcile()
	if l, _ := env.sys.link("macsec0"); l.Master == "br0" {
		t.Fatal("bridged a secY without encryption")
	}
	if readMeshConfig().LeafMACsec.Confirmed {
		t.Fatal("confirmed without encryption")
	}

	env.sys.secure("macsec0", true, true)
	env.m.reconcile()
	if l, _ := env.sys.link("macsec0"); l.Master != "br0" {
		t.Fatalf("secured secY not bridged: %v", env.sys.Ops())
	}
	if !readMeshConfig().LeafMACsec.Confirmed {
		t.Fatal("secured link not confirmed")
	}
	if !env.m.Status().Links[0].Secured {
		t.Fatal("status not secured")
	}

	env.sys.secure("macsec0", true, false)
	env.m.reconcile()
	if l, _ := env.sys.link("macsec0"); l.Master == "br0" {
		t.Fatal("insecure secY left in the bridge")
	}
}

func TestLeafPendingRevertsAfterTimeout(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()

	env.clock = env.clock.Add(macsecConfirmTimeout - macsecApplyDelay - time.Second)
	env.m.reconcile()
	if !readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("reverted before the timeout")
	}

	env.clock = env.clock.Add(2 * time.Second)
	env.m.reconcile()
	if readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("never-secured leaf did not revert")
	}
	ops := env.sys.Ops()
	del := indexOf(ops, "del macsec0")
	rejoin := indexOf(ops, "master eth0 br0")
	if del < 0 || rejoin < 0 || del > rejoin {
		t.Fatalf("secY must be removed before the uplink rejoins the bridge: %v", ops)
	}
	if !contains(ops, "nft-del netdev "+macsecGuardTable) {
		t.Errorf("guard left in place after revert: %v", ops)
	}
	if !contains(ops, "mtu eth0 1500") {
		t.Errorf("uplink MTU not restored: %v", ops)
	}
	if macsecRequiredFlagSet() {
		t.Error("mesh_rules.sh flag left after revert")
	}
	for _, p := range env.sys.procs {
		if !p.stopped {
			t.Error("MKA left running")
		}
	}
	if _, err := os.Stat(filepath.Join(macsecRunDir, "leaf.conf")); err == nil {
		t.Error("key material left on disk")
	}
}

func TestLeafConfirmedFailsClosed(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()

	env.clock = env.clock.Add(24 * time.Hour)
	for i := 0; i < 3; i++ {
		env.m.reconcile()
	}
	if !readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("confirmed leaf reverted")
	}
	for _, op := range env.sys.Ops() {
		if op == "master eth0 br0" || strings.HasPrefix(op, "nft-del netdev") {
			t.Fatalf("confirmed leaf weakened its uplink: %v", env.sys.Ops())
		}
	}
}

func TestLeafPendingRevertKeepsConcurrentReenable(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()
	cfg := readMeshConfig().LeafMACsec

	newer := enabledLeafConfig(env, false)
	newer.LeafMACsec.KeyNonce = strings.Repeat("cd", macsecNonceLen)
	writeMeshConfig(t, newer)

	env.clock = env.clock.Add(macsecConfirmTimeout + time.Second)
	env.m.confirmOrRevert(&cfg, false, "eth0")
	if got := readMeshConfig().LeafMACsec; !got.Enabled || got.KeyNonce != newer.LeafMACsec.KeyNonce {
		t.Fatalf("stale revert clobbered a newer enable: %+v", got)
	}
}

func TestLeafWithoutPairingTokenFailsClosed(t *testing.T) {
	env := setupMACsecEnv(t, true)
	os.WriteFile(AuthTokensFile, []byte("[]"), 0600)
	cfg := enabledLeafConfig(env, true)
	writeMeshConfig(t, cfg)
	env.m.reconcile()
	ops := env.sys.Ops()
	if indexOf(ops, "mka") >= 0 {
		t.Fatalf("MKA started without a pairing secret: %v", ops)
	}
	if indexOf(ops, "nft guard") < 0 || indexOf(ops, "nomaster eth0") < 0 {
		t.Fatalf("uplink not guarded: %v", ops)
	}
	if contains(ops, "master eth0 br0") {
		t.Fatal("bridged plaintext uplink")
	}
	if env.m.Status().Links[0].Error == "" {
		t.Error("error not reported")
	}
}

func TestLeafGuardFallsBackWithoutEgressHook(t *testing.T) {
	env := setupMACsecEnv(t, true)
	env.sys.egressErr = true
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()
	env.m.reconcile()
	ops := env.sys.Ops()
	if !contains(ops, "nft guard") {
		t.Fatalf("ingress guard not applied: %v", ops)
	}
	fails := 0
	for _, op := range ops {
		if op == "nft-fail egress" {
			fails++
		}
	}
	if fails != 1 {
		t.Errorf("egress retried %d times", fails)
	}
}

func TestLeafMSSClampWhenUplinkCannotGrow(t *testing.T) {
	env := setupMACsecEnv(t, true)
	info := env.sys.infos["eth0"]
	info.MaxMTU = 1500
	env.sys.infos["eth0"] = info
	cfg := enabledLeafConfig(env, false)
	cfg.LeafMACsec.LinkMTU = 1468
	writeMeshConfig(t, cfg)
	env.m.reconcile()
	ops := env.sys.Ops()
	if !contains(ops, "nft mss 1428") {
		t.Fatalf("MSS clamp missing for a 1468 byte link: %v", ops)
	}
	if indexOf(ops, "mtu eth0") >= 0 {
		t.Errorf("tried to raise an uplink at its max MTU: %v", ops)
	}
}

func TestLeafNoMSSClampOnFullSizeLink(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()
	if indexOf(env.sys.Ops(), "nft mss") >= 0 {
		t.Fatal("clamped a 1500 byte link")
	}
	if l, _ := env.sys.link("macsec0"); l.MTU != 1500 {
		t.Fatalf("secY MTU %d, AP/VLAN clients would lose 1500 byte frames", l.MTU)
	}
}

func TestLeafDisabledDoesNothing(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, MeshConfig{})
	env.m.reconcile()
	if ops := env.sys.Ops(); len(ops) != 0 {
		t.Fatalf("plaintext leaf touched: %v", ops)
	}
}

func TestMKARestartsCleanlyAfterCrash(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()
	env.sys.procs[0].mu.Lock()
	env.sys.procs[0].exited = true
	env.sys.procs[0].mu.Unlock()
	env.m.reconcile()
	ops := env.sys.Ops()
	if len(env.sys.procs) != 2 {
		t.Fatalf("MKA not restarted: %v", ops)
	}
	lastStart := -1
	for i, op := range ops {
		if op == "mka eth0 port=1" {
			lastStart = i
		}
	}
	del := indexOf(ops, "del macsec0")
	if del < 0 || del > lastStart {
		t.Fatalf("stale secY must be removed before MKA restarts (kernel refuses duplicate SCIs): %v", ops)
	}
}

func TestMKARestartsWhenUplinkMACChanges(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, false))
	env.m.reconcile()
	info := env.sys.infos["eth0"]
	info.MAC, _ = net.ParseMAC("7a:11:22:33:44:99")
	env.sys.infos["eth0"] = info
	env.m.reconcile()
	if len(env.sys.procs) != 2 || !env.sys.procs[0].stopped {
		t.Fatal("MKA not restarted for the new SCI")
	}
}

func mainConfigWithLeaves(n, enabled int) MeshConfig {
	config := MeshConfig{}
	for i := 0; i < n; i++ {
		leaf := LeafRouter{IP: fmt.Sprintf("192.168.2.%d", 10+i), APIToken: fmt.Sprintf("%s%02d", testPairingToken[:41], i), TLSCA: "ca"}
		if i < enabled {
			leaf.MACsec = &LeafMACsec{Enabled: true, Port: 2 + i, KeyNonce: testNonce, Parent: "eth1", LinkMTU: 1500, LeafMAC: fmt.Sprintf("00:11:22:33:44:%02x", i)}
		}
		config.LeafRouters = append(config.LeafRouters, leaf)
	}
	return config
}

func TestMainRunsOneAssociationPerLeaf(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(3, 2))
	env.m.reconcile()
	ops := env.sys.Ops()
	if !contains(ops, "mka eth1 port=2") || !contains(ops, "mka eth1 port=3") {
		t.Fatalf("per-leaf MKA missing: %v", ops)
	}
	if len(env.sys.confs) != 2 {
		t.Fatalf("expected 2 confs, got %d", len(env.sys.confs))
	}
	ckns := map[string]bool{}
	for _, conf := range env.sys.confs {
		if !strings.Contains(conf, "mka_priority=16") {
			t.Error("main is not the preferred key server")
		}
		ckn := regexp.MustCompile(`mka_ckn=([0-9a-f]+)`).FindStringSubmatch(conf)[1]
		if ckns[ckn] {
			t.Fatal("two leaves share a CKN")
		}
		ckns[ckn] = true
	}
	status := env.m.Status()
	if status.Role != "main" || status.Strict {
		t.Fatalf("mixed deployment must not be strict: %+v", status)
	}
	if len(status.Links) != 2 || status.Links[0].Interface == "" || status.Links[0].LeafMAC == "" {
		t.Fatalf("links %+v", status.Links)
	}

	writeMeshConfig(t, mainConfigWithLeaves(3, 3))
	env.m.reconcile()
	if !env.m.Status().Strict {
		t.Fatal("all-MACsec deployment not strict")
	}

	config := mainConfigWithLeaves(3, 3)
	config.LeafRouters = config.LeafRouters[1:]
	writeMeshConfig(t, config)
	env.m.reconcile()
	if !env.sys.procs[0].stopped {
		t.Fatal("removed leaf's MKA still running")
	}
	if _, ok := env.sys.link("macsec0"); ok {
		t.Fatal("removed leaf's secY still present")
	}
}

func TestMainWithoutMACsecIsIdle(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(2, 0))
	env.m.reconcile()
	if ops := env.sys.Ops(); len(ops) != 0 {
		t.Fatalf("main touched the system with no MACsec leaves: %v", ops)
	}
	if env.m.Status().Strict {
		t.Fatal("strict without MACsec")
	}
}

func TestMainWeakTokenNotStarted(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(1, 1)
	config.LeafRouters[0].APIToken = "short"
	writeMeshConfig(t, config)
	env.m.reconcile()
	if indexOf(env.sys.Ops(), "mka") >= 0 {
		t.Fatal("MKA started with a weak pairing secret")
	}
	if env.m.Status().Links[0].Error == "" {
		t.Fatal("error not reported")
	}
}

func TestMACsecStatusLeaksNoSecrets(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config := mainConfigWithLeaves(2, 2)
	writeMeshConfig(t, config)
	env.m.reconcile()
	data, _ := json.Marshal(env.m.Status())
	for _, leaf := range config.LeafRouters {
		keys := mustKeys(t, leaf.APIToken, leaf.MACsec.KeyNonce)
		for _, secret := range []string{leaf.APIToken, hex.EncodeToString(keys.CAK), leaf.MACsec.KeyNonce} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("status leaks %q: %s", secret, data)
			}
		}
	}
}

func TestMainNodeCleansUpAfterLeavingLeafMode(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	setLeafRouter(false)
	env.m.reconcile()
	if macsecRequiredFlagSet() || !env.sys.procs[0].stopped {
		t.Fatal("leaf MACsec state left behind after leaving leaf mode")
	}
	if contains(env.sys.Ops(), "master eth0 br0") {
		t.Fatal("non-leaf must not rebuild the mesh bridge")
	}
}

func TestMeshWANIFFromConfig(t *testing.T) {
	setupMACsecEnv(t, false)
	t.Setenv("WANIF", "")
	os.WriteFile(meshBaseConfigPath, []byte("#!/bin/sh\nWANIF=\"eth2\"\nLANIF=eth3\n"), 0600)
	if got := meshWANIF(); got != "eth2" {
		t.Fatalf("WANIF %q", got)
	}
	os.WriteFile(meshBaseConfigPath, []byte("WANIF=\"$(reboot)\"\n"), 0600)
	if got := meshWANIF(); got != "" {
		t.Fatalf("accepted %q", got)
	}
}

func TestParseLinkInfoAndRoute(t *testing.T) {
	info, err := parseLinkInfo([]byte(`[{"ifname":"eth0","mtu":1500,"min_mtu":68,"max_mtu":9216,"address":"7a:11:22:33:44:55","master":"br0"}]`))
	if err != nil || info.MaxMTU != 9216 || info.Master != "br0" || info.MAC.String() != "7a:11:22:33:44:55" {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := parseLinkInfo([]byte(`[]`)); err == nil {
		t.Error("missing interface accepted")
	}
	wg, err := parseLinkInfo([]byte(`[{"ifindex":7,"ifname":"wgmesh","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":8940,"link_type":"none","min_mtu":0,"max_mtu":2147483552,"linkinfo":{"info_kind":"wireguard"}}]`))
	if err != nil || wg.MTU != 8940 || wg.MAC != nil {
		t.Fatalf("wireguard link: %+v %v", wg, err)
	}
	if _, err := parseLinkInfo([]byte(`[{"ifname":"eth0","mtu":1500,"address":"zz:11"}]`)); err == nil {
		t.Error("malformed address accepted")
	}
	dev, err := parseRouteDev([]byte(`[{"dst":"192.168.2.10","dev":"eth1","prefsrc":"192.168.2.1"}]`))
	if err != nil || dev != "eth1" {
		t.Fatalf("%q %v", dev, err)
	}
	if _, err := parseRouteDev([]byte(`[{"dev":"eth1;reboot"}]`)); err == nil {
		t.Error("bad dev accepted")
	}
}

func TestMKAStartsDespiteStaleSecYFromPreviousRun(t *testing.T) {
	env := setupMACsecEnv(t, true)
	sci, _ := macsecSCI(env.sys.infos["eth0"].MAC, macsecLeafPort)
	env.sys.links = append(env.sys.links, macsecLink{Name: "macsec9", Parent: "eth0", SCI: sci, Validate: "strict", Protect: true, Replay: true})
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	ops := env.sys.Ops()
	if indexOf(ops, "del macsec9") < 0 || indexOf(ops, "mka eth0") < 0 || indexOf(ops, "del macsec9") > indexOf(ops, "mka eth0") {
		t.Fatalf("stale secY blocked MKA: %v", ops)
	}
	if !env.m.Status().Links[0].Running {
		t.Fatal("MKA not running")
	}
}

func TestLeafWaitsForEnableReplyBeforeGuarding(t *testing.T) {
	env := setupMACsecEnv(t, true)
	cfg := enabledLeafConfig(env, false)
	cfg.LeafMACsec.EnabledAt = env.clock.Unix()
	writeMeshConfig(t, cfg)
	env.m.reconcile()
	if ops := env.sys.Ops(); len(ops) != 0 {
		t.Fatalf("leaf changed its uplink before the enable reply could leave: %v", ops)
	}
	env.clock = env.clock.Add(macsecApplyDelay)
	env.m.reconcile()
	if indexOf(env.sys.Ops(), "nft guard") < 0 {
		t.Fatal("leaf never applied MACsec")
	}
}

func TestLeafGuardInstalledOnceAndRepaired(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	env.m.reconcile()
	env.m.reconcile()
	count := func() int {
		n := 0
		for _, op := range env.sys.Ops() {
			if strings.HasPrefix(op, "nft guard") {
				n++
			}
		}
		return n
	}
	if got := count(); got != 1 {
		t.Fatalf("guard rebuilt %d times over three passes", got)
	}
	env.sys.mu.Lock()
	env.sys.tables[macsecGuardTable] = "table netdev mesh_macsec_guard {\n}\n"
	env.sys.mu.Unlock()
	env.m.reconcile()
	if got := count(); got != 2 {
		t.Fatal("flushed guard not repaired")
	}
	env.sys.NFTDeleteTable("netdev", macsecGuardTable)
	env.m.reconcile()
	if got := count(); got != 3 {
		t.Fatal("deleted guard not restored")
	}
}

func TestUnreadableConfigKeepsMACsec(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	before := len(env.sys.Ops())
	for _, bad := range []string{"", "{", "garbage"} {
		os.WriteFile(MeshConfigFile, []byte(bad), 0600)
		env.m.reconcile()
	}
	for _, op := range env.sys.Ops()[before:] {
		if op == "master eth0 br0" || strings.HasPrefix(op, "nft-del") || strings.HasPrefix(op, "del ") {
			t.Fatalf("unreadable config weakened the uplink: %v", env.sys.Ops()[before:])
		}
	}
	if !macsecRequiredFlagSet() || env.sys.procs[0].stopped {
		t.Fatal("unreadable config stopped MACsec")
	}
}

func TestUnreadableConfigKeepsMainStatus(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(2, 2))
	env.m.reconcile()
	os.WriteFile(MeshConfigFile, []byte(""), 0600)
	env.m.reconcile()
	if s := env.m.Status(); !s.Strict || len(s.Links) != 2 {
		t.Fatalf("unreadable config dropped strict mode: %+v", s)
	}
	for _, p := range env.sys.procs {
		if p.stopped {
			t.Fatal("unreadable config stopped a participant")
		}
	}
}

func TestSaveConfigIsAtomicAndPrivate(t *testing.T) {
	setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	st, err := os.Stat(MeshConfigFile)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", err, st)
	}
	entries, _ := os.ReadDir(filepath.Dir(MeshConfigFile))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if got := readMeshConfig(); len(got.LeafRouters) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestLeavingLeafModeClearsMACsecConfig(t *testing.T) {
	env := setupMACsecEnv(t, true)
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	setLeafRouter(false)
	env.m.reconcile()
	if readMeshConfig().LeafMACsec.Enabled {
		t.Fatal("MACsec config left behind after leaving leaf mode")
	}
	setLeafRouter(true)
	env.m.reconcile()
	if indexOf(env.sys.Ops()[len(env.sys.Ops())-1:], "mka") >= 0 || macsecRequiredFlagSet() {
		t.Fatal("re-entering leaf mode resurrected the old association")
	}
}

func TestLeafDeletesStaleSecYWithOldSCI(t *testing.T) {
	env := setupMACsecEnv(t, true)
	env.sys.links = append(env.sys.links, macsecLink{Name: "macsec9", Parent: "eth0", SCI: 0x7a1122334400aa01, Master: "br0", AdminUp: true, Encrypt: true, Protect: true, Replay: true, Validate: "strict"})
	writeMeshConfig(t, enabledLeafConfig(env, true))
	env.m.reconcile()
	if _, ok := env.sys.link("macsec9"); ok {
		t.Fatalf("stale secY with an old SCI left in place: %v", env.sys.Ops())
	}
}

func TestStatusUnavailableBeforeFirstReconcile(t *testing.T) {
	env := setupMACsecEnv(t, false)
	rec := httptest.NewRecorder()
	macsecStatusHandler(rec, httptest.NewRequest(http.MethodGet, "/macsec/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status served before the first reconcile: %d", rec.Code)
	}
	env.m.reconcile()
	rec = httptest.NewRecorder()
	macsecStatusHandler(rec, httptest.NewRequest(http.MethodGet, "/macsec/status", nil))
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
}

func TestNoPeerErrorWhenMKANeverSecures(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	env.m.reconcile()
	if e := env.m.Status().Links[0].Error; e != "" {
		t.Fatalf("error before the timeout: %s", e)
	}
	env.clock = env.clock.Add(macsecNoPeerAfter + time.Second)
	env.m.reconcile()
	if e := env.m.Status().Links[0].Error; e != "Encrypted Link (MACsec) not up on eth1" {
		t.Fatalf("no actionable error for a missing MKA peer: %q", e)
	}
	env.m.reconcile()
	env.sys.secure(env.m.Status().Links[0].Interface, true, true)
	env.m.reconcile()
	if e := env.m.Status().Links[0].Error; e != "" {
		t.Fatalf("error kept after securing: %s", e)
	}
}

func TestOriginalMTURestoredAfterPluginRestart(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	env.m.reconcile()
	if !contains(env.sys.Ops(), "mtu eth1 1532") {
		t.Fatalf("parent MTU not raised: %v", env.sys.Ops())
	}
	writeMeshConfig(t, mainConfigWithLeaves(1, 0))
	restarted := newMACsecManager(env.sys)
	restarted.now = env.m.now
	restarted.reconcile()
	if !contains(env.sys.Ops(), "mtu eth1 1500") {
		t.Fatalf("original MTU lost across a plugin restart: %v", env.sys.Ops())
	}
	if data, _ := os.ReadFile(macsecMTUStatePath); strings.Contains(string(data), "eth1") {
		t.Fatalf("restored MTU still recorded: %s", data)
	}
}

func TestPlaintextRoutesKeepOriginalMTUOnRaisedParent(t *testing.T) {
	env := setupMACsecEnv(t, false)
	env.sys.routes = map[string][]routeEntry{"eth1": {
		{Family: 4, Dst: "192.168.2.4/30", Protocol: "kernel", Scope: "link", PrefSrc: "192.168.2.5"},
		{Family: 4, Dst: "10.0.0.0/8", Gateway: "192.168.2.6", Metric: 50},
		{Family: 4, Dst: "192.168.2.8/30", Protocol: "kernel", Scope: "link", MTU: 1400},
		{Family: 4, Dst: "169.254.83.2", Scope: "link", PrefSrc: "169.254.83.1"},
	}}
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	env.m.reconcile()
	ops := env.sys.Ops()
	if indexOf(ops, "route-mtu eth1 169.254.83.2") >= 0 {
		t.Fatalf("encrypted underlay route pinned to the plaintext MTU: %v", ops)
	}
	raise := indexOf(ops, "mtu eth1 1532")
	if raise < 0 || !contains(ops, "route-mtu eth1 192.168.2.4/30 1500") || !contains(ops, "route-mtu eth1 10.0.0.0/8 1500") {
		t.Fatalf("plaintext routes on the raised LAN parent not pinned to 1500: %v", ops)
	}
	if contains(ops, "route-mtu eth1 192.168.2.8/30 1500") {
		t.Fatal("raised a route MTU an admin had set lower")
	}
	before := len(ops)
	env.m.reconcile()
	if indexOf(env.sys.Ops()[before:], "route-mtu") >= 0 {
		t.Fatal("pinned routes re-pinned every pass")
	}
}

func TestNoRoutePinningWhenParentWasNotRaised(t *testing.T) {
	env := setupMACsecEnv(t, false)
	info := env.sys.infos["eth1"]
	info.MTU = 9000
	env.sys.infos["eth1"] = info
	env.sys.routes = map[string][]routeEntry{"eth1": {{Family: 4, Dst: "192.168.2.4/30"}}}
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	env.m.reconcile()
	if indexOf(env.sys.Ops(), "route-mtu") >= 0 {
		t.Fatalf("pinned routes on a jumbo LAN the plugin did not change: %v", env.sys.Ops())
	}
}

func TestParseRoutesAndReplaceArgs(t *testing.T) {
	routes, err := parseRoutes([]byte(`[
		{"dst":"10.9.0.0/24","protocol":"kernel","scope":"link","prefsrc":"10.9.0.1","flags":[]},
		{"dst":"10.9.1.0/24","gateway":"10.9.0.254","metric":50,"flags":[],"metrics":[{"mtu":1500}]},
		{"dst":"default","gateway":"10.9.0.254","flags":[]},
		{"type":"unreachable","dst":"10.9.2.0/24","flags":[]},
		{"dst":"10.9.3.0/24","nexthops":[{"gateway":"10.9.0.2"},{"gateway":"10.9.0.3"}]},
		{"dst":"10.9.4.0/24 via 1.1.1.1","flags":[]},
		{"dst":"10.9.5.0/24","protocol":"kernel; reboot","flags":[]}
	]`), 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 || routes[1].MTU != 1500 || routes[2].Dst != "default" {
		t.Fatalf("%+v", routes)
	}
	got := strings.Join(routeReplaceArgs("eth1", routes[0], 1500), " ")
	if got != "-4 route replace 10.9.0.0/24 dev eth1 proto kernel scope link src 10.9.0.1 mtu lock 1500" {
		t.Fatalf("%s", got)
	}
	got = strings.Join(routeReplaceArgs("eth1", routes[1], 1500), " ")
	if got != "-4 route replace 10.9.1.0/24 via 10.9.0.254 dev eth1 metric 50 mtu lock 1500" {
		t.Fatalf("%s", got)
	}
}

func TestStuckMKAParticipantIsRestarted(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	env.m.reconcile()
	env.sys.secure("macsec0", true, true)
	env.m.reconcile()
	env.sys.secure("macsec0", false, false)
	env.m.reconcile()
	env.clock = env.clock.Add(macsecMKARestart - time.Second)
	env.m.reconcile()
	if len(env.sys.procs) != 1 {
		t.Fatal("restarted before the timeout")
	}
	env.clock = env.clock.Add(2 * time.Second)
	env.m.reconcile()
	env.m.reconcile()
	if len(env.sys.procs) != 2 || !env.sys.procs[0].stopped {
		t.Fatalf("stuck participant not restarted: %d procs", len(env.sys.procs))
	}
	env.m.reconcile()
	if len(env.sys.procs) != 2 {
		t.Fatal("participant restarted again before the next interval")
	}
	env.clock = env.clock.Add(macsecMKARestart + time.Second)
	env.m.reconcile()
	env.m.reconcile()
	if len(env.sys.procs) != 3 {
		t.Fatalf("restart not retried: %d procs", len(env.sys.procs))
	}
	env.sys.secure("macsec2", true, true)
	env.m.reconcile()
	env.clock = env.clock.Add(10 * macsecMKARestart)
	env.m.reconcile()
	if len(env.sys.procs) != 3 {
		t.Fatal("secured participant restarted")
	}
}
