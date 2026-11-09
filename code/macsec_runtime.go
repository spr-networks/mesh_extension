package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var macsecRunDir = TEST_PREFIX + "/run/spr-mesh-macsec"

var macsecRequiredFlagPath = TEST_PREFIX + "/configs/base/mesh_macsec_required"
var macsecMTUStatePath = TEST_PREFIX + "/state/plugins/mesh/macsec_mtu.json"
var meshBaseConfigPath = TEST_PREFIX + "/configs/base/config.sh"

type linkInfo struct {
	MAC    net.HardwareAddr
	MTU    int
	MaxMTU int
	Master string
}

type mkaProc interface {
	Exited() bool
	Stop()
}

type macsecSys interface {
	Links() ([]macsecLink, error)
	LinkInfo(name string) (linkInfo, error)
	RouteDev(ip string) (string, error)
	SetMTU(name string, mtu int) error
	SetMaster(name, master string) error
	SetUp(name string) error
	DeleteLink(name string) error
	DisableIPv6(name string) error
	NFT(ruleset string) error
	NFTDeleteTable(family, table string) error
	NFTList(family, table string) (string, error)
	StartMKA(parent, confPath string) (mkaProc, error)
	Probe() error
	Routes(dev string) ([]routeEntry, error)
	Cmd(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	ProbeWG() error
	SendFrame(dev string, frame []byte) error
	Exchange(dev string, frame []byte, timeout time.Duration, handle func([]byte) bool) error
	RecvFrames(dev string, timeout time.Duration, handle func([]byte) bool) error
}

type routeEntry struct {
	Family   int
	Dst      string
	Gateway  string
	Protocol string
	Scope    string
	PrefSrc  string
	Metric   int
}

type MACsecLinkStatus struct {
	LeafIP    string `json:",omitempty"`
	Interface string
	Member    string `json:",omitempty"`
	Parent    string
	Port      int
	LeafMAC   string `json:",omitempty"`
	LinkMTU   int
	Mode      string `json:",omitempty"`
	Underlay  int    `json:",omitempty"`
	Running   bool
	Secured   bool
	Pending   bool   `json:",omitempty"`
	Error     string `json:",omitempty"`
}

type MACsecStatus struct {
	Role      string
	Strict    bool
	Enabled   bool
	Confirmed bool
	Links     []MACsecLinkStatus
}

type mkaRunning struct {
	proc      mkaProc
	confHash  [32]byte
	parent    string
	parentMAC string
	sci       uint64
	confPath  string
}

type macsecManager struct {
	mu         sync.Mutex
	sys        macsecSys
	now        func() time.Time
	isLeaf     func() bool
	procs      map[string]*mkaRunning
	status     MACsecStatus
	leafActive bool
	origMTU    map[string]int
	mtuInUse   map[string]bool
	noEgress   bool
	guardRules string
	guardLive  string
	mssMTU     int
	ready      bool
	mtuLoaded  bool
	unsecured  map[string]time.Time
	restarted  map[string]time.Time
	ctlMu      sync.Mutex
	leafCtl    *macsecCtlKeys
	leafCtlMAC net.HardwareAddr
	ctlOffAt   time.Time
	ctlRunning bool
	noCtlLoop  bool
	wgApplied  map[string]string
	wgParents  map[string]bool
	wgMainMTU  int
	mtuTesting map[string]bool
	mtuRaised  map[string]time.Time
	wgSeen     bool
	kick       chan struct{}

	bridgeGone      bool
	bridgeGuard     string
	bridgeGuardLive string
}

func newMACsecManager(sys macsecSys) *macsecManager {
	return &macsecManager{
		sys:        sys,
		now:        time.Now,
		isLeaf:     isLeafRouter,
		procs:      map[string]*mkaRunning{},
		origMTU:    map[string]int{},
		unsecured:  map[string]time.Time{},
		restarted:  map[string]time.Time{},
		wgApplied:  map[string]string{},
		wgParents:  map[string]bool{},
		mtuTesting: map[string]bool{},
		mtuRaised:  map[string]time.Time{},
		mtuInUse:   map[string]bool{},
		kick:       make(chan struct{}, 1),
	}
}

var gMACsec = newMACsecManager(execMACsecSys{})

func (m *macsecManager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *macsecManager) KickAfter(d time.Duration) {
	time.AfterFunc(d, m.Kick)
}

func (m *macsecManager) run() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		m.reconcile()
		select {
		case <-ticker.C:
		case <-m.kick:
		}
	}
}

func (m *macsecManager) Status() MACsecStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.status
	status.Links = append([]MACsecLinkStatus{}, m.status.Links...)
	return status
}

func loadMeshConfigChecked() (MeshConfig, error) {
	config := MeshConfig{}
	data, err := os.ReadFile(MeshConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(data, &config)
	return config, err
}

func (m *macsecManager) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

func (m *macsecManager) reconcile() {
	Configmtx.Lock()
	config, err := loadMeshConfigChecked()
	Configmtx.Unlock()
	if err != nil {
		fmt.Println("[-] macsec: mesh config unreadable, keeping current state:", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.mtuInUse = map[string]bool{}
	m.loadOrigMTU()
	if m.isLeaf() {
		m.reconcileLeaf(config)
	} else {
		m.reconcileMain(config)
	}
	m.restoreUnusedMTU()
	m.ready = true
}

func meshWANIF() string {
	if wanif := os.Getenv("WANIF"); meshIfaceRE.MatchString(wanif) {
		return wanif
	}
	data, err := os.ReadFile(meshBaseConfigPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "WANIF=") {
			continue
		}
		wanif := strings.Trim(strings.TrimPrefix(line, "WANIF="), `"'`)
		if meshIfaceRE.MatchString(wanif) {
			return wanif
		}
	}
	return ""
}

func writeSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return atomicWriteFile(path, data)
}

func atomicWriteFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func setMACsecRequiredFlag(on bool) {
	if on {
		if _, err := os.Stat(macsecRequiredFlagPath); err != nil {
			if err := os.WriteFile(macsecRequiredFlagPath, nil, 0600); err != nil {
				fmt.Println("[-] macsec: failed to write required flag", err)
			}
		}
		return
	}
	if err := os.Remove(macsecRequiredFlagPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Println("[-] macsec: failed to remove required flag", err)
	}
}

func macsecRequiredFlagSet() bool {
	_, err := os.Stat(macsecRequiredFlagPath)
	return err == nil
}

func (m *macsecManager) ensureMKA(inst mkaInstance, parentMAC net.HardwareAddr) (bool, error) {
	conf, err := renderWPAConf(inst)
	if err != nil {
		return false, err
	}
	sci, err := macsecSCI(parentMAC, inst.Port)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256([]byte(conf))
	if running, ok := m.procs[inst.ID]; ok {
		if !running.proc.Exited() && running.confHash == hash &&
			running.parent == inst.Parent && running.parentMAC == parentMAC.String() {
			return true, nil
		}
		m.stopMKA(inst.ID)
	}

	m.deleteSecY(inst.Parent, sci)

	path := filepath.Join(macsecRunDir, inst.ID+".conf")
	if err := writeSecretFile(path, []byte(conf)); err != nil {
		return false, err
	}
	proc, err := m.sys.StartMKA(inst.Parent, path)
	if err != nil {
		return false, err
	}
	m.procs[inst.ID] = &mkaRunning{
		proc:      proc,
		confHash:  hash,
		parent:    inst.Parent,
		parentMAC: parentMAC.String(),
		sci:       sci,
		confPath:  path,
	}
	return true, nil
}

func (m *macsecManager) stopMKA(id string) {
	running, ok := m.procs[id]
	if !ok {
		return
	}
	running.proc.Stop()
	m.deleteSecY(running.parent, running.sci)
	os.Remove(running.confPath)
	delete(m.procs, id)
}

func (m *macsecManager) deleteSecY(parent string, sci uint64) {
	links, err := m.sys.Links()
	if err != nil {
		return
	}
	for _, link := range links {
		if link.Parent == parent && link.SCI == sci {
			if err := m.sys.DeleteLink(link.Name); err != nil {
				fmt.Println("[-] macsec: failed to delete secY", link.Name, err)
			}
		}
	}
}

func parentCapableMTU(info linkInfo) int {
	max := info.MaxMTU
	if max < info.MTU {
		max = info.MTU
	}
	return macsecCapableMTU(max)
}

func (m *macsecManager) raiseParentMTU(parent string, info linkInfo) linkInfo {
	return m.raiseParentMTUTo(parent, info, macsecWantParent)
}

func (m *macsecManager) raiseParentMTUTo(parent string, info linkInfo, target int) linkInfo {
	m.mtuInUse[parent] = true
	if info.MTU >= target {
		return info
	}
	if info.MaxMTU > 0 && info.MaxMTU < target {
		target = info.MaxMTU
	}
	if target <= info.MTU {
		return info
	}
	if _, saved := m.origMTU[parent]; !saved {
		m.origMTU[parent] = info.MTU
		m.saveOrigMTU()
	}
	if err := m.sys.SetMTU(parent, target); err != nil {
		fmt.Println("[-] macsec: could not raise MTU of", parent, err)
		return info
	}
	if m.mtuRaised == nil {
		m.mtuRaised = map[string]time.Time{}
	}
	m.mtuRaised[parent] = m.now()
	info.MTU = target
	return info
}

func (m *macsecManager) loadOrigMTU() {
	if m.mtuLoaded {
		return
	}
	m.mtuLoaded = true
	data, err := os.ReadFile(macsecMTUStatePath)
	if err != nil {
		return
	}
	saved := map[string]int{}
	if json.Unmarshal(data, &saved) != nil {
		return
	}
	for parent, mtu := range saved {
		if _, ok := m.origMTU[parent]; !ok && meshIfaceRE.MatchString(parent) && mtu >= 576 {
			m.origMTU[parent] = mtu
		}
	}
}

func (m *macsecManager) saveOrigMTU() {
	data, _ := json.Marshal(m.origMTU)
	if err := atomicWriteFile(macsecMTUStatePath, data); err != nil {
		fmt.Println("[-] macsec: failed to save original MTUs", err)
	}
}

func (m *macsecManager) restoreUnusedMTU() {
	changed := false
	for parent, mtu := range m.origMTU {
		if m.mtuInUse[parent] {
			continue
		}
		if _, err := m.sys.LinkInfo(parent); err == nil {
			if err := m.sys.SetMTU(parent, mtu); err != nil {
				fmt.Println("[-] macsec: could not restore MTU of", parent, err)
			} else {
				m.sys.Cmd("ethtool", "-r", parent)
			}
		}
		delete(m.origMTU, parent)
		delete(m.mtuRaised, parent)
		changed = true
	}
	if changed {
		m.saveOrigMTU()
	}
}

func (m *macsecManager) restartIfStuck(id string, secured bool) {
	if secured {
		delete(m.restarted, id)
		return
	}
	since, ok := m.unsecured[id]
	if !ok {
		return
	}
	if last, ok := m.restarted[id]; ok && last.After(since) {
		since = last
	}
	if m.now().Sub(since) < macsecMKARestart {
		return
	}
	if _, running := m.procs[id]; !running {
		return
	}
	fmt.Println("[-] macsec: MKA participant", id, "not secured, restarting it")
	m.stopMKA(id)
	m.restarted[id] = m.now()
}

func (m *macsecManager) noPeerError(id string, parent string, secured bool) string {
	return m.noPeerErrorFor(backhaulLabel(backhaulMACsec), id, parent, secured)
}

func (m *macsecManager) noPeerErrorFor(label string, id string, parent string, secured bool) string {
	if secured {
		delete(m.unsecured, id)
		return ""
	}
	since, ok := m.unsecured[id]
	if !ok {
		m.unsecured[id] = m.now()
		return ""
	}
	if m.now().Sub(since) < macsecNoPeerAfter {
		return ""
	}
	return fmt.Sprintf("%s not up on %s", label, parent)
}

func (m *macsecManager) applyLinkMTU(link macsecLink, linkMTU int, parent linkInfo) {
	target := linkMTU
	if limit := parent.MTU - macsecOverhead; limit < target {
		target = limit
	}
	if target < macsecMinLinkMTU || link.MTU == target {
		return
	}
	if err := m.sys.SetMTU(link.Name, target); err != nil {
		fmt.Println("[-] macsec: could not set MTU of", link.Name, err)
	}
}

func (m *macsecManager) stopAllMKA(keep map[string]bool) {
	for id := range m.procs {
		if !keep[id] {
			m.stopMKA(id)
		}
	}
}

func (m *macsecManager) reconcileMain(config MeshConfig) {
	if m.leafActive || macsecRequiredFlagSet() || config.LeafMACsec.Enabled {
		m.teardownLeaf(meshWANIF())
		if _, err := os.Stat(MESH_ENABLED_LEAF_PATH); config.LeafMACsec.Enabled && errors.Is(err, os.ErrNotExist) {
			Configmtx.Lock()
			if current, err := loadMeshConfigChecked(); err == nil && current.LeafMACsec.Enabled {
				current.LeafMACsec = LeafSideMACsec{}
				saveConfigLocked(current)
			}
			Configmtx.Unlock()
		}
	}

	desired := map[string]bool{}
	wgPeers := map[string]bool{}
	wgVX := map[string]bool{}
	m.wgMainMTU = 0
	for _, leaf := range config.LeafRouters {
		if leaf.MACsec != nil && leaf.MACsec.Enabled && storedMode(leaf.MACsec.Mode) == backhaulWireGuard {
			mtu := meshUnderlay(leaf.MACsec.Jumbo, leaf.MACsec.UnderlayMTU) - meshWGOverhead
			if m.wgMainMTU == 0 || mtu < m.wgMainMTU {
				m.wgMainMTU = mtu
			}
		}
	}
	status := MACsecStatus{Role: "main", Links: []MACsecLinkStatus{}}
	enabled := 0
	var links []macsecLink
	var linksErr error
	linksLoaded := false

	for _, leaf := range config.LeafRouters {
		if leaf.MACsec == nil || !leaf.MACsec.Enabled {
			if leaf.MACsecPending {
				status.Links = append(status.Links, MACsecLinkStatus{
					LeafIP:  leaf.IP,
					Pending: true,
					Error:   macsecPendingError(leaf.IP),
				})
			}
			continue
		}
		enabled++
		cfg := leaf.MACsec
		st := MACsecLinkStatus{
			LeafIP:  leaf.IP,
			Parent:  cfg.Parent,
			Port:    cfg.Port,
			LeafMAC: cfg.LeafMAC,
			LinkMTU: effectiveLinkMTU(cfg.Mode, cfg.Jumbo, cfg.UnderlayMTU, cfg.LinkMTU),
			Mode:    storedMode(cfg.Mode),
		}
		if st.Mode == backhaulWireGuard {
			if cfg.Jumbo {
				st.Underlay = cfg.UnderlayMTU
			}
			info, err := m.sys.LinkInfo(cfg.Parent)
			if err != nil {
				st.Error = "parent interface unavailable"
				status.Links = append(status.Links, st)
				continue
			}
			if cfg.Jumbo {
				info = m.raiseParentMTUTo(cfg.Parent, info, meshJumboMTU)
			}
			wgPeers[cfg.LeafPublicKey] = true
			wgVX[meshVXLANMain(cfg.Port)] = true
			if err := m.mainWGLeaf(leaf, info, &st); err != nil {
				st.Error = err.Error()
			} else {
				st.Running = true
			}
			if msg := m.noPeerErrorFor(backhaulLabel(backhaulWireGuard), fmt.Sprintf("wg-%d", cfg.Port), cfg.Parent, st.Secured); msg != "" && st.Error == "" {
				st.Error = msg
			}
			m.maybeTestMTU(leaf, st.Secured)
			status.Links = append(status.Links, st)
			continue
		}
		keys, err := deriveMACsecKeys(leaf.APIToken, cfg.KeyNonce)
		if err != nil {
			st.Error = err.Error()
			status.Links = append(status.Links, st)
			continue
		}
		inst := mkaInstance{
			ID:       fmt.Sprintf("main-%d", cfg.Port),
			Parent:   cfg.Parent,
			Port:     cfg.Port,
			Priority: macsecPrioMain,
			Keys:     keys,
		}
		if err := inst.validate(); err != nil {
			st.Error = err.Error()
			status.Links = append(status.Links, st)
			continue
		}
		info, err := m.sys.LinkInfo(cfg.Parent)
		if err != nil {
			st.Error = "parent interface unavailable"
			status.Links = append(status.Links, st)
			continue
		}
		if cfg.Jumbo {
			info = m.raiseParentMTU(cfg.Parent, info)
		}
		desired[inst.ID] = true
		running, err := m.ensureMKA(inst, info.MAC)
		st.Running = running
		if err != nil {
			st.Error = err.Error()
		}
		if !linksLoaded {
			links, linksErr = m.sys.Links()
			linksLoaded = true
		}
		if linksErr == nil {
			sci, _ := macsecSCI(info.MAC, cfg.Port)
			if link, ok := findMACsecLink(links, cfg.Parent, sci); ok {
				st.Member = link.Name
				st.Secured = link.Forwarding()
				m.applyLinkMTU(link, cfg.LinkMTU, info)
			}
		}
		if msg := m.noPeerError(inst.ID, cfg.Parent, st.Secured); msg != "" && st.Error == "" {
			st.Error = msg
		}
		m.restartIfStuck(inst.ID, st.Secured)
		status.Links = append(status.Links, st)
	}

	m.stopAllMKA(desired)
	if len(wgPeers) > 0 || m.wgSeen {
		m.cleanupMainWG(wgPeers, wgVX)
		m.wgSeen = len(wgPeers) > 0
	}
	m.reconcileMeshBridge(status.Links)
	status.Strict = len(config.LeafRouters) > 0 && enabled == len(config.LeafRouters)
	m.status = status
}

func (m *macsecManager) installGuard(ruleset string) error {
	return m.installTable("netdev", macsecGuardTable, ruleset, &m.guardRules, &m.guardLive)
}

func (m *macsecManager) installTable(family, table, ruleset string, rules, live *string) error {
	if ruleset == *rules {
		if cur, err := m.sys.NFTList(family, table); err == nil && cur == *live {
			return nil
		}
	}
	if err := m.sys.NFT(ruleset); err != nil {
		*rules = ""
		return err
	}
	*rules = ruleset
	*live, _ = m.sys.NFTList(family, table)
	return nil
}

func (m *macsecManager) applyGuard(wanif string) error {
	if !m.noEgress {
		ruleset, err := renderLeafGuard(wanif, true)
		if err != nil {
			return err
		}
		if err := m.installGuard(ruleset); err == nil {
			return nil
		}
		m.noEgress = true
		fmt.Println("[-] macsec: netdev egress hook unavailable, guarding ingress only")
	}
	ruleset, err := renderLeafGuard(wanif, false)
	if err != nil {
		return err
	}
	return m.installGuard(ruleset)
}

func (m *macsecManager) applyMSSClamp(linkMTU int) {
	if linkMTU >= macsecEthernetMTU || linkMTU < macsecMinLinkMTU {
		if m.mssMTU != 0 {
			m.sys.NFTDeleteTable("bridge", macsecMSSTable)
			m.mssMTU = 0
		}
		return
	}
	ruleset, err := renderMSSClamp(linkMTU)
	if err == nil {
		err = m.sys.NFT(ruleset)
	}
	if err != nil {
		fmt.Println("[-] macsec: failed to install MSS clamp", err)
		return
	}
	m.mssMTU = linkMTU
}

func (m *macsecManager) reconcileLeaf(config MeshConfig) {
	cfg := config.LeafMACsec
	wanif := meshWANIF()
	if !cfg.Enabled {
		m.ctlMu.Lock()
		if m.ctlOffAt.IsZero() {
			m.leafCtl = nil
		}
		m.ctlMu.Unlock()
		if m.leafActive || macsecRequiredFlagSet() || len(m.procs) > 0 {
			m.teardownLeaf(wanif)
		}
		m.status = MACsecStatus{Role: "leaf", Links: []MACsecLinkStatus{}}
		return
	}

	if !m.leafActive && !cfg.Confirmed && m.now().Sub(time.Unix(cfg.EnabledAt, 0)) < macsecApplyDelay {
		m.status = MACsecStatus{Role: "leaf", Enabled: true, Links: []MACsecLinkStatus{}}
		return
	}

	m.leafActive = true
	setMACsecRequiredFlag(true)
	st := MACsecLinkStatus{Parent: wanif, Port: macsecLeafPort, LinkMTU: cfg.LinkMTU}
	defer func() {
		m.status = MACsecStatus{
			Role:      "leaf",
			Enabled:   cfg.Enabled,
			Confirmed: cfg.Confirmed,
			Links:     []MACsecLinkStatus{st},
		}
	}()

	secured := false
	defer func() {
		if cfg.Enabled {
			m.confirmOrRevert(&cfg, secured, wanif)
		}
	}()

	if !meshIfaceRE.MatchString(wanif) {
		st.Error = "uplink interface unknown"
		return
	}

	wg := storedMode(cfg.Mode) == backhaulWireGuard
	var guardErr error
	if wg {
		guardErr = m.applyGuardWG(wanif, cfg.Port)
	} else {
		guardErr = m.applyGuard(wanif)
	}
	if guardErr != nil {
		st.Error = "guard: " + guardErr.Error()
	}

	info, err := m.sys.LinkInfo(wanif)
	if err != nil {
		st.Error = "uplink interface unavailable"
		return
	}
	if info.Master != "" {
		if err := m.sys.SetMaster(wanif, ""); err != nil {
			st.Error = "unbridge uplink: " + err.Error()
			return
		}
	}
	m.sys.DisableIPv6(wanif)
	m.sys.SetUp(wanif)
	if cfg.Jumbo && wg {
		info = m.raiseParentMTUTo(wanif, info, meshJumboMTU)
	} else if cfg.Jumbo {
		info = m.raiseParentMTU(wanif, info)
	}

	token, err := getToken(DOWNHAUL_TOKEN_NAME)
	if err != nil {
		st.Error = "pairing token unavailable"
		return
	}
	keys, err := deriveMACsecKeys(token.Token, cfg.KeyNonce)
	if err != nil {
		st.Error = err.Error()
		return
	}
	if ctl, err := deriveMACsecCtlKeys(token.Token, cfg.KeyNonce); err == nil {
		m.ctlMu.Lock()
		m.leafCtl = &ctl
		m.leafCtlMAC = info.MAC
		m.ctlOffAt = time.Time{}
		start := !m.ctlRunning && !m.noCtlLoop
		if start {
			m.ctlRunning = true
		}
		m.ctlMu.Unlock()
		if start {
			go m.ctlListen(wanif)
		}
	}
	if wg {
		st.Mode = backhaulWireGuard
		st.Port = cfg.Port
		if cfg.Jumbo {
			st.Underlay = cfg.UnderlayMTU
		}
		m.stopAllMKA(nil)
		if links, err := m.sys.Links(); err == nil {
			for _, link := range links {
				if link.Parent == wanif {
					m.sys.DeleteLink(link.Name)
				}
			}
		}
		ok, err := m.leafWG(cfg, wanif, token.Token, &st)
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Running = true
		}
		secured = ok
		st.Secured = secured
		if msg := m.noPeerErrorFor(backhaulLabel(backhaulWireGuard), "leaf-wg", wanif, secured); msg != "" && st.Error == "" {
			st.Error = msg
		}
		m.applyMSSClamp(effectiveLinkMTU(cfg.Mode, cfg.Jumbo, cfg.UnderlayMTU, cfg.LinkMTU))
		return
	}
	if m.linkExists(meshWGIface) {
		m.teardownWG(wanif)
	}
	inst := mkaInstance{ID: "leaf", Parent: wanif, Port: macsecLeafPort, Priority: macsecPrioLeaf, Keys: keys}
	running, err := m.ensureMKA(inst, info.MAC)
	st.Running = running
	if err != nil {
		st.Error = err.Error()
		return
	}
	m.stopAllMKA(map[string]bool{"leaf": true})

	links, err := m.sys.Links()
	if err != nil {
		st.Error = err.Error()
		return
	}
	sci, _ := macsecSCI(info.MAC, macsecLeafPort)
	for _, stale := range links {
		if stale.Parent == wanif && stale.SCI != sci {
			if err := m.sys.DeleteLink(stale.Name); err != nil {
				fmt.Println("[-] macsec: failed to delete stale secY", stale.Name, err)
			}
		}
	}
	link, found := findMACsecLink(links, wanif, sci)
	if found {
		st.Interface = link.Name
		m.applyLinkMTU(link, cfg.LinkMTU, info)
		switch {
		case link.Forwarding():
			secured = true
			if link.Master != BRIDGE_IFACE {
				if err := m.sys.SetMaster(link.Name, BRIDGE_IFACE); err != nil {
					st.Error = "bridge secY: " + err.Error()
					secured = false
				}
			}
		case link.AdminUp && link.Master == BRIDGE_IFACE:
			if err := m.sys.SetMaster(link.Name, ""); err != nil {
				st.Error = "unbridge insecure secY: " + err.Error()
			}
		}
	}
	st.Secured = secured
	if msg := m.noPeerError("leaf", wanif, secured); msg != "" && st.Error == "" {
		st.Error = msg
	}
	m.restartIfStuck("leaf", secured)
	m.applyMSSClamp(effectiveLinkMTU(cfg.Mode, cfg.Jumbo, cfg.UnderlayMTU, cfg.LinkMTU))
}

func (m *macsecManager) confirmOrRevert(cfg *LeafSideMACsec, secured bool, wanif string) {
	if cfg.Confirmed {
		return
	}
	if secured {
		Configmtx.Lock()
		config := loadConfigLocked()
		if config.LeafMACsec.Enabled && config.LeafMACsec.KeyNonce == cfg.KeyNonce {
			config.LeafMACsec.Confirmed = true
			saveConfigLocked(config)
			cfg.Confirmed = true
		}
		Configmtx.Unlock()
		return
	}
	started := time.Unix(cfg.EnabledAt, 0)
	if m.now().Sub(started) < macsecConfirmTimeout {
		return
	}
	fmt.Println("[-] macsec: link never secured, reverting to the plaintext uplink")
	Configmtx.Lock()
	config := loadConfigLocked()
	if config.LeafMACsec.Enabled && !config.LeafMACsec.Confirmed && config.LeafMACsec.KeyNonce == cfg.KeyNonce {
		config.LeafMACsec = LeafSideMACsec{}
		saveConfigLocked(config)
		cfg.Enabled = false
	}
	Configmtx.Unlock()
	if !cfg.Enabled {
		m.teardownLeaf(wanif)
	}
}

func (m *macsecManager) teardownLeaf(wanif string) {
	m.stopAllMKA(nil)
	if meshIfaceRE.MatchString(wanif) {
		if links, err := m.sys.Links(); err == nil {
			for _, link := range links {
				if link.Parent == wanif {
					m.sys.DeleteLink(link.Name)
				}
			}
		}
	}
	m.teardownWG(wanif)
	m.sys.NFTDeleteTable("netdev", macsecGuardTable)
	m.guardRules = ""
	m.guardLive = ""
	m.sys.NFTDeleteTable("bridge", macsecMSSTable)
	m.mssMTU = 0
	delete(m.mtuInUse, wanif)
	m.restoreUnusedMTU()
	if meshIfaceRE.MatchString(wanif) && m.isLeaf() {
		if _, err := m.sys.LinkInfo(BRIDGE_IFACE); err == nil {
			if err := m.sys.SetMaster(wanif, BRIDGE_IFACE); err != nil {
				fmt.Println("[-] macsec: failed to rejoin uplink to bridge", err)
			}
			m.sys.SetUp(wanif)
		}
	}
	setMACsecRequiredFlag(false)
	m.leafActive = false
}

type execMACsecSys struct{}

func runQuiet(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func checkIfname(name string) error {
	if !meshIfaceRE.MatchString(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

func (execMACsecSys) Links() ([]macsecLink, error) {
	out, err := exec.Command("ip", "-d", "-j", "link", "show", "type", "macsec").Output()
	if err != nil {
		return nil, err
	}
	return parseMACsecLinks(out)
}

func linkInfoArgs(name string) []string {
	if strings.HasPrefix(name, meshVXLANPrefix) {
		return []string{"-j", "link", "show", "dev", name}
	}
	return []string{"-d", "-j", "link", "show", "dev", name}
}

func parseLinkInfo(data []byte) (linkInfo, error) {
	var entries []struct {
		Address string `json:"address"`
		MTU     int    `json:"mtu"`
		MaxMTU  int    `json:"max_mtu"`
		Master  string `json:"master"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return linkInfo{}, err
	}
	if len(entries) != 1 {
		return linkInfo{}, errors.New("interface not found")
	}
	var mac net.HardwareAddr
	if entries[0].Address != "" {
		parsed, err := net.ParseMAC(entries[0].Address)
		if err != nil {
			return linkInfo{}, err
		}
		mac = parsed
	}
	return linkInfo{MAC: mac, MTU: entries[0].MTU, MaxMTU: entries[0].MaxMTU, Master: entries[0].Master}, nil
}

func (execMACsecSys) LinkInfo(name string) (linkInfo, error) {
	if err := checkIfname(name); err != nil {
		return linkInfo{}, err
	}
	out, err := exec.Command("ip", linkInfoArgs(name)...).Output()
	if err != nil {
		return linkInfo{}, err
	}
	return parseLinkInfo(out)
}

func parseRouteDev(data []byte) (string, error) {
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return "", err
	}
	if len(routes) == 0 || !meshIfaceRE.MatchString(routes[0].Dev) {
		return "", errors.New("no route")
	}
	return routes[0].Dev, nil
}

func (execMACsecSys) RouteDev(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", errors.New("invalid ip")
	}
	out, err := exec.Command("ip", "-j", "route", "get", ip).Output()
	if err != nil {
		return "", err
	}
	return parseRouteDev(out)
}

func (execMACsecSys) SetMTU(name string, mtu int) error {
	if err := checkIfname(name); err != nil {
		return err
	}
	return runQuiet("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu))
}

func (execMACsecSys) SetMaster(name, master string) error {
	if err := checkIfname(name); err != nil {
		return err
	}
	if master == "" {
		return runQuiet("ip", "link", "set", "dev", name, "nomaster")
	}
	if err := checkIfname(master); err != nil {
		return err
	}
	return runQuiet("ip", "link", "set", "dev", name, "master", master)
}

func (execMACsecSys) SetUp(name string) error {
	if err := checkIfname(name); err != nil {
		return err
	}
	return runQuiet("ip", "link", "set", "dev", name, "up")
}

func (execMACsecSys) DeleteLink(name string) error {
	if err := checkIfname(name); err != nil {
		return err
	}
	return runQuiet("ip", "link", "del", "dev", name)
}

func (execMACsecSys) DisableIPv6(name string) error {
	if err := checkIfname(name); err != nil {
		return err
	}
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("1"), 0644)
}

func (execMACsecSys) NFT(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func checkNFTTable(family, table string) error {
	if family != "netdev" && family != "bridge" {
		return errors.New("unexpected nft family")
	}
	if table != macsecGuardTable && table != macsecMSSTable && table != meshBridgeGuardTable {
		return errors.New("unexpected nft table")
	}
	return nil
}

func (execMACsecSys) NFTDeleteTable(family, table string) error {
	if err := checkNFTTable(family, table); err != nil {
		return err
	}
	return exec.Command("nft", "delete", "table", family, table).Run()
}

func (execMACsecSys) NFTList(family, table string) (string, error) {
	if err := checkNFTTable(family, table); err != nil {
		return "", err
	}
	out, err := exec.Command("nft", "list", "table", family, table).Output()
	return string(out), err
}

type execMKAProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *execMKAProc) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *execMKAProc) Stop() {
	if p.Exited() {
		return
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

func (execMACsecSys) StartMKA(parent, confPath string) (mkaProc, error) {
	if err := checkIfname(parent); err != nil {
		return nil, err
	}
	cmd := exec.Command("wpa_supplicant", "-D", "macsec_linux", "-i", parent, "-c", confPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	proc := &execMKAProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(proc.done)
	}()
	return proc, nil
}

const macsecProbeParent = "sprmsprobe"
const macsecProbeLink = "sprmsprobe0"

var routeWordRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

func parseRoutes(data []byte, family int) ([]routeEntry, error) {
	var raw []struct {
		Type     string            `json:"type"`
		Dst      string            `json:"dst"`
		Gateway  string            `json:"gateway"`
		Protocol string            `json:"protocol"`
		Scope    string            `json:"scope"`
		PrefSrc  string            `json:"prefsrc"`
		Metric   int               `json:"metric"`
		Nexthops []json.RawMessage `json:"nexthops"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	routes := []routeEntry{}
	for _, r := range raw {
		if (r.Type != "" && r.Type != "unicast") || len(r.Nexthops) > 0 {
			continue
		}
		if r.Dst != "default" {
			if _, _, err := net.ParseCIDR(r.Dst); err != nil && net.ParseIP(r.Dst) == nil {
				continue
			}
		}
		if (r.Gateway != "" && net.ParseIP(r.Gateway) == nil) || (r.PrefSrc != "" && net.ParseIP(r.PrefSrc) == nil) {
			continue
		}
		if (r.Protocol != "" && !routeWordRE.MatchString(r.Protocol)) || (r.Scope != "" && !routeWordRE.MatchString(r.Scope)) {
			continue
		}
		routes = append(routes, routeEntry{Family: family, Dst: r.Dst, Gateway: r.Gateway, Protocol: r.Protocol, Scope: r.Scope, PrefSrc: r.PrefSrc, Metric: r.Metric})
	}
	return routes, nil
}

func (execMACsecSys) Routes(dev string) ([]routeEntry, error) {
	if err := checkIfname(dev); err != nil {
		return nil, err
	}
	routes := []routeEntry{}
	for _, family := range []int{4, 6} {
		out, err := exec.Command("ip", "-j", "-"+strconv.Itoa(family), "route", "show", "dev", dev).Output()
		if err != nil {
			return nil, err
		}
		parsed, err := parseRoutes(out, family)
		if err != nil {
			return nil, err
		}
		routes = append(routes, parsed...)
	}
	return routes, nil
}

func (execMACsecSys) SendFrame(dev string, frame []byte) error {
	if err := checkIfname(dev); err != nil {
		return err
	}
	return sendRawFrame(dev, frame)
}

func (execMACsecSys) Exchange(dev string, frame []byte, timeout time.Duration, handle func([]byte) bool) error {
	if err := checkIfname(dev); err != nil {
		return err
	}
	return exchangeRawFrame(dev, frame, timeout, handle)
}

func (execMACsecSys) RecvFrames(dev string, timeout time.Duration, handle func([]byte) bool) error {
	if err := checkIfname(dev); err != nil {
		return err
	}
	return recvRawFrames(dev, timeout, handle)
}

func (execMACsecSys) Probe() error {
	help, _ := exec.Command("wpa_supplicant", "-h").CombinedOutput()
	if !bytes.Contains(help, []byte("macsec_linux")) {
		return errors.New("wpa_supplicant with the macsec_linux driver is not installed")
	}
	exec.Command("ip", "link", "del", "dev", macsecProbeParent).Run()
	if err := runQuiet("ip", "link", "add", "name", macsecProbeParent, "type", "dummy"); err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	defer exec.Command("ip", "link", "del", "dev", macsecProbeParent).Run()
	if err := runQuiet("ip", "link", "add", "link", macsecProbeParent, "name", macsecProbeLink, "type", "macsec"); err != nil {
		return errors.New("kernel MACsec support (macsec module) is unavailable")
	}
	return nil
}
