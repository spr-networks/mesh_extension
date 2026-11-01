package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	backhaulMACsec    = "macsec"
	backhaulWireGuard = "wireguard"

	meshWGIface       = "wgmesh"
	meshWGPort        = 51821
	meshVXLANPort     = 4789
	meshVXLANLeaf     = "mshvx0"
	meshVXLANPrefix   = "mshvx"
	meshWGOverhead    = 60
	meshVXLANOverhead = 50
	meshJumboMTU      = 9000
	meshWGFresh       = 3 * time.Minute
	meshWGMaxPort     = 254
)

var meshWGKeyPath = TEST_PREFIX + "/configs/mesh/wg_private.key"

func requestedMode(mode string) string {
	if mode == backhaulMACsec {
		return backhaulMACsec
	}
	return backhaulWireGuard
}

func backhaulLabel(mode string) string {
	if storedMode(mode) == backhaulWireGuard {
		return "Encrypted Link (WireGuard)"
	}
	return "Encrypted Link (MACsec)"
}

func storedMode(mode string) string {
	if mode == backhaulWireGuard {
		return backhaulWireGuard
	}
	return backhaulMACsec
}

func wgCapableUnderlay(info linkInfo) int {
	max := info.MaxMTU
	if max < info.MTU {
		max = info.MTU
	}
	if max > meshJumboMTU {
		max = meshJumboMTU
	}
	return max
}

func meshUnderlayIP(port int) string {
	return fmt.Sprintf("169.254.83.%d", port)
}

func isMeshUnderlayRoute(dst string) bool {
	ip := net.ParseIP(strings.TrimSuffix(dst, "/32"))
	if ip == nil || ip.To4() == nil {
		return false
	}
	ip4 := ip.To4()
	return ip4[0] == 169 && ip4[1] == 254 && ip4[2] == 83
}

func meshTunnelIP(port int) string {
	return fmt.Sprintf("169.254.84.%d", port)
}

const meshMainSide = 1

func meshVXLANMain(port int) string {
	return fmt.Sprintf("%s%d", meshVXLANPrefix, port)
}

func validWGPort(port int) bool {
	return port >= macsecMainPortFirst && port <= meshWGMaxPort
}

func wgInnerMTU(underlay int) int {
	mtu := underlay - meshWGOverhead - meshVXLANOverhead
	if mtu > macsecEthernetMTU {
		mtu = macsecEthernetMTU
	}
	return mtu
}

func parseWGKey(key string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid WireGuard key")
	}
	return raw, nil
}

func clampX25519(k []byte) {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

func loadOrCreateWGKey() (string, error) {
	data, err := os.ReadFile(meshWGKeyPath)
	if err == nil {
		raw, err := parseWGKey(strings.TrimSpace(string(data)))
		if err != nil {
			return "", err
		}
		priv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	clampX25519(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(meshWGKeyPath), 0700); err != nil {
		return "", err
	}
	if err := atomicWriteFile(meshWGKeyPath, []byte(base64.StdEncoding.EncodeToString(raw)+"\n")); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func deriveWGPSK(secret string, nonceHex string) (string, error) {
	if _, err := deriveMACsecKeys(secret, nonceHex); err != nil {
		return "", err
	}
	nonce, _ := decodeMACsecNonce(nonceHex)
	psk, err := hkdf.Key(sha256.New, []byte(secret), nonce, macsecKDFLabel+" wg psk", 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(psk), nil
}

func parseWGHandshakes(out []byte) map[string]int64 {
	hs := map[string]int64{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		hs[fields[0]] = ts
	}
	return hs
}

func renderLeafGuardWG(wanif string, port int, egress bool) (string, error) {
	if !meshIfaceRE.MatchString(wanif) {
		return "", fmt.Errorf("invalid uplink interface %q", wanif)
	}
	if !validWGPort(port) {
		return "", fmt.Errorf("invalid mesh port %d", port)
	}
	main := meshUnderlayIP(meshMainSide)
	leaf := meshUnderlayIP(port)
	var b strings.Builder
	fmt.Fprintf(&b, "table netdev %s\ndelete table netdev %s\ntable netdev %s {\n", macsecGuardTable, macsecGuardTable, macsecGuardTable)
	fmt.Fprintf(&b, "\tchain ingress {\n\t\ttype filter hook ingress device \"%s\" priority -500; policy drop;\n", wanif)
	fmt.Fprintf(&b, "\t\tether type arp arp daddr ip %s accept\n", leaf)
	fmt.Fprintf(&b, "\t\tether type 0x88b5 accept\n")
	fmt.Fprintf(&b, "\t\tip saddr %s ip daddr %s udp sport %d udp dport %d accept\n\t}\n", main, leaf, meshWGPort, meshWGPort)
	if egress {
		fmt.Fprintf(&b, "\tchain egress {\n\t\ttype filter hook egress device \"%s\" priority -500; policy drop;\n", wanif)
		fmt.Fprintf(&b, "\t\tether type arp arp saddr ip %s accept\n", leaf)
		fmt.Fprintf(&b, "\t\tether type 0x88b5 accept\n")
		fmt.Fprintf(&b, "\t\tip saddr %s ip daddr %s udp sport %d udp dport %d accept\n\t}\n", leaf, main, meshWGPort, meshWGPort)
	}
	b.WriteString("}\n")
	return b.String(), nil
}

func (m *macsecManager) applyGuardWG(wanif string, port int) error {
	if !m.noEgress {
		ruleset, err := renderLeafGuardWG(wanif, port, true)
		if err != nil {
			return err
		}
		if err := m.installGuard(ruleset); err == nil {
			return nil
		}
		m.noEgress = true
	}
	ruleset, err := renderLeafGuardWG(wanif, port, false)
	if err != nil {
		return err
	}
	return m.installGuard(ruleset)
}

func (m *macsecManager) linkExists(name string) bool {
	_, err := m.sys.LinkInfo(name)
	return err == nil
}

func (m *macsecManager) applyOnce(key string, value string, apply func() error) error {
	if m.wgApplied[key] == value {
		return nil
	}
	if err := apply(); err != nil {
		return err
	}
	m.wgApplied[key] = value
	return nil
}

func (m *macsecManager) ensureWGIface(localTunnelIP string, mtu int) error {
	if !m.linkExists(meshWGIface) {
		if err := m.sys.Cmd("ip", "link", "add", meshWGIface, "type", "wireguard"); err != nil {
			return err
		}
		for key := range m.wgApplied {
			if key == "wg-iface" || strings.HasPrefix(key, "peer-") {
				delete(m.wgApplied, key)
			}
		}
	}
	if err := m.applyOnce("wg-iface", meshWGKeyPath+localTunnelIP, func() error {
		if err := m.sys.Cmd("wg", "set", meshWGIface, "private-key", meshWGKeyPath, "listen-port", strconv.Itoa(meshWGPort)); err != nil {
			return err
		}
		return m.sys.Cmd("ip", "addr", "replace", localTunnelIP+"/32", "dev", meshWGIface)
	}); err != nil {
		return err
	}
	if info, err := m.sys.LinkInfo(meshWGIface); err == nil && info.MTU != mtu {
		m.sys.SetMTU(meshWGIface, mtu)
	}
	return m.sys.SetUp(meshWGIface)
}

func (m *macsecManager) ensureWGPeer(pub, pskPath, peerTunnelIP, endpoint, localTunnelIP string) error {
	value := strings.Join([]string{pskPath, peerTunnelIP, endpoint, localTunnelIP}, " ")
	return m.applyOnce("peer-"+pub, value, func() error {
		if err := m.sys.Cmd("wg", "set", meshWGIface, "peer", pub, "preshared-key", pskPath,
			"allowed-ips", peerTunnelIP+"/32", "endpoint", endpoint+":"+strconv.Itoa(meshWGPort),
			"persistent-keepalive", "15"); err != nil {
			return err
		}
		return m.sys.Cmd("ip", "route", "replace", peerTunnelIP+"/32", "dev", meshWGIface, "src", localTunnelIP)
	})
}

func (m *macsecManager) ensureVXLAN(name string, vni int, local, remote string, mtu int) error {
	if !m.linkExists(name) {
		if err := m.sys.Cmd("ip", "link", "add", name, "type", "vxlan", "id", strconv.Itoa(vni),
			"local", local, "remote", remote, "dstport", strconv.Itoa(meshVXLANPort), "nolearning"); err != nil {
			return err
		}
	}
	if info, err := m.sys.LinkInfo(name); err == nil && info.MTU != mtu {
		m.sys.SetMTU(name, mtu)
	}
	return m.sys.SetUp(name)
}

func (m *macsecManager) wgHandshakeFresh(pub string) bool {
	out, err := m.sys.Output("wg", "show", meshWGIface, "latest-handshakes")
	if err != nil {
		return false
	}
	ts, ok := parseWGHandshakes(out)[pub]
	if !ok || ts == 0 {
		return false
	}
	return m.now().Sub(time.Unix(ts, 0)) < meshWGFresh
}

func writePSK(port int, psk string) (string, error) {
	path := filepath.Join(macsecRunDir, fmt.Sprintf("psk-%d", port))
	return path, writeSecretFile(path, []byte(psk+"\n"))
}

func underlayOrDefault(mtu int) int {
	if mtu < macsecEthernetMTU {
		return macsecEthernetMTU
	}
	return mtu
}

func (m *macsecManager) mainWGLeaf(leaf LeafRouter, info linkInfo, st *MACsecLinkStatus) error {
	cfg := leaf.MACsec
	if !validWGPort(cfg.Port) {
		return fmt.Errorf("invalid mesh port %d", cfg.Port)
	}
	if _, err := parseWGKey(cfg.LeafPublicKey); err != nil {
		return err
	}
	if _, err := loadOrCreateWGKey(); err != nil {
		return err
	}
	psk, err := deriveWGPSK(leaf.APIToken, cfg.KeyNonce)
	if err != nil {
		return err
	}
	pskPath, err := writePSK(cfg.Port, psk)
	if err != nil {
		return err
	}
	underlay := underlayOrDefault(cfg.UnderlayMTU)
	if err := m.applyOnce("underlay-"+cfg.Parent+"-"+strconv.Itoa(cfg.Port), "set", func() error {
		if err := m.sys.Cmd("ip", "addr", "replace", meshUnderlayIP(meshMainSide)+"/32", "dev", cfg.Parent); err != nil {
			return err
		}
		return m.sys.Cmd("ip", "route", "replace", meshUnderlayIP(cfg.Port)+"/32", "dev", cfg.Parent, "src", meshUnderlayIP(meshMainSide))
	}); err != nil {
		return err
	}
	m.wgParents[cfg.Parent] = true
	if err := m.ensureWGIface(meshTunnelIP(meshMainSide), m.wgMainMTU); err != nil {
		return err
	}
	if err := m.ensureWGPeer(cfg.LeafPublicKey, pskPath, meshTunnelIP(cfg.Port), meshUnderlayIP(cfg.Port), meshTunnelIP(meshMainSide)); err != nil {
		return err
	}
	name := meshVXLANMain(cfg.Port)
	if err := m.ensureVXLAN(name, cfg.Port, meshTunnelIP(meshMainSide), meshTunnelIP(cfg.Port), wgInnerMTU(underlay)); err != nil {
		return err
	}
	st.Interface = name
	st.Secured = m.wgHandshakeFresh(cfg.LeafPublicKey)
	return nil
}

func (m *macsecManager) cleanupMainWG(desiredPeers map[string]bool, desiredVX map[string]bool) {
	if out, err := m.sys.Output("wg", "show", meshWGIface, "peers"); err == nil {
		for _, pub := range strings.Fields(string(out)) {
			if !desiredPeers[pub] {
				m.sys.Cmd("wg", "set", meshWGIface, "peer", pub, "remove")
				delete(m.wgApplied, "peer-"+pub)
			}
		}
	}
	if out, err := m.sys.Output("ip", "-o", "link", "show", "type", "vxlan"); err == nil {
		for _, name := range vxlanNames(out) {
			if strings.HasPrefix(name, meshVXLANPrefix) && !desiredVX[name] {
				m.sys.DeleteLink(name)
			}
		}
	}
	if len(desiredPeers) == 0 {
		if m.linkExists(meshWGIface) {
			m.sys.DeleteLink(meshWGIface)
		}
		for parent := range m.wgParents {
			m.sys.Cmd("ip", "addr", "del", meshUnderlayIP(meshMainSide)+"/32", "dev", parent)
			delete(m.wgParents, parent)
		}
		for key := range m.wgApplied {
			delete(m.wgApplied, key)
		}
	}
}

func vxlanNames(out []byte) []string {
	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if i := strings.Index(name, "@"); i >= 0 {
			name = name[:i]
		}
		if meshIfaceRE.MatchString(name) {
			names = append(names, name)
		}
	}
	return names
}

func (m *macsecManager) leafWG(cfg LeafSideMACsec, wanif string, token string, st *MACsecLinkStatus) (bool, error) {
	if !validWGPort(cfg.Port) {
		return false, fmt.Errorf("invalid mesh port %d", cfg.Port)
	}
	if _, err := parseWGKey(cfg.MainPublicKey); err != nil {
		return false, err
	}
	if _, err := loadOrCreateWGKey(); err != nil {
		return false, err
	}
	psk, err := deriveWGPSK(token, cfg.KeyNonce)
	if err != nil {
		return false, err
	}
	pskPath, err := writePSK(cfg.Port, psk)
	if err != nil {
		return false, err
	}
	underlay := underlayOrDefault(cfg.UnderlayMTU)
	local := meshUnderlayIP(cfg.Port)
	if err := m.applyOnce("underlay-"+wanif, local, func() error {
		if err := m.sys.Cmd("ip", "addr", "replace", local+"/32", "dev", wanif); err != nil {
			return err
		}
		return m.sys.Cmd("ip", "route", "replace", meshUnderlayIP(meshMainSide)+"/32", "dev", wanif, "src", local)
	}); err != nil {
		return false, err
	}
	if err := m.ensureWGIface(meshTunnelIP(cfg.Port), underlay-meshWGOverhead); err != nil {
		return false, err
	}
	if err := m.ensureWGPeer(cfg.MainPublicKey, pskPath, meshTunnelIP(meshMainSide), meshUnderlayIP(meshMainSide), meshTunnelIP(cfg.Port)); err != nil {
		return false, err
	}
	if err := m.ensureVXLAN(meshVXLANLeaf, cfg.Port, meshTunnelIP(cfg.Port), meshTunnelIP(meshMainSide), wgInnerMTU(underlay)); err != nil {
		return false, err
	}
	st.Interface = meshVXLANLeaf
	secured := m.wgHandshakeFresh(cfg.MainPublicKey)
	if secured {
		if info, err := m.sys.LinkInfo(meshVXLANLeaf); err == nil && info.Master != BRIDGE_IFACE {
			if err := m.sys.SetMaster(meshVXLANLeaf, BRIDGE_IFACE); err != nil {
				return false, err
			}
		}
	}
	return secured, nil
}

func (m *macsecManager) teardownWG(wanif string) {
	for _, name := range []string{meshVXLANLeaf, meshWGIface} {
		if m.linkExists(name) {
			m.sys.DeleteLink(name)
		}
	}
	if meshIfaceRE.MatchString(wanif) {
		if out, err := m.sys.Output("ip", "-4", "-o", "addr", "show", "dev", wanif); err == nil {
			for _, f := range strings.Fields(string(out)) {
				if strings.HasPrefix(f, "169.254.83.") {
					m.sys.Cmd("ip", "addr", "del", f, "dev", wanif)
				}
			}
		}
	}
	for key := range m.wgApplied {
		delete(m.wgApplied, key)
	}
}

func (execMACsecSys) Cmd(name string, args ...string) error {
	if name != "ip" && name != "wg" {
		return errors.New("unexpected command")
	}
	return runQuiet(name, args...)
}

func (execMACsecSys) Output(name string, args ...string) ([]byte, error) {
	if name != "ip" && name != "wg" {
		return nil, errors.New("unexpected command")
	}
	return execOutput(name, args...)
}

const wgProbeLink = "sprwgprobe"
const vxProbeLink = "sprvxprobe"

func (execMACsecSys) ProbeWG() error {
	if _, err := execLookPath("wg"); err != nil {
		return errors.New("wireguard-tools is not installed")
	}
	execRun("ip", "link", "del", "dev", wgProbeLink)
	if err := runQuiet("ip", "link", "add", wgProbeLink, "type", "wireguard"); err != nil {
		return errors.New("kernel WireGuard support is unavailable")
	}
	execRun("ip", "link", "del", "dev", wgProbeLink)
	execRun("ip", "link", "del", "dev", vxProbeLink)
	if err := runQuiet("ip", "link", "add", vxProbeLink, "type", "vxlan", "id", "4094", "dstport", strconv.Itoa(meshVXLANPort), "local", "127.0.0.1"); err != nil {
		return errors.New("kernel VXLAN support is unavailable")
	}
	execRun("ip", "link", "del", "dev", vxProbeLink)
	return nil
}

func execOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func execLookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func execRun(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
