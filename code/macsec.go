package main

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	macsecKDFLabel     = "spr-mesh-macsec-v1"
	macsecCAKLen       = 32
	macsecCKNLen       = 16
	macsecNonceLen     = 32
	macsecMinSecretLen = 32

	macsecOverhead    = 32
	macsecEthernetMTU = 1500
	macsecMinLinkMTU  = 1280
	macsecWantParent  = macsecEthernetMTU + macsecOverhead

	macsecLeafPort      = 1
	macsecMainPortFirst = 2
	macsecMainPortLast  = 65000

	macsecPrioMain = 16
	macsecPrioLeaf = 255

	macsecConfirmTimeout = 3 * time.Minute
	macsecApplyDelay     = 2 * time.Second
	macsecNoPeerAfter    = time.Minute
	macsecMKARestart     = 30 * time.Second

	macsecReplayWindow = 0
)

type LeafMACsec struct {
	Enabled  bool
	Port     int
	KeyNonce string
	Parent   string
	LinkMTU  int
	LeafMAC  string
}

type LeafSideMACsec struct {
	Enabled   bool
	Confirmed bool
	KeyNonce  string
	LinkMTU   int
	EnabledAt int64
}

type macsecKeys struct {
	CAK []byte
	CKN []byte
}

func newMACsecNonce() (string, error) {
	nonce := make([]byte, macsecNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func decodeMACsecNonce(nonceHex string) ([]byte, error) {
	if len(nonceHex) != 2*macsecNonceLen {
		return nil, errors.New("invalid MACsec key nonce length")
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, errors.New("invalid MACsec key nonce encoding")
	}
	return nonce, nil
}

func deriveMACsecKeys(secret string, nonceHex string) (macsecKeys, error) {
	if len(secret) < macsecMinSecretLen {
		return macsecKeys{}, errors.New("pairing secret too short for MACsec key derivation")
	}
	nonce, err := decodeMACsecNonce(nonceHex)
	if err != nil {
		return macsecKeys{}, err
	}
	cak, err := hkdf.Key(sha256.New, []byte(secret), nonce, macsecKDFLabel+" cak", macsecCAKLen)
	if err != nil {
		return macsecKeys{}, err
	}
	ckn, err := hkdf.Key(sha256.New, []byte(secret), nonce, macsecKDFLabel+" ckn", macsecCKNLen)
	if err != nil {
		return macsecKeys{}, err
	}
	return macsecKeys{CAK: cak, CKN: ckn}, nil
}

type mkaInstance struct {
	ID       string
	Parent   string
	Port     int
	Priority int
	Keys     macsecKeys
}

func validMACsecPort(port int) bool {
	return port >= 1 && port <= 65534
}

func (inst mkaInstance) validate() error {
	if !meshIfaceRE.MatchString(inst.Parent) {
		return fmt.Errorf("invalid MACsec parent interface %q", inst.Parent)
	}
	if !validMACsecPort(inst.Port) {
		return fmt.Errorf("invalid MACsec port %d", inst.Port)
	}
	if inst.Priority < 0 || inst.Priority > 255 {
		return fmt.Errorf("invalid MKA priority %d", inst.Priority)
	}
	if len(inst.Keys.CAK) != macsecCAKLen || len(inst.Keys.CKN) != macsecCKNLen {
		return errors.New("invalid MKA key length")
	}
	return nil
}

func renderWPAConf(inst mkaInstance) (string, error) {
	if err := inst.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`eapol_version=3
ap_scan=0
network={
	key_mgmt=NONE
	eapol_flags=0
	macsec_policy=1
	macsec_integ_only=0
	macsec_replay_protect=1
	macsec_replay_window=%d
	macsec_port=%d
	mka_cak=%s
	mka_ckn=%s
	mka_priority=%d
}
`, macsecReplayWindow, inst.Port,
		hex.EncodeToString(inst.Keys.CAK), hex.EncodeToString(inst.Keys.CKN), inst.Priority), nil
}

func macsecSCI(mac net.HardwareAddr, port int) (uint64, error) {
	if len(mac) != 6 {
		return 0, errors.New("invalid MAC for SCI")
	}
	if !validMACsecPort(port) {
		return 0, fmt.Errorf("invalid MACsec port %d", port)
	}
	var b [8]byte
	copy(b[:6], mac)
	binary.BigEndian.PutUint16(b[6:], uint16(port))
	return binary.BigEndian.Uint64(b[:]), nil
}

type macsecLink struct {
	Name     string
	Parent   string
	Master   string
	SCI      uint64
	MTU      int
	AdminUp  bool
	Encrypt  bool
	Protect  bool
	Replay   bool
	Validate string
	Cipher   string
}

func (l macsecLink) Secure() bool {
	return l.Encrypt && l.Protect && l.Replay && l.Validate == "strict"
}

func (l macsecLink) Forwarding() bool {
	return l.AdminUp && l.Secure()
}

func parseSCI(raw json.RawMessage) (uint64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
		if s == "" || len(s) > 16 {
			return 0, errors.New("invalid sci")
		}
		return strconv.ParseUint(s, 16, 64)
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, errors.New("invalid sci")
	}
	return n, nil
}

func parseMACsecLinks(data []byte) ([]macsecLink, error) {
	var entries []struct {
		IfName   string   `json:"ifname"`
		Link     string   `json:"link"`
		Master   string   `json:"master"`
		MTU      int      `json:"mtu"`
		Flags    []string `json:"flags"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
			Data struct {
				SCI           json.RawMessage `json:"sci"`
				Protect       *bool           `json:"protect"`
				Encrypt       *bool           `json:"encrypt"`
				Replay        *bool           `json:"replay"`
				ReplayProtect *bool           `json:"replay_protect"`
				Validate      string          `json:"validate"`
				Validation    string          `json:"validation"`
				Cipher        string          `json:"cipher_suite"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	links := []macsecLink{}
	for _, e := range entries {
		if e.LinkInfo.Kind != "macsec" || !meshIfaceRE.MatchString(e.IfName) {
			continue
		}
		sci, err := parseSCI(e.LinkInfo.Data.SCI)
		if err != nil {
			continue
		}
		link := macsecLink{
			Name:     e.IfName,
			Parent:   e.Link,
			Master:   e.Master,
			SCI:      sci,
			MTU:      e.MTU,
			Validate: e.LinkInfo.Data.Validation,
			Cipher:   e.LinkInfo.Data.Cipher,
		}
		for _, flag := range e.Flags {
			if flag == "UP" {
				link.AdminUp = true
			}
		}
		if link.Validate == "" {
			link.Validate = e.LinkInfo.Data.Validate
		}
		replay := e.LinkInfo.Data.ReplayProtect
		if replay == nil {
			replay = e.LinkInfo.Data.Replay
		}
		link.Protect = e.LinkInfo.Data.Protect != nil && *e.LinkInfo.Data.Protect
		link.Replay = replay != nil && *replay
		link.Encrypt = e.LinkInfo.Data.Encrypt != nil && *e.LinkInfo.Data.Encrypt
		links = append(links, link)
	}
	return links, nil
}

func findMACsecLink(links []macsecLink, parent string, sci uint64) (macsecLink, bool) {
	for _, l := range links {
		if l.Parent == parent && l.SCI == sci {
			return l, true
		}
	}
	return macsecLink{}, false
}

func macsecCapableMTU(parentMaxMTU int) int {
	mtu := parentMaxMTU - macsecOverhead
	if mtu > macsecEthernetMTU {
		mtu = macsecEthernetMTU
	}
	return mtu
}

func macsecLinkMTU(local, peer int) (int, error) {
	mtu := local
	if peer < mtu {
		mtu = peer
	}
	if mtu > macsecEthernetMTU {
		mtu = macsecEthernetMTU
	}
	if mtu < macsecMinLinkMTU {
		return 0, fmt.Errorf("MACsec link MTU %d below minimum %d", mtu, macsecMinLinkMTU)
	}
	return mtu, nil
}

func allocateMACsecPort(leaves []LeafRouter) (int, error) {
	used := map[int]bool{}
	for _, leaf := range leaves {
		if leaf.MACsec != nil && leaf.MACsec.Port != 0 {
			used[leaf.MACsec.Port] = true
		}
	}
	for port := macsecMainPortFirst; port <= macsecMainPortLast; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, errors.New("no free MACsec ports")
}

const macsecGuardTable = "mesh_macsec_guard"
const macsecMSSTable = "mesh_macsec_mss"

func renderLeafGuard(wanif string, egress bool) (string, error) {
	if !meshIfaceRE.MatchString(wanif) {
		return "", fmt.Errorf("invalid uplink interface %q", wanif)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table netdev %s\ndelete table netdev %s\ntable netdev %s {\n", macsecGuardTable, macsecGuardTable, macsecGuardTable)
	fmt.Fprintf(&b, "\tchain ingress {\n\t\ttype filter hook ingress device \"%s\" priority -500; policy drop;\n\t\tether type { 0x888e, 0x88e5, 0x88b5 } accept\n\t}\n", wanif)
	if egress {
		fmt.Fprintf(&b, "\tchain egress {\n\t\ttype filter hook egress device \"%s\" priority -500; policy drop;\n\t\tether type { 0x888e, 0x88e5, 0x88b5 } accept\n\t}\n", wanif)
	}
	b.WriteString("}\n")
	return b.String(), nil
}

func macsecMSS(linkMTU int) (int, int) {
	return linkMTU - 40, linkMTU - 60
}

func renderMSSClamp(linkMTU int) (string, error) {
	if linkMTU < macsecMinLinkMTU || linkMTU >= macsecEthernetMTU {
		return "", fmt.Errorf("no MSS clamp needed for MTU %d", linkMTU)
	}
	v4, v6 := macsecMSS(linkMTU)
	var b strings.Builder
	fmt.Fprintf(&b, "table bridge %s\ndelete table bridge %s\ntable bridge %s {\n", macsecMSSTable, macsecMSSTable, macsecMSSTable)
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority -150; policy accept;\n")
	fmt.Fprintf(&b, "\t\tether type ip ip protocol tcp tcp flags & syn == syn tcp option maxseg size > %d tcp option maxseg size set %d\n", v4, v4)
	fmt.Fprintf(&b, "\t\tether type ip6 ip6 nexthdr tcp tcp flags & syn == syn tcp option maxseg size > %d tcp option maxseg size set %d\n", v6, v6)
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}
