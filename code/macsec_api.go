package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const macsecProtocolVersion = 1

type macsecPeerRequest struct {
	Token         string
	Enable        bool
	KeyNonce      string `json:",omitempty"`
	PeerMTU       int    `json:",omitempty"`
	Mode          string `json:",omitempty"`
	Port          int    `json:",omitempty"`
	UnderlayMTU   int    `json:",omitempty"`
	MainPublicKey string `json:",omitempty"`
}

type macsecPeerResponse struct {
	Version       int
	BridgeMAC     string `json:",omitempty"`
	MaxMTU        int    `json:",omitempty"`
	LinkMTU       int    `json:",omitempty"`
	LeafPublicKey string `json:",omitempty"`
}

type leafMACsecRequest struct {
	IP     string
	Enable bool
	Mode   string
	Parent string
	MTU    int
}

var macsecChangeMtx sync.Mutex

var macsecCallLeaf = callLeafMACsecPeer

func leafURLHost(ip string) (string, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return "", errors.New("invalid leaf ip")
	}
	if addr.To4() != nil {
		return addr.String(), nil
	}
	return "[" + addr.String() + "]", nil
}

func callLeafMACsecPeer(leaf LeafRouter, request macsecPeerRequest) (macsecPeerResponse, error) {
	response := macsecPeerResponse{}
	host, err := leafURLHost(leaf.IP)
	if err != nil {
		return response, err
	}
	if leaf.TLSCA == "" {
		return response, errors.New("leaf TLS CA unknown")
	}
	body, _ := json.Marshal(request)
	req, err := http.NewRequest(http.MethodPut, "https://"+host+"/plugins/mesh/macsec/peer", bytes.NewBuffer(body))
	if err != nil {
		return response, err
	}
	req.Header.Add("Authorization", "Bearer "+leaf.APIToken)
	req.Header.Set("Content-Type", "application/json")

	c := StandardTLSClient(leaf.TLSCA)
	if t, ok := c.Transport.(*http.Transport); ok {
		t.DialContext = (&net.Dialer{Timeout: 5 * time.Second, Control: meshCtlDialControl}).DialContext
	}
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return response, fmt.Errorf("leaf %s unreachable: %w", leaf.IP, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	mode := request.Mode
	if !request.Enable && leaf.MACsec != nil {
		mode = leaf.MACsec.Mode
	}
	if resp.StatusCode != http.StatusOK {
		return response, fmt.Errorf("leaf %s refused %s change: %d %s", leaf.IP, backhaulLabel(mode), resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return response, fmt.Errorf("leaf %s sent an invalid %s reply", leaf.IP, backhaulLabel(mode))
	}
	return response, nil
}

func findLeafByIP(leaves []LeafRouter, ip string) int {
	for i, leaf := range leaves {
		if leaf.IP == ip {
			return i
		}
	}
	return -1
}

func sameLeaf(a, b LeafRouter) bool {
	return a.IP == b.IP && subtle.ConstantTimeCompare([]byte(a.APIToken), []byte(b.APIToken)) == 1
}

func (m *macsecManager) macsecParentFor(leaf LeafRouter, requested string) (string, error) {
	parent := requested
	if parent == "" && leaf.MACsec != nil {
		parent = leaf.MACsec.Parent
	}
	if parent == "" {
		dev, err := m.sys.RouteDev(leaf.IP)
		if err != nil {
			return "", errors.New("could not determine the interface facing the leaf; pass Parent")
		}
		parent = dev
	}
	if !meshIfaceRE.MatchString(parent) {
		return "", fmt.Errorf("invalid parent interface %q", parent)
	}
	if parent == os.Getenv("WANIF") || parent == BRIDGE_IFACE || parent == "lo" {
		return "", fmt.Errorf("Invalid %s for mesh", parent)
	}
	if links, err := m.sys.Links(); err == nil {
		for _, link := range links {
			if link.Name == parent {
				return "", fmt.Errorf("%s is already an %s interface", parent, backhaulLabel(backhaulMACsec))
			}
		}
	}
	return parent, nil
}

func (m *macsecManager) enableLeafMACsec(leaf LeafRouter, leaves []LeafRouter, requestedParent string, requestedMTU int, requestedModeName string) (LeafMACsec, error) {
	mode := requestedMode(requestedModeName)
	if requestedMTU != 0 && (requestedMTU < macsecMinLinkMTU || requestedMTU > macsecEthernetMTU) {
		return LeafMACsec{}, fmt.Errorf("MTU must be between %d and %d", macsecMinLinkMTU, macsecEthernetMTU)
	}
	if len(leaf.APIToken) < macsecMinSecretLen {
		return LeafMACsec{}, fmt.Errorf("Repair mesh, token too short for %s", backhaulLabel(mode))
	}
	parent, err := m.macsecParentFor(leaf, requestedParent)
	if err != nil {
		return LeafMACsec{}, err
	}
	probe := m.sys.Probe
	if mode == backhaulWireGuard {
		probe = m.sys.ProbeWG
	}
	if err := probe(); err != nil {
		return LeafMACsec{}, fmt.Errorf("%s unsupported on this router: %w", backhaulLabel(mode), err)
	}
	info, err := m.sys.LinkInfo(parent)
	if err != nil {
		return LeafMACsec{}, fmt.Errorf("parent interface %s unavailable", parent)
	}
	localMTU := parentCapableMTU(info)
	if requestedMTU != 0 && requestedMTU < localMTU {
		localMTU = requestedMTU
	}
	if localMTU < macsecMinLinkMTU {
		return LeafMACsec{}, fmt.Errorf("parent interface %s MTU too small for %s", parent, backhaulLabel(mode))
	}

	current := leaf.MACsec
	sameAssociation := current != nil && current.Enabled && current.KeyNonce != "" && storedMode(current.Mode) == mode
	next := LeafMACsec{Enabled: true, Parent: parent}
	if mode == backhaulWireGuard {
		next.Mode = backhaulWireGuard
	}
	if sameAssociation {
		next.KeyNonce = current.KeyNonce
		next.UnderlayMTU = current.UnderlayMTU
	} else {
		next.KeyNonce, err = newMACsecNonce()
		if err != nil {
			return LeafMACsec{}, err
		}
	}
	if current != nil && validMACsecPort(current.Port) && current.Port >= macsecMainPortFirst {
		next.Port = current.Port
	} else {
		next.Port, err = allocateMACsecPort(leaves)
		if err != nil {
			return LeafMACsec{}, err
		}
	}
	if mode == backhaulWireGuard && !validWGPort(next.Port) {
		return LeafMACsec{}, fmt.Errorf("too many mesh nodes for %s", backhaulLabel(mode))
	}
	if _, err := deriveMACsecKeys(leaf.APIToken, next.KeyNonce); err != nil {
		return LeafMACsec{}, err
	}

	request := macsecPeerRequest{
		Token:    leaf.APIToken,
		Enable:   true,
		KeyNonce: next.KeyNonce,
		PeerMTU:  localMTU,
		Mode:     next.Mode,
	}
	if mode == backhaulWireGuard {
		request.PeerMTU = 0
		request.Port = next.Port
		request.UnderlayMTU = next.UnderlayMTU
		request.MainPublicKey, err = loadOrCreateWGKey()
		if err != nil {
			return LeafMACsec{}, err
		}
	}
	reply, err := macsecCallLeaf(leaf, request)
	if err != nil {
		return LeafMACsec{}, err
	}
	if reply.Version != macsecProtocolVersion {
		return LeafMACsec{}, fmt.Errorf("leaf speaks %s protocol %d, need %d; update the leaf", backhaulLabel(mode), reply.Version, macsecProtocolVersion)
	}
	leafMAC, err := net.ParseMAC(reply.BridgeMAC)
	if err != nil || len(leafMAC) != 6 {
		return LeafMACsec{}, errors.New("leaf sent an invalid bridge MAC")
	}
	next.LeafMAC = leafMAC.String()
	if mode == backhaulWireGuard {
		if _, err := parseWGKey(reply.LeafPublicKey); err != nil {
			return LeafMACsec{}, errors.New("leaf sent an invalid WireGuard key")
		}
		next.LeafPublicKey = reply.LeafPublicKey
		next.LinkMTU = wgInnerMTU(underlayOrDefault(next.UnderlayMTU))
		return next, nil
	}
	next.LinkMTU, err = macsecLinkMTU(localMTU, reply.MaxMTU)
	if err != nil {
		return LeafMACsec{}, err
	}
	return next, nil
}

func macsecSetLeaf(request leafMACsecRequest) (int, error) {
	if isLeafRouter() {
		return 400, errors.New("Encrypted Link is managed from the main router")
	}
	if net.ParseIP(request.IP) == nil {
		return 400, errors.New("invalid ip")
	}

	macsecChangeMtx.Lock()
	defer macsecChangeMtx.Unlock()

	Configmtx.Lock()
	config := loadConfigLocked()
	Configmtx.Unlock()
	index := findLeafByIP(config.LeafRouters, request.IP)
	if index < 0 {
		return 404, errors.New("unknown leaf router")
	}
	leaf := config.LeafRouters[index]

	var next *LeafMACsec
	var notAcked error
	if request.Enable {
		enabled, err := gMACsec.enableLeafMACsec(leaf, config.LeafRouters, request.Parent, request.MTU, request.Mode)
		if err != nil {
			return 400, err
		}
		next = &enabled
	} else if leaf.MACsec != nil && leaf.MACsec.Enabled {
		if _, err := macsecCallLeaf(leaf, macsecPeerRequest{Token: leaf.APIToken, Enable: false}); err != nil {
			if _, wireErr := gMACsec.disableOverWire(leaf); wireErr != nil {
				notAcked = fmt.Errorf("%s is off on this router and did not get confirmation from node. Check mesh node at %s", backhaulLabel(leaf.MACsec.Mode), leaf.IP)
			}
		}
	}

	Configmtx.Lock()
	defer Configmtx.Unlock()
	config = loadConfigLocked()
	index = findLeafByIP(config.LeafRouters, request.IP)
	if index < 0 || !sameLeaf(config.LeafRouters[index], leaf) {
		return 409, errors.New("leaf router changed during the request")
	}
	if next != nil {
		for i, other := range config.LeafRouters {
			if i != index && other.MACsec != nil && other.MACsec.Port == next.Port {
				return 409, fmt.Errorf("%s port conflict, retry", backhaulLabel(next.Mode))
			}
		}
	}
	config.LeafRouters[index].MACsec = next
	config.LeafRouters[index].MACsecPending = false
	saveConfigLocked(config)
	clearMACsecPendingError(request.IP)
	gMACsec.Kick()
	if notAcked != nil {
		return http.StatusBadGateway, notAcked
	}
	return 200, nil
}

func leafRouterMACsec(w http.ResponseWriter, r *http.Request) {
	request := leafMACsecRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if code, err := macsecSetLeaf(request); err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gMACsec.Status())
}

var macsecPendingMtx sync.Mutex
var macsecPendingErrors = map[string]string{}

func macsecPendingError(ip string) string {
	macsecPendingMtx.Lock()
	defer macsecPendingMtx.Unlock()
	return macsecPendingErrors[ip]
}

func clearMACsecPendingError(ip string) {
	macsecPendingMtx.Lock()
	defer macsecPendingMtx.Unlock()
	delete(macsecPendingErrors, ip)
}

func retryPendingMACsec() {
	if isLeafRouter() {
		return
	}
	Configmtx.Lock()
	config := loadConfigLocked()
	Configmtx.Unlock()
	for _, leaf := range config.LeafRouters {
		if !leaf.MACsecPending || (leaf.MACsec != nil && leaf.MACsec.Enabled) {
			continue
		}
		_, err := macsecSetLeaf(leafMACsecRequest{IP: leaf.IP, Enable: true})
		macsecPendingMtx.Lock()
		if err != nil {
			macsecPendingErrors[leaf.IP] = err.Error()
		} else {
			delete(macsecPendingErrors, leaf.IP)
		}
		macsecPendingMtx.Unlock()
	}
}

func macsecPendingLoop() {
	for {
		time.Sleep(20 * time.Second)
		retryPendingMACsec()
	}
}

func macsecPeer(w http.ResponseWriter, r *http.Request) {
	request := macsecPeerRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if !isLeafRouter() {
		http.Error(w, "not a mesh leaf", 400)
		return
	}
	token, err := getToken(DOWNHAUL_TOKEN_NAME)
	if err != nil || token.Token == "" ||
		subtle.ConstantTimeCompare([]byte(token.Token), []byte(request.Token)) != 1 {
		http.Error(w, "invalid pairing token", http.StatusForbidden)
		return
	}

	reply := macsecPeerResponse{Version: macsecProtocolVersion}

	if !request.Enable {
		Configmtx.Lock()
		config := loadConfigLocked()
		config.LeafMACsec = LeafSideMACsec{}
		saveConfigLocked(config)
		Configmtx.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reply)
		gMACsec.KickAfter(macsecApplyDelay)
		return
	}

	if _, err := deriveMACsecKeys(token.Token, request.KeyNonce); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	wg := storedMode(request.Mode) == backhaulWireGuard
	if wg {
		if _, err := parseWGKey(request.MainPublicKey); err != nil || !validWGPort(request.Port) {
			http.Error(w, "invalid WireGuard settings", 400)
			return
		}
		if request.UnderlayMTU != 0 && (request.UnderlayMTU < macsecEthernetMTU || request.UnderlayMTU > meshJumboMTU) {
			http.Error(w, "invalid underlay MTU", 400)
			return
		}
		if err := gMACsec.sys.ProbeWG(); err != nil {
			http.Error(w, backhaulLabel(backhaulWireGuard)+" unsupported on this leaf: "+err.Error(), 400)
			return
		}
	} else {
		if request.PeerMTU < macsecMinLinkMTU || request.PeerMTU > macsecEthernetMTU {
			http.Error(w, "invalid peer MTU", 400)
			return
		}
		if err := gMACsec.sys.Probe(); err != nil {
			http.Error(w, backhaulLabel(backhaulMACsec)+" unsupported on this leaf: "+err.Error(), 400)
			return
		}
	}
	wanif := meshWANIF()
	uplink, err := gMACsec.sys.LinkInfo(wanif)
	if err != nil {
		http.Error(w, "uplink interface unavailable", 400)
		return
	}
	bridge, err := gMACsec.sys.LinkInfo(BRIDGE_IFACE)
	if err != nil {
		http.Error(w, "mesh bridge unavailable", 400)
		return
	}
	if wg {
		reply.MaxMTU = wgCapableUnderlay(uplink)
		reply.LinkMTU = wgInnerMTU(underlayOrDefault(request.UnderlayMTU))
		reply.LeafPublicKey, err = loadOrCreateWGKey()
		if err != nil {
			http.Error(w, "WireGuard key unavailable", 500)
			return
		}
	} else {
		reply.MaxMTU = parentCapableMTU(uplink)
		reply.LinkMTU, err = macsecLinkMTU(reply.MaxMTU, request.PeerMTU)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	reply.BridgeMAC = bridge.MAC.String()

	Configmtx.Lock()
	config := loadConfigLocked()
	previous := config.LeafMACsec
	next := LeafSideMACsec{
		Enabled:   true,
		KeyNonce:  request.KeyNonce,
		LinkMTU:   reply.LinkMTU,
		EnabledAt: time.Now().Unix(),
	}
	if wg {
		next.Mode = backhaulWireGuard
		next.Port = request.Port
		next.MainPublicKey = request.MainPublicKey
		next.UnderlayMTU = request.UnderlayMTU
	}
	if previous.Enabled && previous.KeyNonce == request.KeyNonce && previous.Mode == next.Mode {
		next.Confirmed = previous.Confirmed
		next.EnabledAt = previous.EnabledAt
	}
	config.LeafMACsec = next
	saveConfigLocked(config)
	Configmtx.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply)
	gMACsec.KickAfter(macsecApplyDelay)
}

func macsecStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !gMACsec.Ready() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gMACsec.Status())
}

type macsecMTUResult struct {
	UnderlayMTU int
	Jumbo       bool
	LinkMTU     int
}

func macsecTestMTU(ip string) (macsecMTUResult, int, error) {
	result := macsecMTUResult{}
	if isLeafRouter() {
		return result, 400, errors.New("Encrypted Link is managed from the main router")
	}
	macsecChangeMtx.Lock()
	defer macsecChangeMtx.Unlock()
	Configmtx.Lock()
	config := loadConfigLocked()
	Configmtx.Unlock()
	index := findLeafByIP(config.LeafRouters, ip)
	if index < 0 {
		return result, 404, errors.New("unknown leaf router")
	}
	leaf := config.LeafRouters[index]
	if leaf.MACsec == nil || !leaf.MACsec.Enabled {
		return result, 400, errors.New("encryption is not enabled for this mesh node")
	}
	underlay, err := gMACsec.testUnderlayMTU(leaf)
	if err != nil {
		return result, http.StatusBadGateway, err
	}
	next := *leaf.MACsec
	next.UnderlayMTU = underlay
	request := macsecPeerRequest{Token: leaf.APIToken, Enable: true, KeyNonce: next.KeyNonce, Mode: next.Mode}
	if storedMode(next.Mode) == backhaulWireGuard {
		next.LinkMTU = wgInnerMTU(underlay)
		request.Port = next.Port
		request.UnderlayMTU = underlay
		if request.MainPublicKey, err = loadOrCreateWGKey(); err != nil {
			return result, 500, err
		}
	} else {
		next.LinkMTU = macsecCapableMTU(underlay)
		request.PeerMTU = next.LinkMTU
	}
	if next != *leaf.MACsec {
		if _, err := macsecCallLeaf(leaf, request); err != nil {
			return result, http.StatusBadGateway, err
		}
		Configmtx.Lock()
		config = loadConfigLocked()
		index = findLeafByIP(config.LeafRouters, ip)
		if index >= 0 && sameLeaf(config.LeafRouters[index], leaf) && config.LeafRouters[index].MACsec != nil &&
			config.LeafRouters[index].MACsec.KeyNonce == next.KeyNonce {
			config.LeafRouters[index].MACsec = &next
			saveConfigLocked(config)
		}
		Configmtx.Unlock()
		gMACsec.Kick()
	}
	return macsecMTUResult{UnderlayMTU: underlay, Jumbo: underlay >= meshJumboMTU, LinkMTU: next.LinkMTU}, 200, nil
}

func leafRouterMTUTest(w http.ResponseWriter, r *http.Request) {
	request := leafMACsecRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	result, code, err := macsecTestMTU(request.IP)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (m *macsecManager) maybeTestMTU(leaf LeafRouter, secured bool) {
	if !secured || leaf.MACsec.UnderlayMTU != 0 || m.mtuTesting[leaf.IP] || m.noCtlLoop {
		return
	}
	m.mtuTesting[leaf.IP] = true
	go func(ip string) {
		if _, _, err := macsecTestMTU(ip); err != nil {
			fmt.Println("[-] mesh: MTU test for", ip, "failed:", err)
		}
		m.mu.Lock()
		delete(m.mtuTesting, ip)
		m.mu.Unlock()
	}(leaf.IP)
}
