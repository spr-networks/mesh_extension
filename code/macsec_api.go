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
	Token    string
	Enable   bool
	KeyNonce string `json:",omitempty"`
	PeerMTU  int    `json:",omitempty"`
}

type macsecPeerResponse struct {
	Version   int
	BridgeMAC string `json:",omitempty"`
	MaxMTU    int    `json:",omitempty"`
	LinkMTU   int    `json:",omitempty"`
}

type leafMACsecRequest struct {
	IP     string
	Enable bool
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
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return response, fmt.Errorf("leaf %s unreachable: %w", leaf.IP, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return response, fmt.Errorf("leaf %s refused MACsec change: %d %s", leaf.IP, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return response, fmt.Errorf("leaf %s sent an invalid MACsec reply", leaf.IP)
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
				return "", fmt.Errorf("%s is already a MACsec interface", parent)
			}
		}
	}
	return parent, nil
}

func (m *macsecManager) enableLeafMACsec(leaf LeafRouter, leaves []LeafRouter, requestedParent string, requestedMTU int) (LeafMACsec, error) {
	if requestedMTU != 0 && (requestedMTU < macsecMinLinkMTU || requestedMTU > macsecEthernetMTU) {
		return LeafMACsec{}, fmt.Errorf("MTU must be between %d and %d", macsecMinLinkMTU, macsecEthernetMTU)
	}
	if len(leaf.APIToken) < macsecMinSecretLen {
		return LeafMACsec{}, errors.New("Repair mesh, token too short for MACsec")
	}
	parent, err := m.macsecParentFor(leaf, requestedParent)
	if err != nil {
		return LeafMACsec{}, err
	}
	if err := m.sys.Probe(); err != nil {
		return LeafMACsec{}, fmt.Errorf("MACsec unsupported on this router: %w", err)
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
		return LeafMACsec{}, fmt.Errorf("parent interface %s MTU too small for MACsec", parent)
	}

	next := LeafMACsec{Enabled: true, Parent: parent}
	if leaf.MACsec != nil && leaf.MACsec.Enabled && leaf.MACsec.KeyNonce != "" {
		next.KeyNonce = leaf.MACsec.KeyNonce
	} else {
		next.KeyNonce, err = newMACsecNonce()
		if err != nil {
			return LeafMACsec{}, err
		}
	}
	if leaf.MACsec != nil && validMACsecPort(leaf.MACsec.Port) && leaf.MACsec.Port >= macsecMainPortFirst {
		next.Port = leaf.MACsec.Port
	} else {
		next.Port, err = allocateMACsecPort(leaves)
		if err != nil {
			return LeafMACsec{}, err
		}
	}
	if _, err := deriveMACsecKeys(leaf.APIToken, next.KeyNonce); err != nil {
		return LeafMACsec{}, err
	}

	reply, err := macsecCallLeaf(leaf, macsecPeerRequest{
		Token:    leaf.APIToken,
		Enable:   true,
		KeyNonce: next.KeyNonce,
		PeerMTU:  localMTU,
	})
	if err != nil {
		return LeafMACsec{}, err
	}
	if reply.Version != macsecProtocolVersion {
		return LeafMACsec{}, fmt.Errorf("leaf speaks MACsec protocol %d, need %d; update the leaf", reply.Version, macsecProtocolVersion)
	}
	leafMAC, err := net.ParseMAC(reply.BridgeMAC)
	if err != nil || len(leafMAC) != 6 {
		return LeafMACsec{}, errors.New("leaf sent an invalid bridge MAC")
	}
	next.LeafMAC = leafMAC.String()
	next.LinkMTU, err = macsecLinkMTU(localMTU, reply.MaxMTU)
	if err != nil {
		return LeafMACsec{}, err
	}
	return next, nil
}

func macsecSetLeaf(request leafMACsecRequest) (int, error) {
	if isLeafRouter() {
		return 400, errors.New("MACsec backhaul is managed from the main router")
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
		enabled, err := gMACsec.enableLeafMACsec(leaf, config.LeafRouters, request.Parent, request.MTU)
		if err != nil {
			return 400, err
		}
		next = &enabled
	} else if leaf.MACsec != nil && leaf.MACsec.Enabled {
		if _, err := macsecCallLeaf(leaf, macsecPeerRequest{Token: leaf.APIToken, Enable: false}); err != nil {
			if _, wireErr := gMACsec.disableOverWire(leaf); wireErr != nil {
				notAcked = fmt.Errorf("MACsec is off on this router and did not get confirmation from node. Check mesh node at %s", leaf.IP)
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
				return 409, errors.New("MACsec port conflict, retry")
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
	if request.PeerMTU < macsecMinLinkMTU || request.PeerMTU > macsecEthernetMTU {
		http.Error(w, "invalid peer MTU", 400)
		return
	}
	if err := gMACsec.sys.Probe(); err != nil {
		http.Error(w, "MACsec unsupported on this leaf: "+err.Error(), 400)
		return
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
	reply.MaxMTU = parentCapableMTU(uplink)
	reply.LinkMTU, err = macsecLinkMTU(reply.MaxMTU, request.PeerMTU)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
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
	if previous.Enabled && previous.KeyNonce == request.KeyNonce {
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
