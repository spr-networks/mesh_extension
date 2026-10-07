package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type MeshBSS struct {
	Interface string
	BSSID     string
	SSID      string // hex-encoded, as returned by SHOW_NEIGHBOR
	NR        string // hostapd's own Neighbor Report element
	Security  string
}

type meshNeighborKey struct{ BSSID, SSID string }

var meshWifiDir = TEST_PREFIX + "/state/wifi"
var meshInterfacesPath = TEST_PREFIX + "/configs/base/interfaces.json"
var meshNeighborStatePath = TEST_PREFIX + "/state/plugins/mesh/neighbors.json"
var meshNeighborMu sync.Mutex
var meshSocketID atomic.Uint64
var meshIfaceRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$`)
var meshHostapd = meshHostapdCommand

func meshHostapdCommand(iface, command string) (string, error) {
	if !meshIfaceRE.MatchString(iface) {
		return "", fmt.Errorf("invalid AP interface %q", iface)
	}
	local := fmt.Sprintf("%s/control-%d-%d", TEST_PREFIX+"/state/plugins/mesh", os.Getpid(), meshSocketID.Add(1))
	if runtime.GOOS == "linux" {
		// Use an abstract socket
		local = "@spr-mesh-" + strings.TrimPrefix(local, TEST_PREFIX+"/state/plugins/mesh/")
	} else {
		defer os.Remove(local)
	}
	remote := meshWifiDir + "/control_" + iface + "/" + iface
	conn, err := net.DialUnix("unixgram", &net.UnixAddr{Name: local, Net: "unixgram"}, &net.UnixAddr{Name: remote, Net: "unixgram"})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(command)); err != nil {
		return "", err
	}
	buffer := make([]byte, 64<<10)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	response := strings.TrimSpace(string(buffer[:n]))
	if response == "" || strings.HasPrefix(response, "FAIL") || strings.HasPrefix(response, "UNKNOWN COMMAND") {
		return response, fmt.Errorf("hostapd rejected %s on %s: %s", strings.Fields(command)[0], iface, response)
	}
	return response, nil
}

func meshValues(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}

func meshLocalBSSes() ([]MeshBSS, error) {
	data, err := os.ReadFile(meshInterfacesPath)
	if err != nil {
		return nil, fmt.Errorf("read mesh interfaces: %w", err)
	}
	var interfaces []struct {
		InterfaceConfig
		ExtraBSS []json.RawMessage
	}
	if err := json.Unmarshal(data, &interfaces); err != nil {
		return nil, fmt.Errorf("decode mesh interfaces %s: %w", meshInterfacesPath, err)
	}
	var names []string
	for _, entry := range interfaces {
		if !entry.Enabled || entry.Type != "AP" {
			continue
		}
		names = append(names, entry.Name)
		for i := range entry.ExtraBSS {
			names = append(names, fmt.Sprintf("%s.ap%d", entry.Name, i))
		}
	}
	bsses := []MeshBSS{}
	for _, iface := range names {
		if !meshIfaceRE.MatchString(iface) {
			continue
		}
		statusRaw, err := meshHostapd(iface, "STATUS")
		if err != nil {
			fmt.Println("mesh local BSS", iface, "STATUS", err)
			continue
		}
		status := meshValues(statusRaw)
		if status["state"] != "ENABLED" {
			continue
		}
		configRaw, err := meshHostapd(iface, "GET_CONFIG")
		if err != nil {
			fmt.Println("mesh local BSS", iface, "GET_CONFIG", err)
			continue
		}
		live := meshValues(configRaw)
		// GET_CONFIG identifies this BSS; STATUS also lists the primary BSS.
		bssid := live["bssid"]
		if bssid == "" {
			bssid = status["bssid[0]"]
		}
		reports, err := meshHostapd(iface, "SHOW_NEIGHBOR")
		if err != nil {
			fmt.Println("mesh local BSS", iface, "SHOW_NEIGHBOR", err)
			continue
		}
		keys := strings.Fields(live["key_mgmt"])
		sort.Strings(keys)
		security := strings.Join([]string{live["wpa"], strings.Join(keys, " "), live["group_cipher"], live["rsn_pairwise_cipher"]}, "|")
		for _, line := range strings.Split(reports, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.EqualFold(fields[0], bssid) {
				continue
			}
			values := meshValues(strings.Join(fields[1:], "\n"))
			bss := MeshBSS{iface, fields[0], values["ssid"], values["nr"], security}
			if validMeshBSS(bss) {
				bsses = append(bsses, bss)
			}
			break
		}
	}
	return bsses, nil
}

func validMeshBSS(bss MeshBSS) bool {
	mac, err := net.ParseMAC(bss.BSSID)
	ssid, ssidErr := hex.DecodeString(bss.SSID)
	nr, nrErr := hex.DecodeString(bss.NR)
	return err == nil && len(mac) == 6 && ssidErr == nil && len(ssid) > 0 && len(ssid) <= 32 &&
		nrErr == nil && len(nr) >= 13 && len(nr) <= 255 && bytes.Equal(nr[:6], mac) && nr[10] != 0 && nr[11] != 0
}

func meshApplyNeighbors(all []MeshBSS) error {
	meshNeighborMu.Lock()
	defer meshNeighborMu.Unlock()
	if len(all) > 128 {
		return errors.New("too many mesh APs")
	}
	for _, bss := range all {
		if !validMeshBSS(bss) {
			return errors.New("invalid mesh AP")
		}
	}
	locals, err := meshLocalBSSes()
	if err != nil {
		return err
	}
	previous := map[string][]meshNeighborKey{}
	if data, err := os.ReadFile(meshNeighborStatePath); err == nil {
		_ = json.Unmarshal(data, &previous)
	}
	for _, local := range locals {
		want := map[meshNeighborKey]bool{}
		localMAC, _ := net.ParseMAC(local.BSSID)
		for _, peer := range all {
			mac, _ := net.ParseMAC(peer.BSSID)
			if mac.String() == localMAC.String() || peer.SSID != local.SSID || peer.Security != local.Security {
				continue
			}
			key := meshNeighborKey{mac.String(), peer.SSID}
			command := "SET_NEIGHBOR " + key.BSSID + " ssid=" + key.SSID + " nr=" + peer.NR
			response, err := meshHostapd(local.Interface, command)
			if err != nil || response != "OK" {
				return fmt.Errorf("set neighbor on %s: %v %s", local.Interface, err, response)
			}
			want[key] = true
		}
		for _, key := range previous[local.Interface] {
			if !want[key] {
				// hostapd may have restarted and already forgotten this entry.
				_, _ = meshHostapd(local.Interface, "REMOVE_NEIGHBOR "+key.BSSID+" ssid="+key.SSID)
			}
		}
		previous[local.Interface] = previous[local.Interface][:0]
		for key := range want {
			previous[local.Interface] = append(previous[local.Interface], key)
		}
	}
	data, _ := json.Marshal(previous)
	tmp := meshNeighborStatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, meshNeighborStatePath)
}

func meshRemote(leaf LeafRouter, method, path string, payload []byte) ([]byte, error) {
	request, err := http.NewRequest(method, "https://"+leaf.IP+"/plugins/mesh/"+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+leaf.APIToken)
	client := StandardTLSClient(leaf.TLSCA)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

var meshSyncMu sync.Mutex
var meshRemoteRequest = meshRemote

func syncMeshNeighbors() {
	if isLeafRouter() {
		return
	}
	meshSyncMu.Lock()
	defer meshSyncMu.Unlock()
	all, err := meshLocalBSSes()
	if err != nil {
		fmt.Println("mesh local inventory", err)
		return
	}
	if len(all) == 0 {
		return // Wi-Fi is restarting.
	}
	Configmtx.RLock()
	leaves := loadConfigLocked().LeafRouters
	Configmtx.RUnlock()
	var requests sync.WaitGroup
	inventories := make([][]MeshBSS, len(leaves))
	for i, leaf := range leaves {
		requests.Go(func() {
			data, err := meshRemoteRequest(leaf, http.MethodGet, "bsses", nil)
			if err != nil {
				fmt.Println("mesh neighbor inventory", leaf.IP, err)
				return
			}
			var bsses []MeshBSS
			if json.Unmarshal(data, &bsses) != nil {
				return
			}
			for _, bss := range bsses {
				if !validMeshBSS(bss) {
					return
				}
			}
			inventories[i] = bsses
		})
	}
	requests.Wait()
	reachable := []LeafRouter{}
	for i, bsses := range inventories {
		if len(bsses) > 0 {
			all = append(all, bsses...)
			reachable = append(reachable, leaves[i])
		}
	}
	if err := meshApplyNeighbors(all); err != nil {
		fmt.Println("mesh local neighbors", err)
	}
	data, _ := json.Marshal(all)
	for _, leaf := range reachable {
		requests.Go(func() {
			if _, err := meshRemoteRequest(leaf, http.MethodPut, "neighbors", data); err != nil {
				fmt.Println("mesh node neighbors", leaf.IP, err)
			}
		})
	}
	requests.Wait()
}

func meshNeighborLoop() {
	syncMeshNeighbors()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		syncMeshNeighbors()
	}
}

func meshBSSesHandler(w http.ResponseWriter, _ *http.Request) {
	bsses, err := meshLocalBSSes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bsses)
}

func meshNeighborsHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var bsses []MeshBSS
	if err := json.NewDecoder(r.Body).Decode(&bsses); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := meshApplyNeighbors(bsses); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}
