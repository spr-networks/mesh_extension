/**
 * Copyright (C) Supernetworks, Inc. - All Rights Reserved
 *
 * This source code is protected under international copyright law.  All rights
 * reserved and protected by the copyright holders.
 * This file is confidential and only available to authorized individuals with the
 * permission of the copyright holders.  If you encounter this file and do not have
 * permission, please contact the copyright holders and delete this file.
 */

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
//	"regexp"
	"strings"
	"sync"
)

import (
	"github.com/gorilla/mux"
)

type PSKEntry struct {
	Type string
	Psk  string
}

type DeviceEntry struct {
	Name       string
	MAC        string
	WGPubKey   string
	VLANTag    string
	RecentIP   string
	PSKEntry   PSKEntry
	Groups     []string
	DeviceTags []string
}

var TEST_PREFIX = os.Getenv("TEST_PREFIX")
var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/state/plugins/mesh/socket"
var BRIDGE_IFACE = "br0"

var Configmtx sync.RWMutex

type LeafRouter struct {
	APIToken string
	IP       string
}

type ParentCredentials struct {
	ParentIP       string
	ParentAPIToken string
}

type MeshConfig struct {
	ParentCredentials
	LeafRouters []LeafRouter
}

var MeshConfigFile = TEST_PREFIX + "/configs/mesh/config.json"

func LeafRouterID() string {
	//return our assigned IP address as the Router ID
	cmd := exec.Command("ip", "route", "get", "1.1.1.1")
	stdout, err := cmd.Output()
	if err == nil {
		pieces := strings.Split(string(stdout), " ")
		if len(pieces) >= 7 {
			return pieces[6]
		}
	}
	return ""
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func loadConfigLocked() MeshConfig {
	config := MeshConfig{}
	data, err := ioutil.ReadFile(MeshConfigFile)
	if err != nil {
		fmt.Println("failed to read config file", err)
	} else {
		err := json.Unmarshal(data, &config)
		if err != nil {
			fmt.Println("failed to decode", err)
		}
	}
	return config
}

func saveConfigLocked(config MeshConfig) {
	file, _ := json.MarshalIndent(config, "", " ")
	err := ioutil.WriteFile(MeshConfigFile, file, 0600)
	if err != nil {
		fmt.Println(err)
	}
}

func getMeshConfig(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	config := loadConfigLocked()
	Configmtx.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func initMesh() {

}

type ifaceMacKey struct {
	iface string
	mac   string
}

func getExistingBridgeSet() []ifaceMacKey {
	//google/nftables is incomplete and does not support custom set key types

	existing := []ifaceMacKey{}

	//nft -j list map inet filter dhcp_access
	cmd := exec.Command("nft", "-j", "list", "map", "bridge", "filter", "bridge_access")
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println("nft error", err)
		return existing
	}

	//jq .nftables[1].map.elem[][0].concat
	var data map[string]interface{}
	err = json.Unmarshal(stdout, &data)
	data2, ok := data["nftables"].([]interface{})
	if ok != true {
		log.Fatal("invalid json")
	}
	data3, ok := data2[1].(map[string]interface{})
	data4, ok := data3["map"].(map[string]interface{})
	data5, ok := data4["elem"].([]interface{})
	for _, d := range data5 {
		e, ok := d.([]interface{})
		f, ok := e[0].(map[string]interface{})
		g, ok := f["concat"].([]interface{})
		if ok {
			iface, ok := g[0].(string)
			mac, ok := g[1].(string)
			if ok {
				existing = append(existing, ifaceMacKey{iface, mac})
			}
		}
	}
	return existing
}

func updateBridgeAccess(action string, iface string, mac string) {
	existingSet := getExistingBridgeSet()

	if action == "add" {
		//if this iface or mac is in an existing key, remove it
		for _, e := range existingSet {
			if e.iface == iface || e.mac == mac {
				exec.Command("nft", "delete", "element", "bridge", "filter", "bridge_access", "{", e.iface, ".", e.mac, ":", "accept", "}").Run()
			}
		}

		exec.Command("nft", "add", "element", "bridge", "filter", "bridge_access", "{", iface, ".", mac, ":", "accept", "}").Run()
	} else if action == "remove" {
		for _, e := range existingSet {
			if e.iface == iface || e.mac == mac {
				exec.Command("nft", "delete", "element", "bridge", "filter", "bridge_access", "{", e.iface, ".", e.mac, ":", "accept", "}").Run()
			}
		}
	}
}

var MESH_ENABLED_LEAF_PATH = TEST_PREFIX + "/state/plugins/mesh/enabled"

func setLeafRouter(enabled bool) {
	if enabled == false {
		os.Remove(MESH_ENABLED_LEAF_PATH)
	} else {
		os.Create(MESH_ENABLED_LEAF_PATH)
	}
}

func isLeafRouter() bool {
	_, err := os.Stat(MESH_ENABLED_LEAF_PATH)
	if err == nil {
		return true
	}
	return false
}

func callParentAPI(Path string, jsonValue []byte) {
	Configmtx.Lock()
	defer Configmtx.Unlock()

	config := loadConfigLocked()

	if config.ParentAPIToken == "" {
		fmt.Println("[-] Mesh leaf not configured with parent API token, aborting call to", Path)
		return
	}

	req, err := http.NewRequest(http.MethodPut, "http://"+config.ParentIP+"/"+Path, bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+config.ParentAPIToken)

	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("API Parent Event Push Failed", config.ParentIP, Path, err)
		return
	}

	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("API Parent Event Push Failed", config.ParentIP, Path, resp.StatusCode)
		return
	}

}

//func callParentAPI(Path string, jsonValue []bytes) {

func publishConnectEventParent(event WifiConnectEvent) {
	jsonValue, _ := json.Marshal(event)
	go callParentAPI("reportPSKAuthSuccess", jsonValue)
}

func publishConnectFailureEventParent(event WifiConnectFailureEvent) {
	jsonValue, _ := json.Marshal(event)
	go callParentAPI("reportPSKAuthFailure", jsonValue)
}

func publishDisconnectEventParent(event WifiConnectEvent) {
	jsonValue, _ := json.Marshal(event)
	go callParentAPI("reportDisconnect", jsonValue)
}

type WifiConnectEvent struct {
	Event  string
	Iface  string
	Mac    string
	Router string
}

func wifiConnect(w http.ResponseWriter, r *http.Request) {
	//A device connected. Add the interface to the bridge,
	// and then add it to the bridge_access nft

	event := WifiConnectEvent{}
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if !isLeafRouter() {
		return
	}

	event.Router = LeafRouterID()

	publishConnectEventParent(event)

	//set br0 as the bridge master
	err = exec.Command("ip", "link", "set", "dev", event.Iface, "master", BRIDGE_IFACE).Run()
	if err != nil {
		fmt.Println("ip link set dev", event.Iface, "master br0 -- failed", err)
		return
	}

	//mark the interface isolated to prevent cross talk between devices
	err = exec.Command("bridge", "link", "set", "dev", event.Iface, "isolated", "on").Run()
	if err != nil {
		fmt.Println("Failed to set", event.Iface, "to isolated", err)
		return
	}

	updateBridgeAccess("add", event.Iface, event.Mac)

	// TBD need to sync with upstream about this event.
	// to handle pending devices joining.
}

type WifiConnectFailureEvent struct {
	Type   string
	MAC    string
	Reason string
	Status string
	Router string
}

func wifiConnectFailure(w http.ResponseWriter, r *http.Request) {
	//A device connected. Add the interface to the bridge,
	// and then add it to the bridge_access nft

	event := WifiConnectFailureEvent{}
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if !isLeafRouter() {
		return
	}

	event.Router = LeafRouterID()

	publishConnectFailureEventParent(event)
}

func wifiDisconnect(w http.ResponseWriter, r *http.Request) {
	//A device disconnected, update bridge_access. Add the interface to the bridge,
	// and then add it to the bridge_access nft

	event := WifiConnectEvent{}
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	event.Router = LeafRouterID()

	publishDisconnectEventParent(event)

	updateBridgeAccess("remove", event.Iface, event.Mac)

	//on disconnect it will automatically be removed from the bridge.
}

func tinyRoute(ip string, delta uint32) string {
	net_ip := net.ParseIP(ip)
	u := binary.BigEndian.Uint32(net_ip.To4()) - delta
	newIP := net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
	routeIP := newIP.String() + "/30"
	return routeIP
}

func callAPIDeviceSync(IP string, Token string, devices map[string]DeviceEntry) {
	jsonValue, _ := json.Marshal(devices)
	req, err := http.NewRequest(http.MethodPut, "http://"+IP+"/devices", bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("API device sync request failed", IP, err)
		return
	}

	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("API device sync request failed", resp.StatusCode)
		return
	}

}

func syncDevices(w http.ResponseWriter, r *http.Request) {
	devices := map[string]DeviceEntry{}
	err := json.NewDecoder(r.Body).Decode(&devices)
	if err != nil {
		fmt.Println("[-] failed to decode devices")
		http.Error(w, err.Error(), 400)
		return
	}
	Configmtx.Lock()
	defer Configmtx.Unlock()

	//for each subscribed leaf node, sync the devices
	config := loadConfigLocked()
	for _, entry := range config.LeafRouters {
		callAPIDeviceSync(entry.IP, entry.APIToken, devices)
	}

}

func callAPISetSSID(IP string, Token string, SSID string, iface string) {
	val := map[string]string{}
	val["Ssid"] = SSID
	jsonValue, _ := json.Marshal(val)
	req, err := http.NewRequest(http.MethodPut, "http://"+IP+"/hostapd/"+iface+"/config", bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("API Set SSID Failed", IP, iface, err)
		return
	}

	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("API Set SSID Failed", IP, iface, resp.StatusCode)
		return
	}

}

type InterfaceConfig struct {
	Name    string
	Type    string
	Enabled bool
}

func callAPIGetInterfaces(IP string, Token string) []InterfaceConfig {
	ifaces := []InterfaceConfig{}
	req, err := http.NewRequest(http.MethodGet, "http://"+IP+"/interfacesConfiguration", nil)
	if err != nil {
		return ifaces
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("API Get Interfaces failed", IP, err)
		return ifaces
	}

	err = json.NewDecoder(resp.Body).Decode(&ifaces)
	if err != nil {
		fmt.Println("[-] Could not deserialize interfaces")
		return ifaces
	}

	return ifaces

}

func callAPIGetStations(IP string, Token string, Iface string) []string {
	stations := []string{}
	var data map[string]interface{}
	req, err := http.NewRequest(http.MethodGet, "http://"+IP+"/"+Iface+"/all_stations", nil)
	if err != nil {
		return stations
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("API Get Stations failed", IP, err)
		return stations
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		fmt.Println("[-] Could not deserialize stations")
		return stations
	}

	for k := range data {
		stations = append(stations, k)
	}

	return stations
}

func getGlobalStations() []string {
	stations := []string{}
	Configmtx.Lock()
	defer Configmtx.Unlock()
	//for each subscribed leaf node, set the ssid
	config := loadConfigLocked()
	for _, entry := range config.LeafRouters {
		ifaces := callAPIGetInterfaces(entry.IP, entry.APIToken)
		for _, iface := range ifaces {
			if iface.Enabled && iface.Type == "AP" {
				stations = append(stations, callAPIGetStations(entry.IP, entry.APIToken, iface.Name)...)
			}
		}
	}
	return stations
}

func setSSID(w http.ResponseWriter, r *http.Request) {
	SSID := ""
	err := json.NewDecoder(r.Body).Decode(&SSID)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	Configmtx.Lock()
	defer Configmtx.Unlock()
	//for each subscribed leaf node, set the ssid
	config := loadConfigLocked()
	for _, entry := range config.LeafRouters {
		ifaces := callAPIGetInterfaces(entry.IP, entry.APIToken)
		for _, iface := range ifaces {
			if iface.Enabled && iface.Type == "AP" {
				callAPISetSSID(entry.IP, entry.APIToken, SSID, iface.Name)
			}
		}
	}

}

func leafRouters(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	defer Configmtx.Unlock()
	config := loadConfigLocked()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config.LeafRouters)
}

func leafRouter(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	defer Configmtx.Unlock()
	config := loadConfigLocked()

	entry := LeafRouter{}
	err := json.NewDecoder(r.Body).Decode(&entry)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	newLeaves := []LeafRouter{}

	//delete any partial matches in the existing list
	for _, existing := range config.LeafRouters {
		//match on either IP or API Token, and then delete it
		if existing.IP == entry.IP || existing.APIToken == entry.APIToken {
			continue
		} else {
			newLeaves = append(newLeaves, existing)
		}
	}

	if r.Method == http.MethodPut {
		//add the new entry
		newLeaves = append(newLeaves, entry)
	}

	//save it
	config.LeafRouters = newLeaves
	saveConfigLocked(config)

}

func setParentCredentials(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	defer Configmtx.Unlock()
	config := loadConfigLocked()

	if r.Method == http.MethodDelete {
		config.ParentIP = ""
		config.ParentAPIToken = ""
		saveConfigLocked(config)
		return
	}

	creds := ParentCredentials{}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if creds.ParentAPIToken == "" {
		fmt.Println("[-] Invalid API Token")
		http.Error(w, err.Error(), 400)
		return
	}

	ip := net.ParseIP(creds.ParentIP)
	if ip == nil {
		http.Error(w, fmt.Errorf("invalid ip "+creds.ParentIP).Error(), 400)
		return
	}

	//parent credentials are used to inform the parent about events
	config.ParentIP = creds.ParentIP
	config.ParentAPIToken = creds.ParentAPIToken

	saveConfigLocked(config)
}

func leafMode(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	defer Configmtx.Unlock()

	if r.Method == http.MethodPut {
		action := mux.Vars(r)["enable"]
		if action == "enable" {
			setLeafRouter(true)
			// whoever called enable is responsible for telling
			// superd to restart super
		} else if action == "disable" {
			setLeafRouter(false)
		} else {
			http.Error(w, fmt.Errorf("invalid enable param").Error(), 400)
			return
		}
	} else {
		val := isLeafRouter()
		json.NewEncoder(w).Encode(val)
	}

}
func main() {
	unix_plugin_router := mux.NewRouter().StrictSlash(true)

	//view mesh configuration
	unix_plugin_router.HandleFunc("/config", getMeshConfig).Methods("GET")

	//get and set leaf mode
	unix_plugin_router.HandleFunc("/leafMode/{enable}", leafMode).Methods("PUT")
	unix_plugin_router.HandleFunc("/leafMode", leafMode).Methods("GET")

	//adding a leaf router to a central router
	unix_plugin_router.HandleFunc("/leafRouters", leafRouters).Methods("GET")
	unix_plugin_router.HandleFunc("/leafRouter", leafRouter).Methods("PUT", "DELETE")

	//good use case for event bus
	// these are called by the API on-device into the mesh plugin
	unix_plugin_router.HandleFunc("/stationConnect", wifiConnect).Methods("PUT")
	unix_plugin_router.HandleFunc("/stationConnectFailure", wifiConnectFailure).Methods("PUT")
	unix_plugin_router.HandleFunc("/stationDisconnect", wifiDisconnect).Methods("PUT")

	//these are routines for synchronizing from a central router to a leaf router
	unix_plugin_router.HandleFunc("/syncDevices", syncDevices).Methods("PUT")
	unix_plugin_router.HandleFunc("/setSSID", setSSID).Methods("PUT")
	unix_plugin_router.HandleFunc("/setParentCredentials", setParentCredentials).Methods("PUT", "DELETE")

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initMesh()

	pluginServer.Serve(unixPluginListener)
}
