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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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
var FirewallConfigFile = TEST_PREFIX + "/configs/mesh/rules.json"
var BRIDGE_IFACE = "br0"

var Configmtx sync.RWMutex

type LeafRouter struct {
	APIToken string
	IP       string
}

type MeshConfig struct {
	LeafRouters []LeafRouter
}

var MeshConfigFile = TEST_PREFIX + "/configs/mesh/config.json"

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

type WifiConnectEvent struct {
	Action string
	Iface  string
	Mac    string
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

	updateBridgeAccess("add", event.Iface, event.Mac)

	//mark the interface isolated to prevent cross talk between devices
	err = exec.Command("bridge", "link", "set", "dev", event.Iface, "isolated", "on").Run()
	if err != nil {
		fmt.Println("Failed to set", event.Iface, "to isoalted", err)
		return
	}

	//set br0 as the bridge master
	err = exec.Command("ip", "link", "set", "dev", event.Iface, "master", BRIDGE_IFACE).Run()
	if err != nil {
		fmt.Println("ip link set dev", event.Iface, "master br0 -- failed", err)
		return
	}

	// TBD need to sync with upstream about this event.

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
	updateBridgeAccess("remove", event.Iface, event.Mac)

	//on disconnect it will automatically be removed from the bridge.
}

func callAPIDeviceSync(IP string, Token string, devices map[string]DeviceEntry) {
	jsonValue, _ := json.Marshal(devices)
	req, err := http.NewRequest(http.MethodPut, "http://" + IP + "/devices", bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer " + Token)

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

func callAPISetSSID(IP string, Token string, SSID string) {




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
		callAPISetSSID(entry.IP, entry.APIToken, SSID)
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
	if err == nil {
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

func main() {
	unix_plugin_router := mux.NewRouter().StrictSlash(true)

	unix_plugin_router.HandleFunc("/config", getMeshConfig).Methods("GET")

	//good use case for event bus
	unix_plugin_router.HandleFunc("/stationConnect", wifiConnect).Methods("PUT")
	unix_plugin_router.HandleFunc("/stationDisconnect", wifiDisconnect).Methods("PUT")
	unix_plugin_router.HandleFunc("/syncDevice", syncDevices).Methods("PUT")
	unix_plugin_router.HandleFunc("/setSSID", setSSID).Methods("PUT")

	unix_plugin_router.HandleFunc("/leafRouters", leafRouters).Methods("GE")
	unix_plugin_router.HandleFunc("/leafRouter", leafRouter).Methods("PUT", "DELETE")

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initMesh()

	pluginServer.Serve(unixPluginListener)
}
