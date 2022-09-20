/**
 * Copyright (C) Longterm Security, Inc - All Rights Reserved
 *
 * This source code is protected under international copyright law.  All rights
 * reserved and protected by the copyright holders.
 * This file is confidential and only available to authorized individuals with the
 * permission of the copyright holders.  If you encounter this file and do not have
 * permission, please contact the copyright holders and delete this file.
 */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
)

import (
	"github.com/gorilla/mux"
)

var TEST_PREFIX = os.Getenv("TEST_PREFIX")
var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/state/plugins/mesh/socket"
var FirewallConfigFile = TEST_PREFIX + "/configs/mesh/rules.json"

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func getMeshConfig(w http.ResponseWriter, r *http.Request) {
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
	Iface string
	Mac string
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
}

func wifiDisconnect(w http.ResponseWriter, r *http.Request) {
	//A device connected. Add the interface to the bridge,
	// and then add it to the bridge_access nft

	event := WifiConnectEvent{}
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	updateBridgeAccess("remove", event.Iface, event.Mac)
}


func main() {
	unix_plugin_router := mux.NewRouter().StrictSlash(true)

	unix_plugin_router.HandleFunc("/config", getMeshConfig).Methods("GET")

	//good use case for event bus
	unix_plugin_router.HandleFunc("/stationConnect", wifiConnect).Methods("PUT")
	unix_plugin_router.HandleFunc("/stationDisconnect", wifiDisconnect).Methods("PUT")


	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initMesh()

	pluginServer.Serve(unixPluginListener)
}
