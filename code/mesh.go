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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
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
var OTPSettingsFile = TEST_PREFIX + "/configs/auth/otp_settings.json"
var AuthTokensFile = TEST_PREFIX + "/configs/auth/auth_tokens.json"
var ApiTlsCaCert = TEST_PREFIX + "/configs/auth/cert/www-api-ca.crt"
var BRIDGE_IFACE = "br0"

var Configmtx sync.RWMutex
var Tokensmtx sync.Mutex

type LeafRouter struct {
	APIToken string
	IP       string
	TLSCA    string
}

type ParentCredentials struct {
	ParentIP       string
	ParentAPIToken string
	ParentCA       string
}

type MeshConfig struct {
	ParentCredentials
	LeafRouters []LeafRouter
}

type OTPUser struct {
	Name      string
	Secret    string
	Confirmed bool
	AlwaysOn  bool
}

type OTPUserRequest struct {
	Name           string
	Code           string
	UpdateAlwaysOn bool
	AlwaysOn       bool
}

type OTPSettings struct {
	OTPUsers           []OTPUser
	JWTDurationSeconds int64
}

type OTPSettingsRequest struct {
	Token    string
	Settings OTPSettings
}

type Token struct {
	Name        string
	Token       string
	Expire      int64
	ScopedPaths []string
}

var MeshConfigFile = TEST_PREFIX + "/configs/mesh/config.json"

func CATLSVerifierTransport(TLSCA []byte) http.Transport {
	return http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}

				caPool, err := CAPoolFromCABytes(TLSCA)
				if err != nil {
					return err
				}

				// Verify the server certificate using the CA
				opts := x509.VerifyOptions{
					Roots: caPool,
				}

				_, err = cert.Verify(opts)
				if err != nil {
					return err
				}

				return nil
			},
		},
	}
}
func StandardTLSClient(tlsca string) http.Client {
	transport := CATLSVerifierTransport([]byte(tlsca))
	return http.Client{Timeout: 10 * time.Second, Transport: &transport}
}

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
		if os.Getenv("DEBUGHTTP") != "" {
			fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		}
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
	if err = json.Unmarshal(stdout, &data); err != nil {
		fmt.Println("nft json parse error", err)
		return existing
	}
	data2, ok := data["nftables"].([]interface{})
	if !ok || len(data2) < 2 {
		fmt.Println("nft json: missing nftables array")
		return existing
	}
	data3, ok := data2[1].(map[string]interface{})
	if !ok {
		return existing
	}
	data4, ok := data3["map"].(map[string]interface{})
	if !ok {
		return existing
	}
	data5, ok := data4["elem"].([]interface{})
	if !ok {
		return existing
	}
	for _, d := range data5 {
		e, ok := d.([]interface{})
		if !ok || len(e) < 1 {
			continue
		}
		f, ok := e[0].(map[string]interface{})
		if !ok {
			continue
		}
		g, ok := f["concat"].([]interface{})
		if !ok || len(g) < 2 {
			continue
		}
		iface, okIface := g[0].(string)
		mac, okMac := g[1].(string)
		if okIface && okMac {
			existing = append(existing, ifaceMacKey{iface, mac})
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
		os.WriteFile(MESH_ENABLED_LEAF_PATH, nil, 0600)
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
	config := loadConfigLocked()
	Configmtx.Unlock()

	if config.ParentIP == "" {
		return
	}

	if config.ParentAPIToken == "" {
		fmt.Println("[-] Mesh leaf not configured with parent API token, aborting call to", Path)
		return
	}

	req, err := http.NewRequest(http.MethodPut, "https://"+config.ParentIP+"/"+Path, bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+config.ParentAPIToken)

	c := StandardTLSClient(config.ParentCA)
	defer c.CloseIdleConnections()
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
	Iface  string
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

	if !isLeafRouter() {
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

func callAPIDeviceSync(IP string, Token string, TLSCA string, devices map[string]DeviceEntry) {
	jsonValue, _ := json.Marshal(devices)
	req, err := http.NewRequest(http.MethodPut, "https://"+IP+"/devices", bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := StandardTLSClient(TLSCA)
	defer c.CloseIdleConnections()
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
	config := loadConfigLocked()
	Configmtx.Unlock()

	//for each subscribed leaf node, sync the devices
	for _, entry := range config.LeafRouters {
		callAPIDeviceSync(entry.IP, entry.APIToken, entry.TLSCA, devices)
	}

}

func syncOTP(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	//for each subscribed leaf node, sync the devices
	config := loadConfigLocked()
	Configmtx.Unlock()

	for _, entry := range config.LeafRouters {
		//propagate the OTP settings from main to leaf node
		callAPISetOTP(entry.IP, entry.APIToken, entry.TLSCA)
	}

}

func callAPISetSSID(IP string, Token string, TLSCA string, SSID string, iface string) {
	val := map[string]string{}
	val["Ssid"] = SSID
	jsonValue, _ := json.Marshal(val)
	req, err := http.NewRequest(http.MethodPut, "https://"+IP+"/hostapd/"+iface+"/config", bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := StandardTLSClient(TLSCA)
	defer c.CloseIdleConnections()
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

func callAPISetOTP(IP string, Token string, TLSCA string) {
	Tokensmtx.Lock()
	settings, err := otpLoadLocked()
	Tokensmtx.Unlock()
	if err != nil && len(settings.OTPUsers) == 0 {
		return
	}

	request := OTPSettingsRequest{Settings: settings, Token: Token}
	jsonValue, _ := json.Marshal(request)
	req, err := http.NewRequest(http.MethodPut, "https://"+IP+"/plugins/mesh/setOTP", bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := StandardTLSClient(TLSCA)
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("set OTP Failure")
		return
	}

	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("API Set OTP Failed", IP, resp.StatusCode)
		return
	}
}

type InterfaceConfig struct {
	Name    string
	Type    string
	Enabled bool
}

func callAPIGetInterfaces(IP string, Token string, TLSCA string) []InterfaceConfig {
	ifaces := []InterfaceConfig{}
	req, err := http.NewRequest(http.MethodGet, "https://"+IP+"/interfacesConfiguration", nil)
	if err != nil {
		return ifaces
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := StandardTLSClient(TLSCA)
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("API Get Interfaces failed", IP, err)
		return ifaces
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("API Get Interfaces failed", IP, resp.StatusCode)
		return ifaces
	}

	err = json.NewDecoder(resp.Body).Decode(&ifaces)
	if err != nil {
		fmt.Println("[-] Could not deserialize interfaces")
		return ifaces
	}

	return ifaces

}

/*
//unused code
func callAPIGetStations(IP string, Token string, Iface string) []string {
	stations := []string{}
	var data map[string]interface{}
	req, err := http.NewRequest(http.MethodGet, "https://"+IP+"/"+Iface+"/all_stations", nil)
	if err != nil {
		return stations
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	c := http.Client{}
	defer c.CloseIdleConnections()
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
*/

//unused code
/*
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
*/

func setSSID(w http.ResponseWriter, r *http.Request) {
	SSID := ""
	err := json.NewDecoder(r.Body).Decode(&SSID)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	Configmtx.Lock()
	//for each subscribed leaf node, set the ssid
	config := loadConfigLocked()

	Configmtx.Unlock()

	for _, entry := range config.LeafRouters {
		ifaces := callAPIGetInterfaces(entry.IP, entry.APIToken, entry.TLSCA)
		for _, iface := range ifaces {
			if iface.Enabled && iface.Type == "AP" {
				callAPISetSSID(entry.IP, entry.APIToken, entry.TLSCA, SSID, iface.Name)
			}
		}
	}

}

func leafRouters(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	config := loadConfigLocked()
	Configmtx.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config.LeafRouters)
}

func leafRouter(w http.ResponseWriter, r *http.Request) {
	entry := LeafRouter{}
	err := json.NewDecoder(r.Body).Decode(&entry)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	Configmtx.Lock()
	config := loadConfigLocked()
	defer Configmtx.Unlock()


	if r.Method == http.MethodPut {
		if entry.TLSCA != "" {
			http.Error(w, "Field not accepted", 400)
			return
		}
	}
	// do not accept a TLSCA Arg
	entry.TLSCA = ""

	newLeaves := []LeafRouter{}

	//delete any partial matches in the existing list
	for _, existing := range config.LeafRouters {
		//match on either IP or API Token, and then delete it
		if existing.IP == entry.IP && subtle.ConstantTimeCompare([]byte(existing.APIToken), []byte(entry.APIToken)) == 1 {
			continue
		} else {
			newLeaves = append(newLeaves, existing)
		}
	}

	if r.Method == http.MethodPut {
		err = chainTrustForNodeTLS(&entry)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if entry.TLSCA == "" {
			http.Error(w, "Failed to get mesh TLS Certificate", 400)
			return
		}
		//add the new entry
		newLeaves = append(newLeaves, entry)
	}

	//save it
	config.LeafRouters = newLeaves
	saveConfigLocked(config)

}

func validateCA(certPEM string) error {
	if certPEM == "" {
		return errors.New("Missing CA String")
	}

	// Decode the PEM block
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("failed to parse certificate: " + err.Error())
	}

	// Check if it's a CA certificate
	if !cert.IsCA {
		return errors.New("certificate is not a CA certificate")
	}

	// Check if it's self-signed (issuer and subject should be the same)
	if cert.Subject.String() != cert.Issuer.String() {
		return errors.New("certificate is not self-signed (subject and issuer do not match)")
	}

	// Verify the signature
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return errors.New("certificate signature verification failed: " + err.Error())
	}

	// Check if the certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("certificate is not valid at the current time")
	}

	// Check Basic Constraints
	if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
		return errors.New("CA certificate does not have basic constraints set properly")
	}

	return nil
}

func setParentCredentials(w http.ResponseWriter, r *http.Request) {
	creds := ParentCredentials{}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	Configmtx.Lock()
	config := loadConfigLocked()
	defer Configmtx.Unlock()

	if r.Method == http.MethodDelete {
		config.ParentIP = ""
		config.ParentAPIToken = ""
		config.ParentCA = ""
		saveConfigLocked(config)
		return
	}

	if creds.ParentAPIToken == "" {
		fmt.Println("[-] Invalid API Token")
		http.Error(w, "Invalid API Token", 400)
		return
	}

	ip := net.ParseIP(creds.ParentIP)
	if ip == nil {
		http.Error(w, "invalid ip "+creds.ParentIP, 400)
		return
	}

	if creds.ParentCA == "" {
		http.Error(w, "Missing CA for parent SPR", 400)
		return
	}
	err = validateCA(creds.ParentCA)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	//parent credentials are used to inform the parent about events
	config.ParentIP = creds.ParentIP
	config.ParentAPIToken = creds.ParentAPIToken
	config.ParentCA = creds.ParentCA

	saveConfigLocked(config)
	//+
}

func otpSaveLocked(settings OTPSettings) error {
	file, _ := json.MarshalIndent(settings, "", " ")
	return ioutil.WriteFile(OTPSettingsFile, file, 0600)
}

func otpLoadLocked() (OTPSettings, error) {
	settings := OTPSettings{}
	data, err := os.ReadFile(OTPSettingsFile)
	if err == nil {
		err = json.Unmarshal(data, &settings)
	}

	return settings, err
}

func setOTP(w http.ResponseWriter, r *http.Request) {

	request := OTPSettingsRequest{}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	//verify that only the downhaul token was used to do this
	// the downhaul token is owned by the parent SPR.
	// it is not retrievable without a valid OTP code from either mesh or parent.

	token, err := getToken(DOWNHAUL_TOKEN_NAME)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if subtle.ConstantTimeCompare([]byte(token.Token), []byte(request.Token)) != 1 {
		http.Error(w, "Invalid token to set OTP", 400)
		return
	}

	settings := request.Settings

	Tokensmtx.Lock()
	err = otpSaveLocked(settings)
	Tokensmtx.Unlock()

	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

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
			http.Error(w, "invalid enable param", 400)
			return
		}
	} else {
		val := isLeafRouter()
		json.NewEncoder(w).Encode(val)
	}
}

func getToken(name string) (Token, error) {
	tokens := []Token{}
	Tokensmtx.Lock()
	data, err := os.ReadFile(AuthTokensFile)
	Tokensmtx.Unlock()
	if err != nil {
		return Token{}, err
	}

	err = json.Unmarshal(data, &tokens)
	if err != nil {
		return Token{}, err
	}

	for _, tok := range tokens {
		if tok.Name == name {
			return tok, nil
		}
	}

	return Token{}, fmt.Errorf("token not found")
}

var DOWNHAUL_TOKEN_NAME = "PLUS-MESH-API-DOWNHAUL-TOKEN"

func getCertApiKey(r *http.Request) string {

	/*

		//in the future, we might allow the parent SPR to also have this endpoint,
		//but for now, only the leaf node case is handled

		Configmtx.Lock()
		config := loadConfigLocked()
		Configmtx.Unlock()

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return ""
		}

		//we knew about this leaf router IP, thats requesting,
		// we must be the parent then.
		for _, router := range config.LeafRouters {
			if router.IP == ip {
				return DOWNHAUL_TOKEN_NAME + "|" + router.APIToken
			}
		}
	*/
	// we are then possibly a leaf node, look up our key to use instead
	token, err := getToken(DOWNHAUL_TOKEN_NAME)
	if err == nil {
		return DOWNHAUL_TOKEN_NAME + "|" + token.Token
	}

	//failed
	return ""
}

var HMACHeader = "X-SPR-Mesh-TLS-Hash"

func getCert(w http.ResponseWriter, r *http.Request) {
	apikey := getCertApiKey(r)

	if apikey != "" {
		sig, err := createHMACSignatureWithFile(ApiTlsCaCert, "X-MESH|"+apikey)
		if err == nil {
			w.Header().Set(HMACHeader, sig)
		}
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, ApiTlsCaCert)
}

func CAPoolFromCABytes(data []byte) (*x509.CertPool, error) {
	err := validateCA(string(data))
	if err != nil {
		return nil, err
	}

	// Parse the received CA certificate
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return caPool, nil
}

func chainTrustForNodeTLS(meshNode *LeafRouter) error {
	var serverCert *x509.Certificate

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				serverCert = cert
				return nil
			},
		},
	}

	//note: this is unauthenticated
	req, err := http.NewRequest(http.MethodGet, "https://"+meshNode.IP+"/mesh/cert", nil)
	if err != nil {
		return errors.New("failed to create request")
	}
	// we explicitly do not add an authorization header here

	c := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("failed make cert request")
	}

	hmac_given := resp.Header.Get(HMACHeader)

	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return errors.New("wrong error code for cert request: " + fmt.Sprint(resp.StatusCode))
	}

	hmac_expected, err := createHMACSignatureWithData(data, "X-MESH|"+DOWNHAUL_TOKEN_NAME+"|"+meshNode.APIToken)
	if err != nil {
		return err
	}

	if hmac_given == "" {
		return errors.New("missing hmac")
	}

	if subtle.ConstantTimeCompare([]byte(hmac_given), []byte(hmac_expected)) != 1 {
		return errors.New("invalid hmac")
	}

	if serverCert == nil {
		return errors.New("server certificate not captured")
	}

	caPool, err := CAPoolFromCABytes(data)
	if err != nil {
		return err
	}

	// Verify the server certificate using the CA
	opts := x509.VerifyOptions{
		Roots: caPool,
	}

	_, err = serverCert.Verify(opts)
	if err != nil {
		return errors.New("server certificate not signed by provided CA")
	}

	meshNode.TLSCA = string(data)
	return nil
}

func createHMACSignatureWithData(data []byte, keymaterial string) (string, error) {

	// Hash the keymaterial with SHA256
	h := sha256.New()
	h.Write([]byte(keymaterial))
	key := h.Sum(nil)

	// Create HMAC signature
	hmacSigner := hmac.New(sha256.New, key)
	hmacSigner.Write(data)
	signature := hmacSigner.Sum(nil)

	signatureHex := hex.EncodeToString(signature)

	return signatureHex, nil
}

func createHMACSignatureWithFile(filename string, keymaterial string) (string, error) {
	// Read the file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return createHMACSignatureWithData(data, keymaterial)
}

// StationInfo represents the parsed hostapd station information
type StationInfo map[string]string

// LeafStations represents all stations from a leaf router
type LeafStations struct {
	LeafIP   string
	Stations map[string]StationInfo // MAC -> station info
	Error    error
}

// callAPIAllStations calls the all_stations endpoint for a specific interface
func callAPIAllStations(IP string, Token string, TLSCA string, iface string) (map[string]map[string]string, error) {
	url := fmt.Sprintf("https://%s/hostapd/%s/all_stations", IP, iface)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	// Create custom client with 3 second timeout
	transport := CATLSVerifierTransport([]byte(TLSCA))
	client := http.Client{
		Timeout:   3 * time.Second,
		Transport: &transport,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to poll %s interface %s: %v", IP, iface, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("leaf %s returned status %d for interface %s", IP, resp.StatusCode, iface)
	}

	var stationData map[string]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&stationData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return stationData, nil
}

// pollLeafRouterStations polls a single leaf router for connected stations
func pollLeafRouterStations(leafRouter LeafRouter) LeafStations {
	result := LeafStations{
		LeafIP:   leafRouter.IP,
		Stations: make(map[string]StationInfo),
	}

	// First, get the list of interfaces from the leaf router
	interfaces := callAPIGetInterfaces(leafRouter.IP, leafRouter.APIToken, leafRouter.TLSCA)

	// Poll each AP interface
	for _, iface := range interfaces {
		if !iface.Enabled || iface.Type != "AP" {
			continue
		}

		stationData, err := callAPIAllStations(leafRouter.IP, leafRouter.APIToken, leafRouter.TLSCA, iface.Name)
		if err != nil {
			result.Error = err
			continue
		}

		// Merge stations from this interface
		for mac, info := range stationData {
			result.Stations[mac] = StationInfo(info)
		}
	}

	return result
}

// getAllLeafStations polls all leaf routers concurrently for connected stations
func getAllLeafStations() map[string]LeafStations {
	Configmtx.RLock()
	config := loadConfigLocked()
	leafRouters := config.LeafRouters
	Configmtx.RUnlock()

	results := make(map[string]LeafStations)
	resultsChan := make(chan LeafStations, len(leafRouters))

	// Poll all leaf routers concurrently
	for _, leafRouter := range leafRouters {
		go func(lr LeafRouter) {
			resultsChan <- pollLeafRouterStations(lr)
		}(leafRouter)
	}

	// Collect results
	for i := 0; i < len(leafRouters); i++ {
		result := <-resultsChan
		results[result.LeafIP] = result
	}

	return results
}

// API handler to get all stations from all leaf routers
func getAllStationsHandler(w http.ResponseWriter, r *http.Request) {
	stations := getAllLeafStations()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stations)
}

type LeafTopology struct {
	LeafIP   string
	Online   bool
	Topology json.RawMessage
}

//returns the topology document and whether the leaf host answered at all --
//an older leaf API without /topology still proves the leaf is reachable
func callAPIGetTopology(IP string, Token string, TLSCA string) (json.RawMessage, bool) {
	req, err := http.NewRequest("GET", "https://"+IP+"/topology", nil)
	if err != nil {
		return nil, false
	}
	req.Header.Add("Authorization", "Bearer "+Token)

	transport := CATLSVerifierTransport([]byte(TLSCA))
	c := http.Client{
		Timeout:   3 * time.Second,
		Transport: &transport,
	}
	defer c.CloseIdleConnections()

	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("failed to poll topology", IP, err)
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("leaf topology status", IP, resp.StatusCode)
		return nil, true
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, true
	}
	return data, true
}

func getAllLeafTopologies() []LeafTopology {
	Configmtx.RLock()
	config := loadConfigLocked()
	leafRouters := config.LeafRouters
	Configmtx.RUnlock()

	resultsChan := make(chan LeafTopology, len(leafRouters))
	for _, leafRouter := range leafRouters {
		go func(lr LeafRouter) {
			topology, reachable := callAPIGetTopology(lr.IP, lr.APIToken, lr.TLSCA)
			resultsChan <- LeafTopology{LeafIP: lr.IP, Online: reachable, Topology: topology}
		}(leafRouter)
	}

	results := []LeafTopology{}
	for i := 0; i < len(leafRouters); i++ {
		results = append(results, <-resultsChan)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].LeafIP < results[j].LeafIP
	})

	return results
}

func getLeafTopologiesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getAllLeafTopologies())
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
	unix_plugin_router.HandleFunc("/setOTP", setOTP).Methods("PUT")
	unix_plugin_router.HandleFunc("/syncOTP", syncOTP).Methods("PUT")
	unix_plugin_router.HandleFunc("/setParentCredentials", setParentCredentials).Methods("PUT", "DELETE")
	unix_plugin_router.HandleFunc("/cert", getCert).Methods("GET")

	// Get all stations from all leaf routers
	unix_plugin_router.HandleFunc("/allLeafStations", getAllStationsHandler).Methods("GET")
	unix_plugin_router.HandleFunc("/leafTopologies", getLeafTopologiesHandler).Methods("GET")

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initMesh()

	pluginServer.Serve(unixPluginListener)
}
