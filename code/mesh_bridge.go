package main

import (
	"fmt"
	"net"
	"strings"
)

const meshBridge = "mshbr0"
const meshBridgeGuardTable = "mesh_bridge_guard"

type meshBridgePin struct{ Port, MAC string }

func renderBridgeGuard(own net.HardwareAddr, pins []meshBridgePin) (string, error) {
	t := meshBridgeGuardTable
	var b strings.Builder
	fmt.Fprintf(&b, "table bridge %s\ndelete table bridge %s\ntable bridge %s {\n", t, t, t)
	fmt.Fprintf(&b, "\tchain input {\n\t\ttype filter hook input priority -200; policy accept;\n\t\tmeta ibrname %q ether saddr %s drop\n", meshBridge, own)
	for _, pin := range pins {
		mac, err := net.ParseMAC(pin.MAC)
		if err != nil || len(mac) != 6 || (pin.Port != "" && !meshIfaceRE.MatchString(pin.Port)) {
			return "", fmt.Errorf("invalid bridge pin %q on %q", pin.MAC, pin.Port)
		}
		port := ""
		if pin.Port != "" {
			port = fmt.Sprintf(" iifname != %q", pin.Port)
		}
		fmt.Fprintf(&b, "\t\tmeta ibrname %q ether saddr %s%s drop\n", meshBridge, mac, port)
	}
	fmt.Fprintf(&b, "\t}\n\tchain forward {\n\t\ttype filter hook forward priority -200; policy accept;\n\t\tmeta ibrname %q drop\n\t}\n}\n", meshBridge)
	return b.String(), nil
}

func (m *macsecManager) reconcileMeshBridge(links []MACsecLinkStatus) {
	enabled := []*MACsecLinkStatus{}
	pins := []meshBridgePin{}
	for i := range links {
		if st := &links[i]; !st.Pending && st.Parent != "" {
			st.Interface = meshBridge
			enabled = append(enabled, st)
			if st.LeafMAC != "" {
				pins = append(pins, meshBridgePin{st.Member, st.LeafMAC})
			}
		}
	}
	if len(enabled) == 0 {
		m.removeMeshBridge()
		return
	}
	m.bridgeGone = false
	info, err := m.sys.LinkInfo(meshBridge)
	if err != nil {
		if parent, perr := m.sys.LinkInfo(enabled[0].Parent); perr == nil {
			m.sys.Cmd("ip", "link", "add", meshBridge, "address", parent.MAC.String(), "type", "bridge")
		}
		info, err = m.sys.LinkInfo(meshBridge)
	}
	if err == nil {
		err = m.sys.SetUp(meshBridge)
	}
	if err == nil {
		var ruleset string
		if ruleset, err = renderBridgeGuard(info.MAC, pins); err == nil {
			err = m.installTable("bridge", meshBridgeGuardTable, ruleset, &m.bridgeGuard, &m.bridgeGuardLive)
		}
	}
	if err != nil {
		fmt.Println("[-] mesh:", meshBridge, err)
	}
	for _, st := range enabled {
		port, perr := m.sys.LinkInfo(st.Member)
		st.Secured = st.Secured && err == nil && perr == nil
		if st.Secured && port.Master != meshBridge {
			joined := m.sys.SetMaster(st.Member, meshBridge) == nil
			st.Secured = joined && m.sys.Cmd("bridge", "link", "set", "dev", st.Member, "isolated", "on") == nil
			if joined && !st.Secured {
				m.sys.SetMaster(st.Member, "")
			}
		} else if !st.Secured && perr == nil && port.Master == meshBridge {
			m.sys.SetMaster(st.Member, "")
		}
	}
}

func (m *macsecManager) removeMeshBridge() {
	if m.bridgeGone {
		return
	}
	if m.linkExists(meshBridge) || m.bridgeGuard != "" {
		m.sys.DeleteLink(meshBridge)
		m.sys.NFTDeleteTable("bridge", meshBridgeGuardTable)
	}
	m.bridgeGuard, m.bridgeGuardLive, m.bridgeGone = "", "", true
}
