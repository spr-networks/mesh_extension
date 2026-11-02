package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func reconcileOps(env *macsecTestEnv) []string {
	before := len(env.sys.Ops())
	env.m.reconcile()
	return env.sys.Ops()[before:]
}

func twoWGLeavesConfig(t *testing.T) (MeshConfig, string) {
	config := mainConfigWithLeaves(2, 2)
	for _, leaf := range config.LeafRouters {
		leaf.MACsec.Mode = backhaulWireGuard
		leaf.MACsec.LeafPublicKey = newTestWGPub(t)
	}
	return config, config.LeafRouters[0].MACsec.LeafPublicKey
}

func TestMainBridgeJoinsOnlySecuredLinks(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config, pubA := twoWGLeavesConfig(t)
	writeMeshConfig(t, config)
	ops := reconcileOps(env)
	eth1 := env.sys.infos["eth1"].MAC.String()
	if !contains(ops, "cmd ip link add mshbr0 address "+eth1+" type bridge") || indexOf(ops, "master mshvx") >= 0 {
		t.Fatalf("bridge not created with the parent's MAC, or an unsecured tunnel joined: %v", ops)
	}
	a, b := env.m.Status().Links[0], env.m.Status().Links[1]
	if a.Interface != meshBridge || a.Member != "mshvx2" || b.Interface != meshBridge || b.Member != "mshvx3" || a.Secured || b.Secured {
		t.Fatalf("status before handshake: %+v %+v", a, b)
	}
	for _, want := range []string{
		`meta ibrname "mshbr0" ether saddr ` + eth1 + ` drop`,
		`meta ibrname "mshbr0" ether saddr 00:11:22:33:44:00 iifname != "mshvx2" drop`,
		`meta ibrname "mshbr0" ether saddr 00:11:22:33:44:01 iifname != "mshvx3" drop`,
		"hook forward",
	} {
		if !strings.Contains(env.sys.tables[meshBridgeGuardTable], want) {
			t.Errorf("guard missing %q:\n%s", want, env.sys.tables[meshBridgeGuardTable])
		}
	}

	env.sys.handshakes = map[string]int64{pubA: env.clock.Unix()}
	ops = reconcileOps(env)
	join, isolate := indexOf(ops, "master mshvx2 mshbr0"), indexOf(ops, "cmd bridge link set dev mshvx2 isolated on")
	if join < 0 || isolate < join || contains(ops, "master mshvx3 mshbr0") || !env.m.Status().Links[0].Secured || env.m.Status().Links[1].Secured {
		t.Fatalf("secured tunnel not joined and isolated, or unsecured one joined: %v %+v", ops, env.m.Status().Links)
	}
	if ops = reconcileOps(env); indexOf(ops, "master mshvx2") >= 0 || contains(ops, "nft bridge-guard") {
		t.Fatalf("bridge reconfigured on an unchanged pass: %v", ops)
	}

	env.clock = env.clock.Add(10 * time.Minute)
	if ops = reconcileOps(env); !contains(ops, "nomaster mshvx2") || env.m.Status().Links[0].Secured {
		t.Fatalf("stale tunnel kept in the bridge: %v", ops)
	}

	for _, leaf := range config.LeafRouters {
		leaf.MACsec.Enabled = false
	}
	writeMeshConfig(t, config)
	if ops = reconcileOps(env); !contains(ops, "del mshbr0") || !contains(ops, "nft-del bridge "+meshBridgeGuardTable) {
		t.Fatalf("bridge or guard left behind with no links: %v", ops)
	}
}

func TestMainBridgeNeedsTheGuard(t *testing.T) {
	env := setupMACsecEnv(t, false)
	config, pubA := twoWGLeavesConfig(t)
	writeMeshConfig(t, config)
	env.sys.handshakes = map[string]int64{pubA: env.clock.Unix()}
	env.sys.nftErr = errors.New("nft unavailable")
	if ops := reconcileOps(env); contains(ops, "master mshvx2 mshbr0") || env.m.Status().Links[0].Secured {
		t.Fatalf("tunnel joined the bridge without the node MAC guard: %v", ops)
	}
	env.sys.nftErr = nil
	if ops := reconcileOps(env); !contains(ops, "master mshvx2 mshbr0") {
		t.Fatalf("tunnel not joined once the guard installed: %v", ops)
	}
	env.sys.mu.Lock()
	delete(env.sys.tables, meshBridgeGuardTable)
	env.sys.mu.Unlock()
	if !contains(reconcileOps(env), "nft bridge-guard") {
		t.Fatal("flushed guard not reinstalled")
	}
}

func TestMainBridgeMACsecLink(t *testing.T) {
	env := setupMACsecEnv(t, false)
	writeMeshConfig(t, mainConfigWithLeaves(1, 1))
	env.m.reconcile()
	member := env.m.Status().Links[0].Member
	env.sys.secure(member, true, true)
	ops := reconcileOps(env)
	guard := env.sys.tables[meshBridgeGuardTable]
	if !strings.HasPrefix(member, "macsec") || !contains(ops, "master "+member+" mshbr0") || !strings.Contains(guard, `iifname != "`+member+`"`) {
		t.Fatalf("secured MACsec link not bridged and pinned: %v\n%s", ops, guard)
	}
	env.sys.DeleteLink(member)
	ops = reconcileOps(env)
	st := env.m.Status().Links[0]
	if contains(ops, "del mshbr0") || st.Interface != meshBridge || st.Secured {
		t.Fatalf("bridge torn down or link secured while the secY restarts: %+v %v", st, ops)
	}
	if guard = env.sys.tables[meshBridgeGuardTable]; !strings.Contains(guard, "ether saddr 00:11:22:33:44:00 drop") {
		t.Fatalf("node MAC not blocked while it has no port:\n%s", guard)
	}
}

func TestRenderBridgeGuardRejectsBadInput(t *testing.T) {
	own := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, pin := range []meshBridgePin{{"mshvx2", "zz"}, {`x" accept; #`, "02:00:00:00:00:02"}} {
		if _, err := renderBridgeGuard(own, []meshBridgePin{pin}); err == nil {
			t.Errorf("accepted %+v", pin)
		}
	}
}
