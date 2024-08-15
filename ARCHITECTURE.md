# MESH Architecture

SPR Supports wired backhaul from SPR devices running as mesh nodes, serving as WiFi APs.

The uplink interface (eth0) serves as the bridge master for 'br0'.
When stations connect over wifi, their vlan is joined with 'isolated on',
so they can not directly communicate with one-another or see each others traffic on the bridge.

That isolation combined with a MAC filter provides defense in depth hardening against network attacks.

Furthermore, per-device PSKs are used assigned by MAC address.

## Not Currently Supported
- Wired Clients
- Wireless Backhaul
- Rotating API keys

## Provisioning mesh nodes UX

To provision:
- Generate the API token on the mesh node
- On the main SPR router, set the IP and token from the mesh node, and hit save

## Provisioning implementation

1. The Mesh UI generates an API token named `PLUS-MESH-API-DOWNHAUL-TOKEN`
2. When installed on the main router, the main router then:
a. Generates a scoped token, `PLUS-MESH-API-TOKEN`, to allow mesh nodes to call:
1) /reportPSKAuthSuccess
2) /reportPSKAuthFailure
3) /reportDisconnect
For when wifi clients connect/disconnect to the SPR mesh node

b. Using the downhaul token the main SPR provisions the mesh node
- over HTTPS, on node, calls /cert to get the mesh TLS cert. see tls setup*
- on node: calls setParentCredentials to apply the PLUS-MESH-API-TOKEN for upcalls to the main router.
- on node: calls set otp
- on node: calls setLeafMode true ( to enable mesh )
- on main: saves the mesh node info (PUT /leafRouter) to update config.LeafRouters.
- on node: restarts SPR to reboot as a bridged mesh node

### * TLS Setup
#### Overview
Nodes and the main router independently set up a CA and certificates
We use the PLUS-MESH-API-DOWNHAUL-TOKEN to bootstrap trust between the main SPR and the mesh node,
and rely on the browser to place the main SPR's cert onto the mesh node

The setParentCredentials call has a ParentCA field which includes /cert from the main spr router, that the mesh node will use

For authenticated the mesh node to the SPR Router:
- when a leaf router is added, the main router's backend will query and save the mesh node's CA
- the mesh node + plugin has a /cert endpoint that returns a `X-SPR-Mesh-TLS-Hash` header with the HMAC of the cert
- the cert is authed with the HMAC-SHA256 of `X-MESH|` + `PLUS-MESH-API-DOWNHAUL-TOKEN|` + `TOKEN-DATA`
- The main SPR router uses this key to verify the TLS certificate

- For browsers, users must trust the cert manually
Uses:
- The mesh node itself does the report callbacks with the PLUS-MESH-API-TOKEN. It needs TLS to call the main SPR.

The main SPR backend uses TLS on the mesh node to :
- sync devices.json /syncDevices
- set the ssid names /setSSID


## Bridged Firewall on nodes


```nft
table bridge filter {

  #TBD do we integrate IP address filter here also?
  # Main thing is that leaf stops MAC spoofing for an assigned devices.

  map bridge_access {
    type ifname . ether_addr: verdict;
  }

  chain FORWARD {
  type filter hook forward priority 0; policy drop;
    counter log prefix "bridge:in " group 0

    counter iifname . ether saddr vmap @bridge_access
    counter oifname . ether daddr vmap @bridge_access

    counter log prefix "drop:bridge " group 1
  }
}
```

## Runtime Design

When devices are updated, the main SPR router will sync the devices configuration to the mesh nodes.
This is required to push down the wifi passwords and mac addresses.

When a mesh node gets a wifi connect, disconnect, or password failure, it will use
its api key to report the event to the main router, which will handle it accordingly.
