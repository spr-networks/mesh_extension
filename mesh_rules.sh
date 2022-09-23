#!/bin/bash

# Disable IP forwarding. Not needed with bridge.

sysctl net.ipv4.ip_forward=0

# Drop input
iptables -P INPUT DROP

# Empty flow table
conntrack -D

# Enable ARP filter
sysctl net.ipv4.conf.all.arp_filter=1

# Create the bridge interface
ip link add name br0 type bridge
ip link set dev $WANIF down

# Assign the bridge the WANIF MAC
# Give WANIF the ephemeral bridge MAC,
#  and the bridge the WANIF MAC
# And allow the bridge to receive a MAC address
WANMAC = $(ip -br link show dev ${WANIF} | awk '{print $3}')
BRMAC = $(ip -br link show dev br0 | awk '{print $3}')
ip link set dev $WANIF address ${BRMAC}
ip link set dev br0 address ${WANMAC}
ip link set dev br0 up
ip link set dev $WANIF up

# Add the upstream interface to the bridge
ip link set dev $WANIF master br0

# TBD should use our own dhcp client for htis
dhclient br0

# Clean previous rules
iptables --flush
iptables -t nat --flush
iptables --delete-chain
iptables -t nat --delete-chain

iptables-legacy --flush
iptables-legacy -t nat --flush
iptables-legacy --delete-chain
iptables-legacy -t nat --delete-chain

nft flush ruleset

nft -f - << EOF

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

    counter log prefix "drop:bridge " group 1
  }
}


table inet filter {

  # Dynamic maps of clients, populated by wifid
  map dhcp_access {
    type ifname . ether_addr: verdict;
  }

  map upstream_tcp_port_drop {
    type inet_service : verdict;
    elements = {
      22: drop,
      80: drop,
      443: drop,
      5201: drop
    }
  }

  map spr_tcp_port_accept {
    type inet_service : verdict;
    elements = {
      22: accept,
      80: accept,
      443: accept,
      5201: accept
    }
  }


  chain INPUT {
    type filter hook input priority 0; policy drop;

    #jump USERDEF_INPUT
    iif lo counter accept
    counter jump F_EST_RELATED

    # Mark whether the input came from upstream (wan:in) or local network (lan:in)
    $(if [ "$WANIF" ]; then echo "iifname $WANIF log prefix \"wan:in \" group 0"; fi)
    $(if [ "$WANIF" ]; then echo "iifname ne $WANIF log prefix \"lan:in \" group 0"; else echo "log prefix \"lan:in \" group 0"; fi)

    # drop dhcp requests, multicast ports from upstream
    # When updating lan_udp_accept, updated this list.
    $(if [ "$WANIF" ]; then echo "iifname $WANIF udp dport {67, 1900, 5353} counter jump DROPLOGINP"; fi)

    # drop ssh, iperf from upstream
    $(if [ "$WANIF" ]; then echo "counter iifname $WANIF tcp dport vmap @upstream_tcp_port_drop"; fi)

    # Allow ssh, iperf3 from LAN and those not dropped from upstream (see upstream_tcp_port_drop)
    counter tcp dport vmap @spr_tcp_port_accept
    counter jump DROPLOGINP
  }

  chain FORWARD {
    type filter hook forward priority 0; policy drop;

    counter jump F_EST_RELATED

    # allow docker containers to communicate upstream
    $(if [ "$WANIF" ] && [ "$DOCKERIF" ]; then echo "iif $DOCKERIF oifname $WANIF ip saddr $DOCKERNET counter accept"; fi)
    # allow docker containers to speak to LAN also
    $(if [ "$LANIF" ] && [ "$DOCKERIF" ]; then echo "iif $DOCKERIF oifname $LANIF ip saddr $DOCKERNET counter accept"; fi)

  }

  chain DROPLOGINP {
    counter log prefix "drop:input " group 1
    counter drop
  }

  chain F_EST_RELATED {
    ip protocol udp ct state related,established counter accept
    ip protocol tcp ct state related,established counter accept
    ip protocol icmp ct state related,established counter accept
  }

}

EOF


# Accept input
iptables -P INPUT ACCEPT
