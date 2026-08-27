#!/bin/bash

# Drop input
iptables -P INPUT DROP

# Empty flow table
conntrack -D

# Enable ARP filter
sysctl -w net.ipv4.conf.all.arp_filter=1
# we will not use iptables for the bridge 
sysctl -w net.bridge.bridge-nf-call-iptables=0
sysctl -w net.bridge.bridge-nf-call-ip6tables=0


# Create the bridge interface
ip link add name br0 type bridge
ip link set dev "$WANIF" down

# Assign the bridge the WANIF MAC
# Give WANIF the ephemeral bridge MAC,
#  and the bridge the WANIF MAC
# And allow the bridge to receive a MAC address
INTERFACES_CONFIG=${INTERFACES_CONFIG:-/configs/base/interfaces.json}
CONFIGURED_WANMAC=$(
  grep -Eo '"(Name|MACOverride|MACRandomize)"[[:space:]]*:[[:space:]]*("[^"]*"|true|false)' -- "$INTERFACES_CONFIG" 2>/dev/null |
    awk -v wanif="$WANIF" '
      function emit() {
        if (!done && name == wanif && randomize != "true" && mac != "") {
          print mac
          done = 1
        }
      }
      {
        key = $0
        sub(/^"/, "", key)
        sub(/".*/, "", key)
        value = $0
        sub(/^[^:]*:[[:space:]]*/, "", value)
        gsub(/^"|"$/, "", value)
        if (key == "Name") {
          emit()
          if (done) {
            exit
          }
          name = value
          mac = ""
          randomize = "false"
        } else if (key == "MACOverride") {
          mac = value
        } else if (key == "MACRandomize") {
          randomize = value
        }
      }
      END {
        emit()
      }
    '
)
CONFIGURED_WANMAC=${CONFIGURED_WANMAC//-/:}
if [[ "$CONFIGURED_WANMAC" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
  WANMAC=$CONFIGURED_WANMAC
else
  WANMAC=$(ip -br link show dev "$WANIF" | awk '{print $3}')
fi
BRMAC=$(ip -br link show dev br0 | awk '{print $3}')
ip link set dev "$WANIF" address "$BRMAC"

# Add the upstream interface to the bridge
ip link set dev "$WANIF" master br0
ip link set dev br0 address "$WANMAC"
ip link set dev br0 up
ip link set dev "$WANIF" up
dhclient -r "$WANIF"
ip address flush dev "$WANIF"
# TBD should use our own dhcp client
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

WANIF=br0

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
    counter oifname . ether daddr vmap @bridge_access

    counter log prefix "drop:bridge " group 1
  }
}


table inet filter {

  # Dynamic maps of clients, populated by wifid
  map dhcp_access {
    type ifname . ether_addr: verdict;
  }
  
  set uplink_interfaces {
    type ifname;
    $(if [ "$WANIF" ]; then echo "elements = { $WANIF }" ; fi )
  }

  # this set contains wired lan, wired vlan, and wireless vlan clients
  # dynamically updated
  set lan_interfaces {
    type ifname;
    $(if [ "$LANIF" ]; then echo "elements = { $LANIF }" ; fi )
  }

  map wan_tcp_accept {
    type inet_service : verdict;
    elements = {
      22: accept,
      80: accept,
      443: accept,
    }
  }

  map lan_tcp_accept {
    type inet_service : verdict;
    elements = {
      22: accept,
      80: accept,
      443: accept,
    }
  }

  map wan_udp_accept {
    type inet_service : verdict;
  }

  map lan_udp_accept {
    type inet_service : verdict;
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

    #TCP Services
    iifname @uplink_interfaces counter tcp dport vmap @wan_tcp_accept
    # UDP services
    iifname @uplink_interfaces counter udp dport vmap @wan_udp_accept

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
