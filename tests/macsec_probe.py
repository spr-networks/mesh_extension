#!/usr/bin/env python3
import errno
import json
import socket
import struct
import subprocess
import sys
import time

FRAMES = {
    "ipv4": struct.pack("!H", 0x0800) + bytes.fromhex("4500002e000040004006") + b"\x00" * 36,
    "arp": struct.pack("!H", 0x0806) + bytes.fromhex("0001080006040001") + b"\x00" * 38,
    "ipv6": struct.pack("!H", 0x86DD) + bytes.fromhex("6000000000063b40") + b"\x00" * 38,
    "vlan_ipv4": struct.pack("!HHH", 0x8100, 0x0005, 0x0800) + b"\x45" + b"\x00" * 43,
    "qinq_ipv4": struct.pack("!HHHHH", 0x88A8, 0x0007, 0x8100, 0x0005, 0x0800) + b"\x45" + b"\x00" * 39,
    "vlan_macsec": struct.pack("!HHH", 0x8100, 0x0005, 0x88E5) + b"\x2c" + b"\x00" * 43,
    "lldp": struct.pack("!H", 0x88CC) + b"\x02\x07\x04" + b"\x00" * 43,
    "eapol": struct.pack("!H", 0x888E) + bytes.fromhex("0305") + b"\x00" * 44,
    "macsec": struct.pack("!H", 0x88E5) + bytes.fromhex("2c00000000017a1122334455000100") + b"\x00" * 31,
}


def send(iface, dst):
    dst_mac = bytes.fromhex(dst.replace(":", ""))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    src_mac = s.getsockname()[4]
    refused = 0
    for _ in range(3):
        for frame in FRAMES.values():
            try:
                s.send(dst_mac + src_mac + frame)
            except OSError as e:
                if e.errno != errno.ENOBUFS:
                    raise
                refused += 1
            time.sleep(0.002)
    if refused:
        print(f"{refused} frames dropped at egress", file=sys.stderr)


def counters(table, chain):
    out = subprocess.check_output(["nft", "-j", "list", "chain", "netdev", table, chain])
    result = {}
    for item in json.loads(out)["nftables"]:
        rule = item.get("rule")
        if not rule or "comment" not in rule:
            continue
        for expr in rule["expr"]:
            if "counter" in expr:
                result[rule["comment"]] = expr["counter"]["packets"]
    print(json.dumps(result, sort_keys=True))


def mss(sock):
    return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)


def serve(addr, port):
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(1)
    s.settimeout(10)
    conn, _ = s.accept()
    print(mss(conn), flush=True)
    conn.close()


def connect(addr, port):
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    for _ in range(50):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((addr, int(port)))
            print(mss(s), flush=True)
            s.close()
            return
        except OSError:
            s.close()
            time.sleep(0.1)
    sys.exit("connect failed")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"send": send, "counters": counters, "serve": serve, "connect": connect}[cmd](*args)
