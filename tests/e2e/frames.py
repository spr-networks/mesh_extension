import socket
import struct
import subprocess
import sys


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    off = 24
    frames = []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frames.append(data[off:off + incl])
        off += incl
    return frames


def macsec_from(path, src_mac):
    src = bytes.fromhex(src_mac.replace(":", ""))
    return [f for f in read_pcap(path) if f[6:12] == src and f[12:14] == b"\x88\xe5"]


def send(iface, frames):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    for f in frames:
        s.send(f)


def tamper(frame):
    f = bytearray(frame)
    pn = struct.unpack("!I", f[16:20])[0]
    f[16:20] = struct.pack("!I", (pn + 1000000) & 0xFFFFFFFF)
    return bytes(f)


def stats(netns, dev):
    out = subprocess.check_output(["ip", "-n", netns, "-s", "macsec", "show", dev], text=True)
    totals = {}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "stats:" not in line or i + 1 >= len(lines):
            continue
        names = line.split("stats:")[1].split()
        values = lines[i + 1].split()
        for name, value in zip(names, values):
            if value.isdigit():
                totals[name] = totals.get(name, 0) + int(value)
    return totals


cmd = sys.argv[1]
if cmd == "count":
    print(len(macsec_from(sys.argv[2], sys.argv[3])))
elif cmd == "replay":
    frames = macsec_from(sys.argv[2], sys.argv[3])[:int(sys.argv[5])]
    send(sys.argv[4], frames)
    print(len(frames))
elif cmd == "tamper":
    frames = [tamper(f) for f in macsec_from(sys.argv[2], sys.argv[3])[:int(sys.argv[5])]]
    send(sys.argv[4], frames)
    print(len(frames))
elif cmd == "stat":
    print(stats(sys.argv[2], sys.argv[3]).get(sys.argv[4], 0))
