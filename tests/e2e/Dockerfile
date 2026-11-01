FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      linux-image-generic linux-modules-extra-$(apt-cache depends linux-image-generic | grep -o 'linux-image-[0-9][^ ]*' | head -1 | sed 's/linux-image-//') \
      qemu-system-arm virtme-ng busybox-static kmod binutils zstd udev \
      wpasupplicant wireguard-tools iproute2 nftables tcpdump iputils-ping python3 curl openssl procps \
    && rm -rf /var/lib/apt/lists/*
RUN python3 - <<'PY'
p = "/usr/lib/python3/dist-packages/virtme/architectures.py"
s = open(p).read()
old = '        if is_native:\n            ret.extend(["-M", "virt,gic-version=host"])'
assert s.count(old) == 1
open(p, "w").write(s.replace(old, '        if is_native and use_kvm:\n            ret.extend(["-M", "virt,gic-version=host"])'))
PY
RUN zcat /boot/vmlinuz-* > /boot/Image 2>/dev/null || cp /boot/vmlinuz-* /boot/Image
RUN ln -s /bin/busybox /usr/local/sbin/poweroff
