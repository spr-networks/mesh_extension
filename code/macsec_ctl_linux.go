//go:build linux

package main

import (
	"errors"
	"net"
	"syscall"
	"time"
)

const meshCtlMSS = 1200

func meshCtlDialControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, meshCtlMSS)
	}); err != nil {
		return err
	}
	return serr
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func openPacketSocket(dev string, etherType uint16) (int, int, error) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return -1, 0, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherType)))
	if err != nil {
		return -1, 0, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(etherType), Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return -1, 0, err
	}
	return fd, ifi.Index, nil
}

func sendRawFrame(dev string, frame []byte) error {
	if len(frame) < 14 {
		return errors.New("short frame")
	}
	fd, ifindex, err := openPacketSocket(dev, macsecCtlEtherType)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrLinklayer{Protocol: htons(macsecCtlEtherType), Ifindex: ifindex, Halen: 6}
	copy(sa.Addr[:], frame[:6])
	return syscall.Sendto(fd, frame, 0, sa)
}

func recvRawFrames(dev string, timeout time.Duration, handle func([]byte) bool) error {
	fd, _, err := openPacketSocket(dev, macsecCtlEtherType)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errMACsecCtlNoAck
		}
		if remaining > 500*time.Millisecond {
			remaining = 500 * time.Millisecond
		}
		tv := syscall.NsecToTimeval(remaining.Nanoseconds())
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return err
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		if handle(buf[:n]) {
			return nil
		}
	}
}

func exchangeRawFrame(dev string, frame []byte, timeout time.Duration, handle func([]byte) bool) error {
	if len(frame) < 14 {
		return errors.New("short frame")
	}
	fd, ifindex, err := openPacketSocket(dev, macsecCtlEtherType)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrLinklayer{Protocol: htons(macsecCtlEtherType), Ifindex: ifindex, Halen: 6}
	copy(sa.Addr[:], frame[:6])
	if err := syscall.Sendto(fd, frame, 0, sa); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errMACsecCtlNoAck
		}
		tv := syscall.NsecToTimeval(remaining.Nanoseconds())
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return err
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		if handle(buf[:n]) {
			return nil
		}
	}
}
