//go:build linux

package main

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func TestLeafCallsAdvertiseSmallMSS(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	d := net.Dialer{Timeout: 2 * time.Second, Control: meshCtlDialControl}
	c, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := <-accepted
	defer server.Close()
	raw, err := server.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mss int
	var serr error
	raw.Control(func(fd uintptr) {
		mss, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	})
	if serr != nil {
		t.Fatal(serr)
	}
	if mss > meshCtlMSS {
		t.Fatalf("leaf sends %d byte segments to the main router, want at most %d", mss, meshCtlMSS)
	}
}
