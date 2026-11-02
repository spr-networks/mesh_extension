//go:build !linux

package main

import (
	"errors"
	"syscall"
	"time"
)

func meshCtlDialControl(network, address string, c syscall.RawConn) error {
	return nil
}

func sendRawFrame(dev string, frame []byte) error {
	return errors.New("raw frames are only supported on linux")
}

func recvRawFrames(dev string, timeout time.Duration, handle func([]byte) bool) error {
	return errors.New("raw frames are only supported on linux")
}

func exchangeRawFrame(dev string, frame []byte, timeout time.Duration, handle func([]byte) bool) error {
	return errors.New("raw frames are only supported on linux")
}
