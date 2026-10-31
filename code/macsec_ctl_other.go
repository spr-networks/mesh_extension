//go:build !linux

package main

import (
	"errors"
	"time"
)

func sendRawFrame(dev string, frame []byte) error {
	return errors.New("raw frames are only supported on linux")
}

func recvRawFrames(dev string, timeout time.Duration, handle func([]byte) bool) error {
	return errors.New("raw frames are only supported on linux")
}
