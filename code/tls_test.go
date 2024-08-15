package main

import (
	"os"
	"testing"
)

func TestProcessEventAlerts(t *testing.T) {
	entry := LeafRouter{IP: os.Getenv("TEST_IP"), APIToken: os.Getenv("TEST_TOKEN")}
	err := chainTrustForNodeTLS(&entry)
	if err != nil {
		t.Error(err)
	}
	if entry.TLSCA == "" {
		t.Errorf("Failed to get a validated CA")
	}
}
