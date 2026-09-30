package firewall

import (
	"sync"
	"testing"
	"time"
)

func TestFirewallMockBlockAndAutoUnblock(t *testing.T) {
	mgr := NewManager("mock")

	ip := "192.168.1.100"
	duration := 200 * time.Millisecond

	var unblockedWg sync.WaitGroup
	unblockedWg.Add(1)

	var unblockedIP string
	var unblockedEventID int64

	err := mgr.BlockIP(ip, duration, 50, 1001, func(unblocked string, eventID int64) {
		unblockedIP = unblocked
		unblockedEventID = eventID
		unblockedWg.Done()
	})

	if err != nil {
		t.Fatalf("unexpected error blocking IP: %v", err)
	}

	if !mgr.IsBlocked(ip) {
		t.Errorf("expected IP %s to be blocked", ip)
	}

	// Esperar a que transcurra el temporizador de auto-unblock
	unblockedWg.Wait()

	if mgr.IsBlocked(ip) {
		t.Errorf("expected IP %s to be unblocked after duration", ip)
	}

	if unblockedIP != ip {
		t.Errorf("expected unblocked IP to be %s, got %s", ip, unblockedIP)
	}

	if unblockedEventID != 1001 {
		t.Errorf("expected eventID 1001, got %d", unblockedEventID)
	}
}

func TestFirewallManualUnblock(t *testing.T) {
	mgr := NewManager("mock")
	ip := "10.0.0.5"

	err := mgr.BlockIP(ip, 10*time.Second, 60, 2002, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mgr.IsBlocked(ip) {
		t.Errorf("expected IP %s to be blocked", ip)
	}

	err = mgr.UnblockIP(ip)
	if err != nil {
		t.Fatalf("unexpected error unblocking: %v", err)
	}

	if mgr.IsBlocked(ip) {
		t.Errorf("expected IP %s to be unblocked", ip)
	}
}
