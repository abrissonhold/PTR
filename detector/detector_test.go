package detector

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDetectorDoSThreshold(t *testing.T) {
	var detectedThreats []string
	var threatPPS []int
	var mu sync.Mutex

	onThreat := func(ip string, pps int) {
		mu.Lock()
		defer mu.Unlock()
		detectedThreats = append(detectedThreats, ip)
		threatPPS = append(threatPPS, pps)
	}

	threshold := 40
	window := 100 * time.Millisecond
	det := NewDetector("lo", threshold, window, onThreat, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	det.StartFromChannel(ctx)

	targetIP := "192.168.1.50"
	// Enviar 50 paquetes para superar el umbral de 40
	for i := 0; i < 50; i++ {
		det.ProcessPacketInfo(PacketInfo{SourceIP: targetIP, Timestamp: time.Now()})
	}

	normalIP := "10.0.0.1"
	// Enviar 10 paquetes (debajo del umbral de 40)
	for i := 0; i < 10; i++ {
		det.ProcessPacketInfo(PacketInfo{SourceIP: normalIP, Timestamp: time.Now()})
	}

	// Esperar a que la ventana se evalue
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(detectedThreats) != 1 {
		t.Fatalf("expected 1 threat detected, got %d", len(detectedThreats))
	}

	if detectedThreats[0] != targetIP {
		t.Errorf("expected threat IP %s, got %s", targetIP, detectedThreats[0])
	}

	if threatPPS[0] != 50 {
		t.Errorf("expected 50 pps, got %d", threatPPS[0])
	}
}
