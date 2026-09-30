package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	// Limpiar variables de entorno para probar valores por defecto
	os.Unsetenv("IPS_INTERFACE")
	os.Unsetenv("IPS_THRESHOLD_PPS")
	os.Unsetenv("IPS_BLOCK_DURATION_SECONDS")

	cfg := LoadConfig()

	if cfg.NetworkInterface != "eth0" {
		t.Errorf("expected eth0, got %s", cfg.NetworkInterface)
	}
	if cfg.PPSThreshold != 40 {
		t.Errorf("expected 40, got %d", cfg.PPSThreshold)
	}
	if cfg.BlockDuration != 15*time.Second {
		t.Errorf("expected 15s, got %v", cfg.BlockDuration)
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	os.Setenv("IPS_INTERFACE", "lo")
	os.Setenv("IPS_THRESHOLD_PPS", "100")
	os.Setenv("IPS_BLOCK_DURATION_SECONDS", "30")

	defer func() {
		os.Unsetenv("IPS_INTERFACE")
		os.Unsetenv("IPS_THRESHOLD_PPS")
		os.Unsetenv("IPS_BLOCK_DURATION_SECONDS")
	}()

	cfg := LoadConfig()

	if cfg.NetworkInterface != "lo" {
		t.Errorf("expected lo, got %s", cfg.NetworkInterface)
	}
	if cfg.PPSThreshold != 100 {
		t.Errorf("expected 100, got %d", cfg.PPSThreshold)
	}
	if cfg.BlockDuration != 30*time.Second {
		t.Errorf("expected 30s, got %v", cfg.BlockDuration)
	}
}
