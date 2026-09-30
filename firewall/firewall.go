package firewall

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"
)

// Manager administra las reglas de mitigacion en iptables/nftables o mock.
type Manager struct {
	tool            string
	activeBlocks    map[string]*blockEntry
	mutex           sync.RWMutex
	unblockCallback func(ip string, eventID int64)
}

type blockEntry struct {
	ip        string
	eventID   int64
	timer     *time.Timer
	blockedAt time.Time
}

// NewManager crea una nueva instancia del administrador de firewall.
func NewManager(tool string) *Manager {
	return &Manager{
		tool:         tool,
		activeBlocks: make(map[string]*blockEntry),
	}
}

// SetUnblockCallback establece un callback global opcional al desbloquear una IP.
func (m *Manager) SetUnblockCallback(fn func(ip string, eventID int64)) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.unblockCallback = fn
}

// IsBlocked verifica si una IP se encuentra actualmente bloqueada.
func (m *Manager) IsBlocked(ip string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	_, exists := m.activeBlocks[ip]
	return exists
}

// BlockIP aplica una regla de bloqueo para una IP dada por una duracion especifica.
func (m *Manager) BlockIP(ip string, duration time.Duration, pps int, eventID int64, onUnblock func(ip string, eventID int64)) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Si ya esta bloqueada, renovar temporizador
	if entry, exists := m.activeBlocks[ip]; exists {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		entry.timer = time.AfterFunc(duration, func() {
			m.autoUnblock(ip, eventID, onUnblock)
		})
		log.Printf("[FIREWALL] Renovado bloqueo de IP %s por %v adicionales.", ip, duration)
		return nil
	}

	// Ejecutar comando de sistema segun herramienta configurada
	err := m.applySystemBlock(ip)
	if err != nil {
		return fmt.Errorf("error al aplicar regla de bloqueo para %s: %w", ip, err)
	}

	log.Printf("[FIREWALL] ⛔ IP BLOQUEADA EXITOSAMENTE: %s (Duración: %v, PPS: %d)", ip, duration, pps)

	// Configurar auto-desbloqueo asincrono
	entry := &blockEntry{
		ip:        ip,
		eventID:   eventID,
		blockedAt: time.Now(),
	}

	entry.timer = time.AfterFunc(duration, func() {
		m.autoUnblock(ip, eventID, onUnblock)
	})

	m.activeBlocks[ip] = entry
	return nil
}

// UnblockIP remueve manualmente la regla de bloqueo de una IP.
func (m *Manager) UnblockIP(ip string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	entry, exists := m.activeBlocks[ip]
	if !exists {
		return nil // Ya no estaba bloqueada
	}

	if entry.timer != nil {
		entry.timer.Stop()
	}

	err := m.applySystemUnblock(ip)
	delete(m.activeBlocks, ip)

	if err != nil {
		return fmt.Errorf("error al remover regla de bloqueo para %s: %w", ip, err)
	}

	log.Printf("[FIREWALL] ✅ IP DESBLOQUEADA: %s", ip)
	return nil
}

// autoUnblock funcion interna ejecutada al expirar el temporizador de 15s.
func (m *Manager) autoUnblock(ip string, eventID int64, onUnblock func(ip string, eventID int64)) {
	m.mutex.Lock()
	_, exists := m.activeBlocks[ip]
	if !exists {
		m.mutex.Unlock()
		return
	}
	delete(m.activeBlocks, ip)
	m.mutex.Unlock()

	err := m.applySystemUnblock(ip)
	if err != nil {
		log.Printf("[FIREWALL ERROR] Error al desbloquear automaticamente la IP %s: %v", ip, err)
	} else {
		log.Printf("[FIREWALL] 🔓 IP DESBLOQUEADA AUTOMÁTICAMENTE (15s expirar): %s", ip)
	}

	if onUnblock != nil {
		onUnblock(ip, eventID)
	}

	m.mutex.RLock()
	globalCb := m.unblockCallback
	m.mutex.RUnlock()

	if globalCb != nil {
		globalCb(ip, eventID)
	}
}

// applySystemBlock ejecuta la orden de firewall de sistema operativo.
func (m *Manager) applySystemBlock(ip string) error {
	switch m.tool {
	case "iptables":
		// Check si ya existe la regla para evitar duplicados en iptables
		checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
		if err := checkCmd.Run(); err == nil {
			return nil // Regla ya presente
		}
		cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables -A error: %s (%w)", string(output), err)
		}
	case "nftables":
		cmd := exec.Command("nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add rule error: %s (%w)", string(output), err)
		}
	case "mock", "dry-run":
		log.Printf("[FIREWALL SIMULATION] Executed command to block %s via %s", ip, m.tool)
	default:
		log.Printf("[FIREWALL SIMULATION - UNKNOWN TOOL %s] Mock blocking %s", m.tool, ip)
	}
	return nil
}

// applySystemUnblock elimina la regla de firewall del sistema operativo.
func (m *Manager) applySystemUnblock(ip string) error {
	switch m.tool {
	case "iptables":
		cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables -D error: %s (%w)", string(output), err)
		}
	case "nftables":
		log.Printf("[FIREWALL] nftables unblock for %s triggered", ip)
	case "mock", "dry-run":
		log.Printf("[FIREWALL SIMULATION] Executed command to unblock %s via %s", ip, m.tool)
	default:
		log.Printf("[FIREWALL SIMULATION - UNKNOWN TOOL %s] Mock unblocking %s", m.tool, ip)
	}
	return nil
}
