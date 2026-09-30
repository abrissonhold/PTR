package config

import (
	"os"
	"strconv"
	"time"
)

// Config almacena toda la configuracion necesaria para el funcionamiento del IPS.
type Config struct {
	// Interfaz de red a monitorear (ej. "eth0", "wlan0", "lo" o "any")
	NetworkInterface string

	// Umbral de paquetes por segundo (pps) para clasificar como DoS
	PPSThreshold int

	// Duracion de la ventana de evaluacion (por defecto 1 segundo)
	WindowDuration time.Duration

	// Duracion del bloqueo temporal en la regla de firewall (por defecto 15 segundos)
	BlockDuration time.Duration

	// Herramienta de firewall a utilizar ("iptables", "nftables", "mock" o "dry-run")
	FirewallTool string

	// DSN de conexion a MySQL (ej. "root:password@tcp(127.0.0.1:3306)/ips_db?parseTime=true")
	MySQLDSN string

	// Flag para habilitar modo promiscuo en la captura de red
	PromiscuousMode bool

	// Longitud maxima de captura de paquete (SnapLen)
	SnapLen int32

	// BPF Filter opcional para pcap (ej. "ip")
	BPFFilter string
}

// LoadConfig carga la configuracion desde variables de entorno con valores por defecto seguros.
func LoadConfig() *Config {
	cfg := &Config{
		NetworkInterface: getEnv("IPS_INTERFACE", "eth0"),
		PPSThreshold:     getEnvAsInt("IPS_THRESHOLD_PPS", 40),
		WindowDuration:   time.Duration(getEnvAsInt("IPS_WINDOW_SECONDS", 1)) * time.Second,
		BlockDuration:    time.Duration(getEnvAsInt("IPS_BLOCK_DURATION_SECONDS", 15)) * time.Second,
		FirewallTool:     getEnv("IPS_FIREWALL_TOOL", "iptables"),
		MySQLDSN:         getEnv("IPS_MYSQL_DSN", "root:rootpassword@tcp(127.0.0.1:3306)/ips_db?parseTime=true"),
		PromiscuousMode:  getEnvAsBool("IPS_PROMISCUOUS", true),
		SnapLen:          int32(getEnvAsInt("IPS_SNAPLEN", 65535)),
		BPFFilter:        getEnv("IPS_BPF_FILTER", "ip"),
	}

	return cfg
}

// getEnv obtiene una variable de entorno o retorna un valor por defecto si no esta definida.
func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

// getEnvAsInt obtiene una variable de entorno como int o retorna un valor por defecto.
func getEnvAsInt(key string, fallback int) int {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return fallback
	}
	return val
}

// getEnvAsBool obtiene una variable de entorno como bool o retorna un valor por defecto.
func getEnvAsBool(key string, fallback bool) bool {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}
	val, err := strconv.ParseBool(valStr)
	if err != nil {
		return fallback
	}
	return val
}
