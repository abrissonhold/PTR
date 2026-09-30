package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ips-dos-prevention/config"
	"ips-dos-prevention/database"
	"ips-dos-prevention/detector"
	"ips-dos-prevention/firewall"
)

// Colores ANSI para formateo visual en la terminal
const (
	ColorReset  = "\030[0m"
	ColorRed    = "\033[1;31m"
	ColorGreen  = "\033[1;32m"
	ColorYellow = "\033[1;33m"
	ColorCyan   = "\033[1;36m"
	ColorBold   = "\033[1m"
)

func main() {
	printBanner()

	// 1. Cargar configuracion
	cfg := config.LoadConfig()
	log.Printf("[CONFIG] Interfaz: %s | Umbral: %d pps | Bloqueo: %v | Firewall: %s",
		cfg.NetworkInterface, cfg.PPSThreshold, cfg.BlockDuration, cfg.FirewallTool)

	// 2. Conectar a MySQL (opcional/resiliente si la DB no estuviera disponible de inmediato)
	dbClient, err := database.NewDBClient(cfg.MySQLDSN)
	if err != nil {
		log.Printf("[DATABASE WARN] No se pudo conectar a MySQL (%v). El IPS continuara operando en consola.", err)
	} else {
		defer dbClient.Close()
	}

	// 3. Inicializar Administrador de Firewall
	fwManager := firewall.NewManager(cfg.FirewallTool)

	// Callback cuando se libere un bloqueo (para registrar en DB)
	unblockDBCallback := func(ip string, eventID int64) {
		printFormattedAlert("UNBLOCK", fmt.Sprintf("IP %s desbloqueada tras cumplir tiempo de expiración.", ip))
		if dbClient != nil {
			_ = dbClient.RecordUnblockEvent(ip, eventID)
		}
	}

	// 4. Callback para procesar picos de trafico detectados (Amenazas DoS)
	onThreatDetected := func(ip string, pps int) {
		printFormattedAlert("AMENAZA", fmt.Sprintf("PICO DETECTADO: IP %s transmitiendo a %d pps (> %d pps)", ip, pps, cfg.PPSThreshold))

		if fwManager.IsBlocked(ip) {
			log.Printf("[IPS] La IP %s ya se encuentra bloqueada. Ignorando re-bloqueo activo.", ip)
			return
		}

		// Persistir evento de bloqueo en MySQL
		var eventID int64
		if dbClient != nil {
			var err error
			eventID, err = dbClient.RecordBlockEvent(ip, pps, int(cfg.BlockDuration.Seconds()))
			if err != nil {
				log.Printf("[DATABASE ERROR] Error registrando bloqueo: %v", err)
			}
		}

		// Ejecutar accion mitigadora automatica
		err := fwManager.BlockIP(ip, cfg.BlockDuration, pps, eventID, unblockDBCallback)
		if err != nil {
			log.Printf("[FIREWALL ERROR] Fallo al aplicar bloqueo a %s: %v", ip, err)
		} else {
			printFormattedAlert("ACCION", fmt.Sprintf("Regla de bloqueo aplicada a %s por %v", ip, cfg.BlockDuration))
		}
	}

	// Callback para registrar metricas periodicas de trafico
	onTrafficMetrics := func(ip string, pps int, isThreat bool) {
		if dbClient != nil {
			_ = dbClient.RecordTraffic(ip, pps, isThreat)
		}
	}

	// 5. Inicializar Motor Detector
	det := detector.NewDetector(
		cfg.NetworkInterface,
		cfg.PPSThreshold,
		cfg.WindowDuration,
		onThreatDetected,
		onTrafficMetrics,
	)

	// Manejo de senales de apagado limpio (SIGINT / SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[IPS] Recibida senal de apagado. Limpiando recursos y deteniendo motor IPS...")
		cancel()
	}()

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("[IPS] Sistema de Prevención de Intrusos ACTIVO. Escuchando en '%s'...\n", cfg.NetworkInterface)
	fmt.Println("--------------------------------------------------------------------------------")

	// Iniciar monitoreo en tiempo real
	if err := det.Start(ctx); err != nil {
		log.Fatalf("[IPS FATAL] Error ejecutando detector: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	fmt.Println("[IPS] Sistema finalizado correctamente.")
}

func printBanner() {
	banner := `
================================================================================
  _____ _____   _____   _____   ____   _____   _____  _____ ______   _____ _____  _____
 |_   _|  __ \ / ____| |  __ \ / __ \ / ____| |  __ \|  __ \  ____| |  __ \  __ \/ ____|
   | | | |__) | (___   | |  | | |  | | (___   | |__) | |__) | |__    | |  | | |__) | (___
   | | |  ___/ \___ \  | |  | | |  | |\___ \  |  ___/|  _  /|  __|   | |  | |  ___/ \___ \
  _| |_| |     ____) | | |__| | |__| |____) | | |    | | \ \| |____  | |__| | |     ____) |
 |_____|_|    |_____/  |_____/ \____/|_____/  |_|    |_|  \_\______| |_____/|_|    |_____/

         SISTEMA DE PREVENCION DE INTRUSOS EN TIEMPO REAL - MITIGACION DOS
================================================================================
`
	fmt.Println(banner)
}

func printFormattedAlert(category string, message string) {
	now := time.Now().Format("2006-01-02 15:04:05.000")
	var prefix string
	switch category {
	case "AMENAZA":
		prefix = fmt.Sprintf("\033[1;31m[%s] [AMENAZA DoS DETECTADA]\033[0m", now)
	case "ACCION":
		prefix = fmt.Sprintf("\033[1;33m[%s] [MITIGACION AUTOMATICA]\033[0m", now)
	case "UNBLOCK":
		prefix = fmt.Sprintf("\033[1;32m[%s] [RESTABLECIMIENTO ACCESO]\033[0m", now)
	default:
		prefix = fmt.Sprintf("\033[1;36m[%s] [%s]\033[0m", now, category)
	}
	fmt.Printf("%s %s\n", prefix, message)
}
