package detector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ThreatHandler es la funcion callback invocada cuando una IP excede el umbral PPS.
type ThreatHandler func(ip string, pps int)

// TrafficMetricsHandler es la funcion callback invocada periodicamente para reportar las metricas de trafico.
type TrafficMetricsHandler func(ip string, pps int, isThreat bool)

// PacketPacket struct representa la informacion minima extraida de un paquete.
type PacketInfo struct {
	SourceIP  string
	Timestamp time.Time
}

// Detector se encarga de capturar paquetes y analizar la tasa por segundo por IP origen.
type Detector struct {
	iface          string
	snapLen        int32
	promisc        bool
	bpfFilter      string
	thresholdPPS   int
	windowDuration time.Duration

	onThreat  ThreatHandler
	onMetrics TrafficMetricsHandler

	// Almacena conteo de paquetes por IP para la ventana actual
	ipCounts map[string]int
	mutex    sync.Mutex

	// Canal para procesar paquetes concurrentemente mediante goroutines
	packetChan chan PacketInfo
}

// NewDetector crea e inicializa un nuevo detector de intrusiones.
func NewDetector(iface string, thresholdPPS int, windowDuration time.Duration, onThreat ThreatHandler, onMetrics TrafficMetricsHandler) *Detector {
	if windowDuration <= 0 {
		windowDuration = 1 * time.Second
	}
	return &Detector{
		iface:          iface,
		snapLen:        65535,
		promisc:        true,
		bpfFilter:      "ip",
		thresholdPPS:   thresholdPPS,
		windowDuration: windowDuration,
		onThreat:       onThreat,
		onMetrics:      onMetrics,
		ipCounts:       make(map[string]int),
		packetChan:     make(chan PacketInfo, 10000),
	}
}

// ProcessPacket mock or test helper para inyectar paquetes directamente sin libpcap.
func (d *Detector) ProcessPacketInfo(pkt PacketInfo) {
	d.packetChan <- pkt
}

// Start inicia la captura y el analisis concurrente.
func (d *Detector) Start(ctx context.Context) error {
	handle, err := pcap.OpenLive(d.iface, d.snapLen, d.promisc, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error al abrir la interfaz de red %s: %w", d.iface, err)
	}
	defer handle.Close()

	if d.bpfFilter != "" {
		if err := handle.SetBPFFilter(d.bpfFilter); err != nil {
			log.Printf("[DETECTOR WARN] No se pudo aplicar filtro BPF '%s': %v", d.bpfFilter, err)
		}
	}

	log.Printf("[DETECTOR] Captura iniciada en interfaz '%s'. Escuchando trafico...", d.iface)

	// Goroutine 1: Evaluador periodico de umbrales
	go d.startWindowEvaluator(ctx)

	// Goroutine 2: Worker para procesar canal de paquetes
	go d.startPacketProcessor(ctx)

	// Goroutine 3: Capturador pcap
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			log.Println("[DETECTOR] Deteniendo captura de paquetes...")
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			d.parseAndEnqueue(packet)
		}
	}
}

// StartFromChannel permite ejecutar el detector consumiendo directamente de un canal (util para tests).
func (d *Detector) StartFromChannel(ctx context.Context) {
	go d.startWindowEvaluator(ctx)
	go d.startPacketProcessor(ctx)
}

func (d *Detector) parseAndEnqueue(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP string
	switch layer := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = layer.SrcIP.String()
	case *layers.IPv6:
		srcIP = layer.SrcIP.String()
	default:
		return
	}

	if srcIP != "" {
		select {
		case d.packetChan <- PacketInfo{SourceIP: srcIP, Timestamp: time.Now()}:
		default:
			// Canal lleno, omitir si hay sobrecarga masiva para evitar bloqueos
		}
	}
}

// startPacketProcessor consume paquetes del canal concurrente y actualiza el contador.
func (d *Detector) startPacketProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-d.packetChan:
			if !ok {
				return
			}
			d.mutex.Lock()
			d.ipCounts[pkt.SourceIP]++
			d.mutex.Unlock()
		}
	}
}

// startWindowEvaluator evalua cada 1 segundo (o windowDuration) la tasa de pps acumulada.
func (d *Detector) startWindowEvaluator(ctx context.Context) {
	ticker := time.NewTicker(d.windowDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.evaluateWindow()
		}
	}
}

func (d *Detector) evaluateWindow() {
	d.mutex.Lock()
	currentCounts := d.ipCounts
	d.ipCounts = make(map[string]int) // Resetear mapa para la siguiente ventana de 1 segundo
	d.mutex.Unlock()

	for ip, count := range currentCounts {
		// PPS es directamente el conteo acumulado en la ventana de 1 segundo
		pps := count
		isThreat := pps > d.thresholdPPS

		if d.onMetrics != nil {
			d.onMetrics(ip, pps, isThreat)
		}

		if isThreat {
			log.Printf("[DETECTOR AMENAZA] ⚠️ ALERTA: IP %s supero el umbral con %d pps (Umbral: %d pps)", ip, pps, d.thresholdPPS)
			if d.onThreat != nil {
				d.onThreat(ip, pps)
			}
		}
	}
}
