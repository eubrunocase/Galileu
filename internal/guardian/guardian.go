package guardian

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func protocolLabel(packet gopacket.Packet) string {
	label := "TCP"
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return label
	}

	payload := string(appLayer.Payload())
	if strings.HasPrefix(payload, "GET ") ||
		strings.HasPrefix(payload, "POST ") ||
		strings.HasPrefix(payload, "PUT ") ||
		strings.HasPrefix(payload, "DELETE ") ||
		strings.HasPrefix(payload, "PATCH ") ||
		strings.HasPrefix(payload, "HEAD ") ||
		strings.HasPrefix(payload, "OPTIONS ") ||
		strings.HasPrefix(payload, "HTTP/1.") {
		return "HTTP"
	}

	return label
}

func StartGuardian() {

	file, err := os.Create("guardian_log.pcap")
	if err != nil {
		log.Fatal("Erro ao criar PCAP:", err)
	}
	defer file.Close()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Erro ao encontrar dispositivos", err)
	}

	fmt.Println("Interfaces encontradas:")
	for _, d := range devices {
		fmt.Printf("Nome: %s | Descrição: %s\n", d.Name, d.Description)
	}

	device := "\\Device\\NPF_Loopback" 
	snapshotLen := int32(1600)
	promiscuous := false
	timeout := 1 * time.Second

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("Erro ao abrir dispositivo. Rode como Administrador:", err)
	}
	defer handle.Close()

	w := pcapgo.NewWriter(file)
	if err := w.WriteFileHeader(uint32(snapshotLen), handle.LinkType()); err != nil {
		log.Fatal("Erro ao escrever cabeçalho PCAP:", err)
	}

	filter := "tcp"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("Erro ao definir filtro BPF", err)
	}

	fmt.Printf("\n[GALILEU] Sniffer ativo. Monitorando tráfegos TCP/HTTP...\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		label := protocolLabel(packet)
		if len(packet.Data()) > 0 {
			fmt.Printf("[%s] Pacote capturado! Tamanho: %d bytes\n", label, len(packet.Data()))
			fmt.Printf("[%s] Dados: %s\n", label, string(packet.Data()))
		}

		if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Println("Erro ao escrever pacote no PCAP:", err)
			continue
		}
		log.Printf("[%s] Pacote salvo no PCAP. Tamanho: %d bytes\n", label, len(packet.Data()))
	}

}


