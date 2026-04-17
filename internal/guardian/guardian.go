package guardian

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
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

	filter := "tcp"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n[GALILEU] Sniffer ativo. Monitorando tráfego na porta 8080...\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if len(packet.Data()) > 0 {
			label := protocolLabel(packet)
			fmt.Printf("[%s] Pacote capturado! Tamanho: %d bytes\n", label, len(packet.Data()))
			fmt.Printf("[%s] Dados: %s\n", label, string(packet.Data()))
		}
	}
}


