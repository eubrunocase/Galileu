package guardian

import (
	"fmt"
	"log"
	"github.com/google/windivert-go"
)

func StartGuardian() {
	filter := "outbound and (tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 8080)"
	
	wd, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatal("Erro: Certifique-se de estar como ADMIN e com a DLL na raiz:", err)
	}
	defer wd.Close()

	analyzer := NewAnalyzer()
	packetChan := make(chan *windivert.Packet, 100)

	for i := 0; i < 4; i++ {
		go func() {
			for packet := range packetChan {
				if len(packet.Payload) > 0 {
					found, cleanPayload := analyzer.Analyze(packet.Payload)
					if found {
						fmt.Println("[GALILEU] Interceptado: Dados sensíveis removidos.")
						packet.Payload = cleanPayload
					}
				}
				wd.Send(packet)
			}
		}()
	}

	fmt.Println("[GALILEU] Ativo. Interceptando e analisando chamadas...")
	for {
		packet, err := wd.Recv()
		if err != nil {
			continue
		}
		packetChan <- packet
	}
}