package guardian

import (
	"fmt"
	"log"

	"github.com/imgk/divert-go"
)

func StartGuardian() {
	filter := "outbound and (tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 8080)"

	wd, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatal("Erro: Certifique-se de estar como ADMIN e com a DLL na raiz:", err)
	}
	defer wd.Close()

	analyzer := NewAnalyzer()

	type CapturedPacket struct {
		Data []byte
		Addr *divert.Address
		Len  uint
	}

	packetChan := make(chan *CapturedPacket, 100)

	for i := 0; i < 4; i++ {
		go func() {
			for cp := range packetChan {
				if cp.Len > 0 {
					found, cleanPayload := analyzer.Analyze(cp.Data[:cp.Len])
					if found {
						fmt.Println("[GALILEU] Interceptado: Dados sensíveis removidos.")
						cp.Data = cleanPayload
						cp.Len = uint(len(cleanPayload))
					}
				}
				wd.Send(cp.Data, cp.Addr)
			}
		}()
	}

	fmt.Println("[GALILEU] Ativo. Interceptando e analisando chamadas...")

	for {
		buf := make([]byte, 1600)
		addr := new(divert.Address)

		n, err := wd.Recv(buf, addr)
		if err != nil || n == 0 {
			continue
		}

		packetChan <- &CapturedPacket{
			Data: buf,
			Addr: addr,
			Len:  n,
		}
	}
}
