package guardian

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"unsafe"

	"github.com/imgk/divert-go"
)

const (
	MITMListenPort = 9001
	MinPacketSize  = 80
	HostsFile      = "C:\\Windows\\System32\\drivers\\etc\\hosts"
)

type IPv4Header struct {
	VersionIhl  uint8
	Tos         uint8
	TotalLength uint16
	Identifier  uint16
	FlagsFrag   uint16
	Ttl         uint8
	Protocol    uint8
	Checksum    uint16
	SourceIP    [4]byte
	DestIP      [4]byte
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

var monitoringDomains = []string{
	"opencode.ai",
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"api.cohere.ai",
	"api.cerebras.ai",
	"api.mistral.ai",
}

func loadCertificates() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair("rootCA.pem", "rootCA-key.pem")
	if err != nil {
		return nil, fmt.Errorf("erro certificados: %w", err)
	}
	return &cert, nil
}

func StartMITMListener() error {
	cert, err := loadCertificates()
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*cert},
		ServerName:         "*",
		InsecureSkipVerify: true,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", MITMListenPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	defer listener.Close()

	fmt.Printf("[GALILEU] MITM ativo em :%d\n", MITMListenPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[GALILEU] Erro: %v", err)
			continue
		}
		go handleMITMConnection(conn)
	}
}

func handleMITMConnection(clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 8192)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}

	payload := buf[:n]
	analyzer := NewAnalyzer()
	found, _ := analyzer.Analyze(payload)
	if found {
		fmt.Println("[GALILEU] Payload processado!")
	}

	host := "opencode.ai:443"
	for _, line := range strings.Split(string(payload), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				host = strings.TrimSpace(parts[1]) + ":443"
				break
			}
		}
	}

	upstream, err := tls.Dial("tcp", host, &tls.Config{
		ServerName:         strings.Split(host, ":")[0],
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer upstream.Close()

	upstream.Write(payload)
	resp := make([]byte, 8192)
	m, _ := upstream.Read(resp)
	clientConn.Write(resp[:m])
}

func getTCPHeader(packet []byte) *TCPHeader {
	if len(packet) < 20 {
		return nil
	}
	ip := (*IPv4Header)(unsafe.Pointer(&packet[0]))
	if ip.VersionIhl>>4 != 4 {
		return nil
	}
	tcpLen := int((ip.VersionIhl & 0x0F) * 4)
	if len(packet) < tcpLen+20 {
		return nil
	}
	return (*TCPHeader)(unsafe.Pointer(&packet[tcpLen]))
}

func hasRelevantPayload(packet []byte) bool {
	tcp := getTCPHeader(packet)
	if tcp == nil {
		return false
	}
	offset := int(tcp.DataOffset>>4) * 4
	if len(packet) <= offset {
		return false
	}
	return len(packet)-offset >= MinPacketSize
}

func containsRelevantDomain(packet []byte) bool {
	content := string(packet)
	for _, d := range monitoringDomains {
		if strings.Contains(content, d) {
			return true
		}
	}
	return false
}

func StartGuardian() {
	if _, err := os.Stat("rootCA.pem"); os.IsNotExist(err) {
		log.Println("[GALILEU] Aviso: rootCA.pem nao encontrado")
	}

	go func() {
		if err := StartMITMListener(); err != nil {
			log.Printf("[GALILEU] MITM: %v", err)
		}
	}()

	filter := "(outbound and tcp.DstPort == 443)"
	wd, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatal("Erro (ADMIN): ", err)
	}
	defer wd.Close()

	analyzer := NewAnalyzer()
	fmt.Println("[GALILEU] Ativo. Monitorando HTTPS...")

	for {
		buf := make([]byte, 1600)
		addr := new(divert.Address)
		n, err := wd.Recv(buf, addr)
		if err != nil || n == 0 {
			continue
		}

		if hasRelevantPayload(buf[:n]) && containsRelevantDomain(buf[:n]) {
			fmt.Printf("[GALILEU] >>> Pacote capturado: %d bytes\n", n)
			analyzer.Analyze(buf[:n])
		}

		_, _ = wd.Send(buf[:n], addr)
	}
}
