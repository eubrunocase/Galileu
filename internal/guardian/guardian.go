package guardian

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/imgk/divert-go"
)

const (
	MITMListenAddr = "127.0.0.1:9001"
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

var hostsEntries = []string{
	"127.0.0.1 opencode.ai",
	"127.0.0.1 api.anthropic.com",
	"127.0.0.1 api.openai.com",
	"127.0.0.1 generativelanguage.googleapis.com",
	"127.0.0.1 api.cohere.ai",
	"127.0.0.1 api.cerebras.ai",
	"127.0.0.1 api.mistral.ai",
}

func setupDNSRedirect() error {
	fmt.Println("[GALILEU] Configurando redirecionamento DNS...")

	content, err := os.ReadFile(HostsFile)
	if err != nil {
		return fmt.Errorf("erro ao ler arquivo hosts: %w", err)
	}

	fileContent := string(content)

	for _, entry := range hostsEntries {
		domain := strings.Split(entry, " ")[1]
		if strings.Contains(fileContent, domain) {
			fmt.Printf("[GALILEU] Entrada já existe: %s\n", domain)
			continue
		}

		fileContent += "\n" + entry
		fmt.Printf("[GALILEU] Adicionado: %s\n", entry)
	}

	err = os.WriteFile(HostsFile, []byte(fileContent), 0644)
	if err != nil {
		return fmt.Errorf("erro ao escrever arquivo hosts: %w", err)
	}

	fmt.Println("[GALILEU] DNS configurado com sucesso!")
	return nil
}

func cleanupDNSRedirect() error {
	fmt.Println("[GALILEU] Removendo redirecionamento DNS...")

	content, err := os.ReadFile(HostsFile)
	if err != nil {
		return fmt.Errorf("erro ao ler arquivo hosts: %w", err)
	}

	fileContent := string(content)
	lines := strings.Split(fileContent, "\n")
	var newLines []string

	for _, line := range lines {
		shouldRemove := false
		for _, entry := range hostsEntries {
			if strings.TrimSpace(line) == entry {
				shouldRemove = true
				break
			}
		}
		if !shouldRemove {
			newLines = append(newLines, line)
		}
	}

	newContent := strings.Join(newLines, "\n")
	err = os.WriteFile(HostsFile, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("erro ao limpar arquivo hosts: %w", err)
	}

	fmt.Println("[GALILEU] DNS limpo com sucesso!")
	return nil
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)

	go func() {
		<-c
		fmt.Println("\n[GALILEU] Encerrando...")
		cleanupDNSRedirect()
		os.Exit(0)
	}()
}

func loadCertificates() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair("rootCA.pem", "rootCA-key.pem")
	if err != nil {
		return nil, fmt.Errorf("falha ao carregar certificados: %w", err)
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

	listener, err := tls.Listen("tcp", MITMListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("falha ao iniciar listener TLS: %w", err)
	}
	defer listener.Close()

	fmt.Printf("[GALILEU] MITM listener ativo em %s\n", MITMListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[GALILEU] Erro ao aceitar conexão: %v", err)
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
		log.Printf("[GALILEU] Erro ao ler do cliente: %v", err)
		return
	}

	payload := buf[:n]
	analyzer := NewAnalyzer()
	found, _ := analyzer.Analyze(payload)
	if found {
		fmt.Println("[GALILEU] Payload processado pelo analyzer.")
	}

	upstreamHost := extractHost(payload)
	if upstreamHost == "" {
		upstreamHost = "opencode.ai:443"
	}

	upstreamConn, err := tls.Dial("tcp", upstreamHost, &tls.Config{
		ServerName:         strings.Split(upstreamHost, ":")[0],
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("[GALILEU] Erro ao conectar no upstream %s: %v", upstreamHost, err)
		return
	}
	defer upstreamConn.Close()

	_, err = upstreamConn.Write(payload)
	if err != nil {
		log.Printf("[GALILEU] Erro ao enviar para upstream: %v", err)
		return
	}

	respBuf := make([]byte, 8192)
	m, err := upstreamConn.Read(respBuf)
	if err != nil {
		log.Printf("[GALILEU] Erro ao ler resposta: %v", err)
		return
	}

	_, err = clientConn.Write(respBuf[:m])
	if err != nil {
		log.Printf("[GALILEU] Erro ao retornar resposta: %v", err)
	}
}

func extractHost(payload []byte) string {
	content := string(payload)
	for _, line := range strings.Split(content, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]) + ":443"
			}
		}
	}
	return ""
}

func getTCPHeader(packet []byte) *TCPHeader {
	if len(packet) < 20 {
		return nil
	}

	ipHeader := (*IPv4Header)(unsafe.Pointer(&packet[0]))
	if ipHeader.VersionIhl>>4 != 4 {
		return nil
	}

	tcpHeaderLen := int((ipHeader.VersionIhl & 0x0F) * 4)
	if len(packet) < tcpHeaderLen+20 {
		return nil
	}

	return (*TCPHeader)(unsafe.Pointer(&packet[tcpHeaderLen]))
}

func hasRelevantPayload(packet []byte) bool {
	tcp := getTCPHeader(packet)
	if tcp == nil {
		return false
	}

	dataOffset := int(tcp.DataOffset >> 4)
	payloadStart := dataOffset * 4
	if len(packet) <= payloadStart {
		return false
	}

	payloadLen := len(packet) - payloadStart
	return payloadLen >= MinPacketSize
}

func containsRelevantDomain(packet []byte) bool {
	content := string(packet)
	for _, domain := range monitoringDomains {
		if strings.Contains(content, domain) {
			return true
		}
	}
	return false
}

func StartGuardian() {

	if _, err := os.Stat("rootCA.pem"); os.IsNotExist(err) {
		log.Println("[GALILEU] Aviso: certificados CA não encontrados.")
	}

	if err := setupDNSRedirect(); err != nil {
		log.Printf("[GALILEU] Erro ao configurar DNS: %v", err)
	}

	setupSignalHandler()

	go func() {
		if err := StartMITMListener(); err != nil {
			log.Printf("[GALILEU] MITM não iniciado: %v", err)
		}
	}()

	filter := "(outbound and tcp.DstPort == 443) or (inbound and tcp.SrcPort == 9001)"

	wd, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatal("Erro: Certifique-se de estar como ADMIN:", err)
	}
	defer wd.Close()

	analyzer := NewAnalyzer()

	fmt.Println("[GALILEU] Ativo. Monitorando e redirecionando chamadas HTTPS...")

	for {
		buf := make([]byte, 1600)
		addr := new(divert.Address)

		n, err := wd.Recv(buf, addr)
		if err != nil || n == 0 {
			continue
		}

		packetLen := n
		hasPayload := hasRelevantPayload(buf[:n])
		hasDomain := containsRelevantDomain(buf[:n])

		if hasPayload && hasDomain {
			fmt.Printf("[GALILEU] Pacote capturado: %d bytes, dominio relevante\n", packetLen)
			analyzer.Analyze(buf[:n])
		}

		_, _ = wd.Send(buf[:n], addr)
	}
}
