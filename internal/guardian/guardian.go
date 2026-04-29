package guardian

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/elazarl/goproxy"
)

var bodyPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 32768)
	},
}

func StartGuardian() {
	proxy := goproxy.NewProxyHttpServer()

	caCert, err := os.ReadFile("rootCA.pem")
	if err != nil {
		log.Fatalf("Erro ao ler rootCA.pem: %v", err)
	}
	caKey, err := os.ReadFile("rootCA-key.pem")
	if err != nil {
		log.Fatalf("Erro ao ler rootCA-key.pem: %v", err)
	}

	setCA(caCert, caKey)

	if err := InitAuditLogger(); err != nil {
		fmt.Printf("[GALILEU] Aviso: Não foi possível iniciar auditoria: %v\n", err)
	}
	defer CloseAuditLogger()

	analyzer := NewAnalyzer()

	targetHosts := []string{
		"opencode.ai",
		"api.openai.com",
		"api.anthropic.com",
		"generativelanguage.googleapis.com",
		"api.cohere.ai",
		"api.mistral.ai",
	}

	processRequest := func(r *http.Request) (*http.Request, *http.Response) {
		if r.Body == nil {
			return r, nil
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			return r, nil
		}

		found, cleanBody := analyzer.Analyze(body)

		go func() {
			if found {
				LogRequest(r.Host, r.URL.Path, r.Method, true, "sensitive_data")
			} else {
				LogRequest(r.Host, r.URL.Path, r.Method, false, "")
			}
		}()

		if found {
			fmt.Printf("[GALILEU] Interceptado em %s: Dados sensíveis removidos.\n", r.Host)
			r.Body = io.NopCloser(bytes.NewReader(cleanBody))
			r.ContentLength = int64(len(cleanBody))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(cleanBody)))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		return r, nil
	}

	for _, host := range targetHosts {
		h := host
		proxy.OnRequest(goproxy.DstHostIs(h)).DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				fmt.Printf("[DEBUG] Requisição capturada para: %s\n", r.Host)
				return processRequest(r)
			},
		)
	}

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			fmt.Printf("[DEBUG] Requisição recebida: %s %s\n", r.Method, r.Host)
			return r, nil
		},
	)

	fmt.Println("[GALILEU] Proxy MITM Ativo na porta 9000...")
	log.Fatal(http.ListenAndServe(":9000", proxy))
}

// Função auxiliar para configurar o certificado no goproxy
func setCA(caCert, caKey []byte) {
	block, _ := pem.Decode(caCert)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Erro: certificado CA inválido")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Erro ao parsear certificado CA: %v", err)
	}

	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		log.Fatalf("Erro ao carregar par de chaves CA: %v", err)
	}
	ca.Leaf = cert

	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
}
