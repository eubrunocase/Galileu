package guardian

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/elazarl/goproxy"
)

var bodyPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 32*1024)
	},
}

type LogRequest struct {
	Host        string
	Path        string
	Method      string
	Redacted    bool
	PatternType string
}

type LogWorkerPool struct {
	logChan chan LogRequest
	workers int
	wg      sync.WaitGroup
}

func NewLogWorkerPool(numWorkers int, channelBuffer int) *LogWorkerPool {
	return &LogWorkerPool{
		logChan: make(chan LogRequest, channelBuffer),
		workers: numWorkers,
	}
}

func (p *LogWorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for logReq := range p.logChan {
				LogAudit(logReq.Host, logReq.Path, logReq.Method, logReq.Redacted, logReq.PatternType)
			}
		}()
	}
}

func (p *LogWorkerPool) Submit(logReq LogRequest) {
	select {
	case p.logChan <- logReq:
	default:
		fmt.Printf("[GALILEU] Aviso: fila de logging cheia, descartando log\n")
	}
}

func (p *LogWorkerPool) Shutdown() {
	close(p.logChan)
	p.wg.Wait()
}

var (
	logWorkerPool *LogWorkerPool
	shutdownChan  chan struct{}
)

func GracefulListen() {
	proxy := goproxy.NewProxyHttpServer()

	caCert, err := os.ReadFile("rootCA.pem")
	if err != nil {
		fmt.Printf("[GALILEU] Erro ao ler rootCA.pem: %v\n", err)
		return
	}
	caKey, err := os.ReadFile("rootCA-key.pem")
	if err != nil {
		fmt.Printf("[GALILEU] Erro ao ler rootCA-key.pem: %v\n", err)
		return
	}

	setCA(caCert, caKey)

	if err := InitAuditLogger(); err != nil {
		fmt.Printf("[GALILEU] Aviso: Nao foi possivel iniciar auditoria: %v\n", err)
	}
	defer CloseAuditLogger()

	logWorkerPool = NewLogWorkerPool(4, 100)
	logWorkerPool.Start()
	defer logWorkerPool.Shutdown()

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

		bufRaw := bodyPool.Get().([]byte)
		buf := bufRaw[:0]
		defer bodyPool.Put(buf)

		body := bytes.NewBuffer(buf)
		_, err := io.Copy(body, r.Body)
		if err != nil {
			return r, nil
		}
		bodyBytes := body.Bytes()

		found, cleanBody := analyzer.Analyze(bodyBytes)

		host, path, method := r.Host, r.URL.Path, r.Method
		patternType := ""
		if found {
			patternType = "sensitive_data"
		}

		logWorkerPool.Submit(LogRequest{
			Host:        host,
			Path:        path,
			Method:      method,
			Redacted:    found,
			PatternType: patternType,
		})

		if found {
			fmt.Printf("[GALILEU] Interceptado em %s: Dados sensiveis removidos.\n", r.Host)
			r.Body = io.NopCloser(bytes.NewReader(cleanBody))
			r.ContentLength = int64(len(cleanBody))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(cleanBody)))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		return r, nil
	}

	for _, host := range targetHosts {
		h := host
		proxy.OnRequest(goproxy.DstHostIs(h)).DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				fmt.Printf("[DEBUG] Requisicao capturada para: %s\n", r.Host)
				return processRequest(r)
			},
		)
	}

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			fmt.Printf("[DEBUG] Requisicao recebida: %s %s\n", r.Method, r.Host)
			return r, nil
		},
	)

	fmt.Println("[GALILEU] Proxy MITM Ativo na porta 9000...")
	shutdownChan = make(chan struct{})

	srv := &http.Server{Addr: ":9000", Handler: proxy}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[GALILEU] Erro no servidor: %v\n", err)
		}
	}()

	<-shutdownChan
}

func GracefulStop() {
	if shutdownChan != nil {
		close(shutdownChan)
	}
}

func CloseGuardian() {
	GracefulStop()
}

func setCA(caCert, caKey []byte) {
	block, _ := pem.Decode(caCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}

	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return
	}
	ca.Leaf = cert

	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
}

func StartGuardian() {
	proxy := goproxy.NewProxyHttpServer()

	caCert, err := os.ReadFile("rootCA.pem")
	if err != nil {
		fmt.Printf("[GALILEU] Erro ao ler rootCA.pem: %v\n", err)
		return
	}
	caKey, err := os.ReadFile("rootCA-key.pem")
	if err != nil {
		fmt.Printf("[GALILEU] Erro ao ler rootCA-key.pem: %v\n", err)
		return
	}

	setCA(caCert, caKey)

	if err := InitAuditLogger(); err != nil {
		fmt.Printf("[GALILEU] Aviso: Nao foi possivel iniciar auditoria: %v\n", err)
	}
	defer CloseAuditLogger()

	logWorkerPool = NewLogWorkerPool(4, 100)
	logWorkerPool.Start()
	defer logWorkerPool.Shutdown()

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

		bufRaw := bodyPool.Get().([]byte)
		buf := bufRaw[:0]
		defer bodyPool.Put(buf)

		body := bytes.NewBuffer(buf)
		_, err := io.Copy(body, r.Body)
		if err != nil {
			return r, nil
		}
		bodyBytes := body.Bytes()

		found, cleanBody := analyzer.Analyze(bodyBytes)

		host, path, method := r.Host, r.URL.Path, r.Method
		patternType := ""
		if found {
			patternType = "sensitive_data"
		}

		logWorkerPool.Submit(LogRequest{
			Host:        host,
			Path:        path,
			Method:      method,
			Redacted:    found,
			PatternType: patternType,
		})

		if found {
			fmt.Printf("[GALILEU] Interceptado em %s: Dados sensiveis removidos.\n", r.Host)
			r.Body = io.NopCloser(bytes.NewReader(cleanBody))
			r.ContentLength = int64(len(cleanBody))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(cleanBody)))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		return r, nil
	}

	for _, host := range targetHosts {
		h := host
		proxy.OnRequest(goproxy.DstHostIs(h)).DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				fmt.Printf("[DEBUG] Requisicao capturada para: %s\n", r.Host)
				return processRequest(r)
			},
		)
	}

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			fmt.Printf("[DEBUG] Requisicao recebida: %s %s\n", r.Method, r.Host)
			return r, nil
		},
	)

	fmt.Println("[GALILEU] Proxy MITM Ativo na porta 9000...")
	http.ListenAndServe(":9000", proxy)
}
