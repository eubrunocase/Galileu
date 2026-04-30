package main

import (
	"Galileu/internal/guardian"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
)

func getCertThumbprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("arquivo de certificado invalido")
	}

	hash := sha1.Sum(block.Bytes)
	return fmt.Sprintf("%X", hash), nil
}

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

func certExistsInStore(certPath string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	thumbprint, err := getCertThumbprint(certPath)
	if err != nil {
		return false
	}

	cmd := exec.Command("certutil", "-store", "Root")
	output, _ := cmd.CombinedOutput()
	outputStr := string(output)
	for i := 0; i <= len(outputStr)-len(thumbprint); i++ {
		if outputStr[i:i+len(thumbprint)] == thumbprint {
			return true
		}
	}
	return false
}

func InstallCA(certPath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("autoinstalacao disponivel apenas para Windows")
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("certificado nao encontrado: %s", certPath)
	}

	if certExistsInStore(certPath) {
		fmt.Println("[GALILEU] Certificado CA ja esta instalado no repositorio.")
		return nil
	}

	if !isAdmin() {
		return fmt.Errorf("privilegios de administrador necessarios para instalar o certificado")
	}

	cmd := exec.Command("certutil", "-addstore", "-f", "Root", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("falha ao instalar certificado: %v, output: %s", err, string(output))
	}

	fmt.Println("[GALILEU] Certificado Root CA instalado com sucesso.")
	return nil
}

func main() {
	fmt.Println(`
                                                                                                                                             
                       (     (    (                 
 (        (      )\ )  )\ ) )\ )              
 )\ )     )\    (()/( (()/((()/(  (       (   
(()/(  ((((_)(   /(_)) /(_))/(_)) )\      )\  
 /(_))_ )\ _ )\ (_))  (_)) (_))  ((_)  _ ((_) 
(_)) __|(_)_\(_)| |   |_ _|| |   | __|| | | | 
  | (_ | / _ \  | |__  | | | |__ | _| | |_| | 
   \___|/_/ \_\ |____||___||____||___| \___/  
                                                   
                       
    `)

	certPath := "./rootCA.pem"
	err := InstallCA(certPath)
	if err != nil {
		fmt.Printf("[ERRO] %v\n", err)
		fmt.Println("[DICA] Execute o Galileu como Administrador para instalar o certificado CA.")
		return
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go guardian.GracefulListen()

	fmt.Println("[GALILEU] Proxy ativo na porta 9000.")
	fmt.Println("[GALILEU]pressione Ctrl+C para encerrar e persistir o log de auditoria.")

	<-quit
	fmt.Println("\n[GALILEU] Encerrando...")
	guardian.CloseGuardian()
	guardian.CloseAuditLogger()
	fmt.Println("[GALILEU] Log de auditoria persistido com sucesso.")
}