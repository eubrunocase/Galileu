package main

import (
	"Galileu/internal/guardian"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

func getCertThumbprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("arquivo de certificado inválido")
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
		return fmt.Errorf("autoinstalação disponível apenas para Windows")
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("certificado não encontrado: %s", certPath)
	}

	if certExistsInStore(certPath) {
		fmt.Println("[GALILEU] Certificado CA já está instalado no repositório.")
		return nil
	}

	if !isAdmin() {
		return fmt.Errorf("privilégios de administrador necessários para instalar o certificado")
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
    #####     #      #        #####  #      ####### #     #
    #     #   # #    #         #    #      #       #     #
    #        #   #   #         #    #      #       #     #
    #  #### #     #  #         #    #      #####   #     #
    #     # #######  #         #    #      #       #     #
    #     # #     #  #         #    #      #       #     #
    #####  #     #  #######  #####  ###### #######  #####
    `)

	certPath := "./rootCA.pem"
	err := InstallCA(certPath)
	if err != nil {
		fmt.Printf("[ERRO] %v\n", err)
		fmt.Println("[DICA] Execute o Galileu como Administrador para instalar o certificado CA.")
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		guardian.StartGuardian()
	}()

	fmt.Println("[GALILEU] Proxy ativo na porta 9000.")
	fmt.Println("[GALILEU] Execute 'start-opencode.bat' em outro CMD (sem admin) para iniciar o OpenCode.")
	wg.Wait()
}
