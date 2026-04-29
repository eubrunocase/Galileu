# Galileu - Proxy de Segurança e Governança para LLMs

O **Galileu** é uma ferramenta de segurança e governança de dados voltada para o monitoramento e sanitização de informações enviadas a provedores de Inteligência Artificial (LLMs). O projeto adota uma arquitetura de **Proxy Reverso MITM (Man-in-the-the-Middle)**.

## Arquitetura do Sistema

O Galileu funciona como uma camada intermediária inteligente entre a aplicação cliente (IDE, CLI, TUI) e o servidor da LLM.

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Cliente   │───▶  │  Galileu    │───▶  │   LLM       │
│  (OpenCode)│◀───  │  Proxy MITM │◀───  │  Provider   │
└─────────────┘      └─────────────┘      └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │  Analyzer   │
                   │ (Sanitização)│
                   └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │   Audit     │
                   │    Log      │
                   └─────────────┘
```

## Instalação e Configuração

### Pré-requisitos

- **Sistema Operacional:** Windows
- **Privilégios:** Administrador (para instalar o certificado CA)
- **Go:** Versão 1.23 ou superior (para compilação)

### Compilação

```bash
go build -o galileu.exe ./cmd/sentinel
```

### Estrutura de Arquivos

```
Galileu/
├── galileu.exe          # Executável principal
├── rootCA.pem           # Certificado CA público
├── rootCA-key.pem       # Chave privada do CA (NÃO commitar)
├── start-opencode.bat   # Script para iniciar OpenCode com proxy
└── galileu_audit.log   # Log de auditoria (gerado automaticamente)
```

## Como Usar

### Passo 1: Executar o Galileu (como Administrador)

Abra o terminal como Administrador e execute:

```bash
galileu.exe
```

O programa irá:
1. Verificar/instalar o certificado CA no repositório "Root" do Windows
2. Iniciar o proxy na porta 9000
3. Ativar o logging de auditoria

**Importante:** O certificado CA deve estar instalado para que o proxy MITM funcione corretamente com HTTPS.

### Passo 2: Configurar o OpenCode

Em um novo terminal **sem privilégios de administrador**:

Execute o script de configuração:
```bash
start-opencode.bat
```

Ou configure manualmente:
```cmd
set HTTP_PROXY=http://127.0.0.1:9000
set HTTPS_PROXY=http://127.0.0.1:9000
opencode
```

### Passo 3: Usar o OpenCode normalmente

A partir de agora, todas as requisições do OpenCode para os provedores de IA passarão pelo proxy Galileu, que:
- Detecta e remove dados sensíveis
- Registra as requisições para auditoria

## Hosts Monitorados

O Galileu intercepta requisições para os seguintes provedores:

| Provedor | Host |
|----------|------|
| OpenCode | opencode.ai |
| OpenAI | api.openai.com |
| Anthropic | api.anthropic.com |
| Google AI | generativelanguage.googleapis.com |
| Cohere | api.cohere.ai |
| Mistral | api.mistral.ai |

## Detecção de Dados Sensíveis

O Analyzer detecta os seguintes padrões:

| Tipo | Padrão | Exemplo |
|------|--------|---------|
| OpenAI API Key | `sk-...` | `sk-1234567890abcdef...` |
| OpenAI Project Key | `sk-proj-...` | `sk-proj-abc123...` |
| Anthropic API Key | `sk-ant-...` | `sk-ant-abc123...` |
| Google API Key | `AIzaSy...` | `AIzaSyABC123...` |
| GitHub Token | `ghp_...` | `ghp_abcdef123456...` |
| Slack/Discord | `xox[baprs]-...` | `xoxb-123456...` |
| AWS Access Key | `AKIA...` | `AKIAIOSFODNN7...` |

Os dados sensíveis são substituídos por `[REDACTED_BY_GALILEU]`.

## Logs de Auditoria

O arquivo `galileu_audit.log` contém um registro JSON de cada requisição:

```json
{"timestamp":"2026-04-29T10:00:00Z","host":"opencode.ai","path":"/v1/chat/completions","method":"POST","redacted":true,"pattern_type":"sensitive_data"}
{"timestamp":"2026-04-29T10:05:00Z","host":"api.openai.com","path":"/v1/chat/completions","method":"POST","redacted":false,"pattern_type":""}
```

## Performance

O Galileu foi otimizado para performance:

- **Goroutines:** Cada requisição é processada em sua própria goroutine
- **Buffer Pooling:** Reutilização de memória com `sync.Pool`
- **Regex Pré-compilado:** Padrões de detecção compilados na inicialização
- **Processamento Assíncrono:** Logging não bloqueante

## Solução de Problemas

### "Certificado não encontrado"

Execute o Galileu como Administrador para permitir a instalação do certificado CA.

### OpenCode não conecta ao proxy

Verifique se as variáveis de ambiente estão configuradas corretamente:
```cmd
echo %HTTP_PROXY%
```

O resultado deve ser: `http://127.0.0.1:9000`

### Erros de certificado no navegador/cliente

O certificado CA do Galileu deve estar instalado no repositório "Root" do Windows. Você pode verificar em:
> Painel de Controle > Opções da Internet > Conteúdo > Certificados > Autoridades Certificadoras Raiz Confiáveis

## Arquitetura do Código

```
cmd/sentinel/main.go      # Ponto de entrada, instalação de CA
internal/guardian/
  ├── guardian.go         # Configuração do proxy MITM
  ├── analyzer.go        # Detecção e sanitização de dados
  └── audit.go           # Sistema de logging de auditoria
```

## Segurança

- O certificado CA (`rootCA-key.pem`) deve ser mantido em segurança
- Não commite arquivos `.pem` no repositório (já estão no `.gitignore`)
- O proxy só intercepta os hosts definidos em `targetHosts`

## Licença

Este projeto é para fins educacionais e de segurança interna. 
Todos os direitos são reservados ao desenvolvedor Bruno Dantas de Oliveira Cazé / https://github.com/eubrunocase/Galileu