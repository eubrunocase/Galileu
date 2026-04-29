import os

# Conteúdo do README.md para o projeto Galileu
readme_content = """# Projeto Galileu 🌌

O **Galileu** é uma ferramenta de segurança e governança de dados voltada para o monitoramento e sanitização de informações enviadas a provedores de Inteligência Artificial (LLMs). 

Nesta versão, o projeto adota uma arquitetura de **Proxy Reverso MITM (Man-in-the-Middle)**, garantindo que nenhum dado sensível ou segredo industrial saia do ambiente local sem antes passar por uma rigorosa camada de inspeção e redação.

## 🎯 Objetivos do Projeto

1.  **Proteção de Dados Sensíveis:** Identificar e mascarar automaticamente chaves de API, segredos de ambiente (`.env`), PII (Informações Pessoais Identificáveis) e outros dados sensíveis em prompts de IA.
2.  **Monitoramento de Contexto:** Inspecionar não apenas o prompt do usuário, mas também o contexto de arquivos locais que ferramentas como o **OpenCode** ou **Copilot** podem anexar silenciosamente às requisições.
3.  **Transparência Total:** Operar de forma transparente para o desenvolvedor, exigindo configuração mínima e sem causar impacto perceptível na experiência de uso.
4.  **Governança de IA:** Gerar logs e relatórios de auditoria sobre quais dados estão sendo compartilhados com provedores externos.

## 🏗️ Arquitetura do Sistema

O Galileu funciona como uma camada intermediária inteligente entre a aplicação cliente (IDE, CLI, TUI) e o servidor da LLM.

* **Camada de Proxy MITM:** Utilizando a biblioteca `elazarl/goproxy`, o sistema estabelece um túnel seguro onde o tráfego HTTPS é descriptografado localmente utilizando um certificado Root CA próprio.
* **Inspeção Seletiva:** Através de filtros de Host, o sistema decide quais pacotes devem ser inspecionados (ex: `opencode.ai`) e quais devem apenas passar (bypass), otimizando o uso de recursos.
* **Analisador Heurístico:** Um motor em Go que processa os buffers JSON em busca de padrões pré-definidos (Regex, assinaturas de bytes).



## ⚡ Performance Elevada e Paralelismo

A performance é o pilar central do Galileu. Para garantir que a inspeção não adicione latência à resposta da IA, utilizamos as capacidades nativas da linguagem Go:

* **Go Routines:** Cada requisição capturada é processada em sua própria unidade leve de execução (Goroutine). Isso permite que múltiplas chamadas simultâneas sejam analisadas em paralelo sem bloquear o fluxo de rede.
* **Processamento Não-Bloqueante:** O tráfego que não corresponde aos alvos de IA (ex: telemetria do VS Code) é encaminhado instantaneamente através de funções de bypass otimizadas.
* **Gerenciamento de Memória (Zero-Copy):** O uso de buffers circulares e reaproveitamento de memória (`sync.Pool`) minimiza a pressão sobre o Garbage Collector, essencial para processar JSONs extensos típicos de contextos de código.

## 🚀 Como Funciona

1.  **Inicialização:** O Galileu inicia um servidor proxy na porta `9000`.
2.  **Certificação:** O sistema carrega os arquivos `rootCA.pem` e `rootCA-key.pem` para assinar certificados dinâmicos, permitindo a leitura do tráfego HTTPS.
3.  **Configuração do Cliente:** A ferramenta de IA (ex: OpenCode) é configurada para usar `http://127.0.0.1:9000` como seu proxy HTTPS.
4.  **Interceptação:**
    * O usuário envia um prompt.
    * O Galileu captura a requisição, descriptografa e envia o corpo para o `Analyzer`.
    * Se chaves de API ou dados sensíveis forem encontrados, o Galileu substitui o texto por `[REDACTED_BY_GALILEU]`.
    * A requisição "limpa" é criptografada novamente e enviada ao provedor original.

## 🛠️ Tecnologias Utilizadas

* **Linguagem:** Go (Golang) - Pela sua eficiência nativa em concorrência.
* **Proxy Engine:** `github.com/elazarl/goproxy`.
* **Segurança:** TLS/SSL Bumping com certificados X.509.
* **Análise:** Regex e Buffer Analysis de alta performance.

---
**Nota de Segurança:** O Projeto Galileu deve ser executado com privilégios de administrador para permitir a instalação do certificado CA no repositório de confiança do sistema operacional.
"""

# Salva o arquivo .md
with open("README_GALILEU.md", "w", encoding="utf-8") as f:
    f.write(readme_content)