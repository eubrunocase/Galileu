# Galileu - Relatório de Projeto

## Visão Geral do Projeto

O Galileu é uma aplicação de segurança para monitoramento e interceptação de tráfego de IA no Windows, utilizando WinDivert para capturar pacotes TCP e um MITM (Man-in-the-Middle) para descriptografar e analisar payloads HTTPS.

---

## Fases do Projeto

### Fase 1: Captura de Pacotes (WINDIVERT)
- **Objetivo**: Capturar pacotes HTTPS na porta 443
- **Status**: ✓ FUNCIONAL
- **Implementação**: Filtro BPF `(outbound and tcp.DstPort == 443)`
- **Resultado**: Pacotes são capturados e logados corretamente

### Fase 2: Análise de Payload (ANALYZER)
- **Objetivo**: Detectar domínios relevantes e dados sensíveis
- **Status**: ✓ FUNCIONAL
- **Implementação**:search em texto claro no payload TCP
- **Detectado**: opencode.ai, api.anthropic.com, api.openai.com, etc.

### Fase 3: Configuração Automática de DNS
- **Objetivo**: Configurar redirecionamento DNS automaticamente
- **Status**: ✓ FUNCIONAL
- **Implementação**: Modificar arquivo C:\Windows\System32\drivers\etc\hosts
- **Resultado**: DNS redireciona domínios para IP configurado

### Fase 4: MITM Proxy
- **Objetivo**: Receber tráfego redirecionado, descriptografar e analisar
- **Status**: ✗ INCOMPLETO
- **Implementação**: TLS listener na porta 9001
- **Problema**: Tráfego não chega ao MITM

---

## Desafios e Dificuldades

### 1. WinDivert Não Captura Loopback
- **Descrição**: O WinDivert não captura tráfego entre 127.0.0.1 → 127.0.0.1
- **Impacto**: Não é possível usar DNS com 127.0.0.1
- **Tentativas**:Usar IP real da máquina, DNS spoofing, portproxy

### 2. NETSH Portproxy Não Funciona
- **Descrição**: O portproxy não redireciona tráfego como esperado
- **Impacto**: Abordagem mais confiável não funcionou
- **Causa**:Possível limitação no Windows ou necessidade de regras adicionais

### 3. Tráfego HTTPS Está Criptografado
- **Descrição**: O payload capturado está em TLS, não legível
- **Impacto**: Não é possível ler o conteúdo sem descriptografia
- **Solução Necessária**: MITM funcional com descriptografia

### 4. Arquitetura de Rede do Windows
- **Descrição**:IP de gateway (10.88.112.1) não pode ser usado para binding
- **Impacto**: MITM não consegue ouvir no IP real
- **Tentativa**:Usar 0.0.0.0:9001

---

## Estado Atual

| Componente | Status |
|------------|--------|
| WinDivert | ✓ Capturando |
| Analyzer | ✓ Detectando domínios |
| DNS Config | ✓ Configurando |
| MITM Proxy | ✗ Não recebe tráfego |
| Redirecionamento | ✗ Não funciona |

---

## Próximos Passos Sugeridos

### Opção A: Usar Proxy Explícito
- Modificar o OpenCode para usar proxy HTTP_PROXY
- **Prós**: Funciona se app suportar
- **Contras**: Requer configuração adicional

### Opção B: Firewall com Regra de Redirecionamento
- Criar regra de firewall via netsh ou PowerShell
- **Prós**: Funciona no nível de rede
- **Contras**:Requer permissões elevadas

### Opção C: TUN/TAP Adapter
- Usar um driver de rede virtual (OpenVPN/TAP)
- **Prós**: Captura todo tráfego
- **Contras**: Requer driver adicional

### Opção D: Simplificar para Monitoramento
- Manter apenas modo de leitura
- **Prós**: Já funciona, não quebra rede
- **Contras**: Não intercepta/direciona tráfego

---

## Conclusão

O projeto conseguiu implementar a captura de pacotes e detecção de domínios de IA. O redirecionamento do tráfego para o MITM proxy enfrenta limitações do Windows e do WinDivert com tráfego loopback. A opção mais viável no momento seria continuar com o monitoramento somente leitura (Opção D) ou explorar alternativas de driver de rede virtual (Opção C).

---

**Data do Relatório**: 23 de Abril de 2026
**Versão**: 0.1.0