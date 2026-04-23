package guardian

import (
	"fmt"
	"strings"
)

type SensitiveInfo struct {
	Label   string
	Pattern string
}

type PayloadAnalyzer struct {
	Patterns     []SensitiveInfo
	ZenPaths     []string
	ProviderSNIs []string
}

func NewAnalyzer() *PayloadAnalyzer {
	return &PayloadAnalyzer{
		Patterns: []SensitiveInfo{
			{Label: "Gemini_Key", Pattern: "AIzaSy"},
			{Label: "OpenAI_Key", Pattern: "sk-"},
			{Label: "Claude_Key", Pattern: "sk-ant-"},
		},
		ZenPaths: []string{
			"/zen/v1/chat/completions",
			"/zen/v1/messages",
			"/zen/v1/models",
		},
		ProviderSNIs: []string{
			"api.anthropic.com",
			"api.openai.com",
			"generativelanguage.googleapis.com",
			"api.cohere.ai",
			"opencode.ai",
			"api.cerebras.ai",
			"api.mistral.ai",
			"ai.platform.x.ai",
		},
	}
}

func (a *PayloadAnalyzer) extractSNI(payload []byte) string {
	content := string(payload)
	for _, sni := range a.ProviderSNIs {
		if strings.Contains(content, sni) {
			return sni
		}
	}
	return ""
}

func (a *PayloadAnalyzer) Analyze(payload []byte) (bool, []byte) {
	content := string(payload)
	isSensitive := false
	modifiedContent := content

	sni := a.extractSNI(payload)
	if sni != "" {
		fmt.Printf("[GALILEU] Dominio detectado: %s\n", sni)
	}

	for _, path := range a.ZenPaths {
		if strings.Contains(content, path) {
			isSensitive = true
			fmt.Printf("[GALILEU] Interceptado: Chamada Zen - %s\n", path)
			break
		}
	}

	for _, p := range a.Patterns {
		if strings.Contains(content, p.Pattern) {
			isSensitive = true
			modifiedContent = strings.ReplaceAll(modifiedContent, p.Pattern, "[REDACTED_"+p.Label+"]")
		}
	}

	return isSensitive, []byte(modifiedContent)
}
