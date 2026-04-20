package guardian

import (
	"strings"
)

type SensitiveInfo struct {
	Label   string
	Pattern string
}

type PayloadAnalyzer struct {
	Patterns []SensitiveInfo
}

func NewAnalyzer() *PayloadAnalyzer {
	return &PayloadAnalyzer{
		Patterns: []SensitiveInfo{
			{Label: "Gemini_Key", Pattern: "AIzaSy"},
			{Label: "OpenAI_Key", Pattern: "sk-"},
			{Label: "Claude_Key", Pattern: "sk-ant-"},
		},
	}
}

func (a *PayloadAnalyzer) Analyze(payload []byte) (bool, []byte) {
	content := string(payload)
	isSensitive := false
	modifiedContent := content

	for _, p := range a.Patterns {
		if strings.Contains(content, p.Pattern) {
			isSensitive = true
			modifiedContent = strings.ReplaceAll(modifiedContent, p.Pattern, "[REDACTED_"+p.Label+"]")
		}
	}
	return isSensitive, []byte(modifiedContent)
}