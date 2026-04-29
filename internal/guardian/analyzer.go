package guardian

import (
	"regexp"
	"sync"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return &bufferWrapper{data: make([]byte, 0, 4096)}
	},
}

type bufferWrapper struct {
	data []byte
}

type Analyzer struct {
	compiledPatterns []*regexp.Regexp
	redaction        []byte
}

func NewAnalyzer() *Analyzer {
	patterns := []string{
		`(sk-[a-zA-Z0-9]{20,})`,
		`(sk-proj-[a-zA-Z0-9.-]{20,})`,
		`(sk-ant-[a-zA-Z0-9.-]{20,})`,
		`(AIzaSy[a-zA-Z0-9_-]{35})`,
		`(ghp_[a-zA-Z0-9]{36})`,
		`(xox[baprs]-[a-zA-Z0-9]{10,})`,
		`(AKIA[0-9A-Z]{16})`,
		`(bearer\s+[a-zA-Z0-9.-]{20,})`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &Analyzer{
		compiledPatterns: compiled,
		redaction:        []byte("[REDACTED_BY_GALILEU]"),
	}
}

func (a *Analyzer) Analyze(data []byte) (bool, []byte) {
	modified := false
	result := data

	for _, re := range a.compiledPatterns {
		if re.Match(result) {
			modified = true
			result = re.ReplaceAll(result, a.redaction)
		}
	}

	return modified, result
}
