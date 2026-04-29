package guardian

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp   string `json:"timestamp"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Method      string `json:"method"`
	Redacted    bool   `json:"redacted"`
	PatternType string `json:"pattern_type,omitempty"`
}

type AuditLogger struct {
	mu       sync.Mutex
	file     *os.File
	entries  []AuditEntry
	count    int
	filename string
}

var auditLogger *AuditLogger

func NewAuditLogger(filename string) (*AuditLogger, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &AuditLogger{
		file:     f,
		filename: filename,
		entries:  make([]AuditEntry, 0, 100),
		count:    0,
	}, nil
}

func (a *AuditLogger) Log(entry AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries = append(a.entries, entry)
	a.count++

	if a.count >= 10 {
		a.flush()
	}
}

func (a *AuditLogger) flush() {
	if len(a.entries) == 0 {
		return
	}

	for _, e := range a.entries {
		data, _ := json.Marshal(e)
		a.file.Write(append(data, '\n'))
	}

	a.entries = a.entries[:0]
	a.count = 0
}

func (a *AuditLogger) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flush()
	a.file.Close()
}

func LogRequest(host, path, method string, redacted bool, patternType string) {
	if auditLogger == nil {
		return
	}
	entry := AuditEntry{
		Timestamp:   time.Now().Format(time.RFC3339),
		Host:        host,
		Path:        path,
		Method:      method,
		Redacted:    redacted,
		PatternType: patternType,
	}
	auditLogger.Log(entry)
}

func InitAuditLogger() error {
	logger, err := NewAuditLogger("galileu_audit.log")
	if err != nil {
		return err
	}
	auditLogger = logger
	fmt.Println("[GALILEU] Logging de auditoria ativo: galileu_audit.log")
	return nil
}

func CloseAuditLogger() {
	if auditLogger != nil {
		auditLogger.Close()
	}
}
