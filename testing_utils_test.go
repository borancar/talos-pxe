package main

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// Not a real test file just file with utils code for other test files

type LogCapture struct {
	buf bytes.Buffer
}

func NewLogCapture() (*LogCapture, func()) {
	c := LogCapture{}
	current := logrus.StandardLogger().Out
	log.SetOutput(&c.buf)
	return &c, func() { log.SetOutput(current) }
}

func (c *LogCapture) RequireInLog(t *testing.T, phrase string) {
	if strings.Contains(c.buf.String(), phrase) {
		return
	}
	t.Fatalf("Logs do not contain [%s], in\n%s", phrase, c.buf.String())
}

type TempDir struct {
	*testing.T
	path string
}

func NewTempDir(t *testing.T, prefix string) *TempDir {
	tmpDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Error creating tmp dir %v", err)
	}
	td := TempDir{
		T:    t,
		path: tmpDir,
	}
	return &td
}

func (td *TempDir) Path() string {
	return td.path
}

func (td *TempDir) Cleanup() {
	err := os.RemoveAll(td.path)
	if err != nil {
		td.Errorf("Error deleting temp dir %v", err)
	}
}

func (td *TempDir) Write(fname, content string) string {
	filePath := path.Join(td.path, fname)
	err := os.WriteFile(filePath, bytes.NewBufferString(content).Bytes(), 0755)
	if err != nil {
		td.Fatalf("Error creating done file %v", err)
	}
	return filePath
}

func (td *TempDir) ReadFile(fname string) string {
	file, err := os.Open(filepath.Join(td.path, fname))
	if err != nil {
		td.Fatalf("Error opening memory file %v", err)
		return ""
	}
	b := make([]byte, 0)
	_, err = file.Read(b)
	if err != nil {
		td.Fatalf("Error reading memory file %v", err)
	}
	return string(b)
}
