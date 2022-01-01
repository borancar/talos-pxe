package main

import (
	"bytes"
	"errors"
	"github.com/pin/tftp"
	"net"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestTFTPHook(t *testing.T) {
	capture, cleanup := NewLogCapture()
	defer cleanup()

	tHook := &TFTPHook{}

	stats := tftp.TransferStats{
		Filename: "foo", RemoteAddr: net.IPv4(1, 2, 3, 4),
	}
	tHook.OnSuccess(stats)
	tHook.OnFailure(stats, errors.New("boom"))
	capture.RequireInLog(t, "foo")

}

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
