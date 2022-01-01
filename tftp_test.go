package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pin/tftp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	expectedInPxeMenu = `
:init
chain http://127.0.0.1:8080/ipxe?uuid=${uuid}&ip=${ip}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=init

:controlplane
chain http://127.0.0.1:8080/ipxe?uuid=${uuid}&ip=${ip}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=controlplane

:worker
chain http://127.0.0.1:8080/ipxe?uuid=${uuid}&ip=${ip}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=worker`
)

func TestTFTPHook(t *testing.T) {
	/*
		Simple test that TFTPHook does log correct message
	*/
	capture, cleanup := NewLogCapture()
	defer cleanup()

	tHook := &TFTPHook{}

	stats := tftp.TransferStats{
		Filename: "foo", RemoteAddr: net.IPv4(1, 2, 3, 4),
	}
	tHook.OnSuccess(stats)
	tHook.OnFailure(stats, errors.New("boom"))
	capture.RequireInLog(t, "Transferred foo to 1.2.3.4")
	capture.RequireInLog(t, "Failure transferring foo to 1.2.3.4: boom")
}

func TestServeTFTP(t *testing.T) {
	/**
	Test behaviour of the tftp server by running it and querying the tftp client
	*/
	s, cleanup := talosPxeServerForTest(t)
	defer cleanup()

	// Run the TFPT server
	go func() {
		tftpListener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.IP, s.TFTPPort))
		require.Nil(t, err)
		err = s.serveTFTP(tftpListener)
		require.Nil(t, err)
	}()

	c, err := tftp.NewClient("127.0.0.1:69")
	require.Nil(t, err)

	// When iPXE is in classInfo then we expect to get the pxe menu
	wt, err := c.Receive("98:01:a7:99:ac:6b/whatever/iPXE", "octet")
	require.Nil(t, err)

	var buff bytes.Buffer
	_, err = wt.WriteTo(&buff)
	require.Nil(t, err)
	require.Contains(t, buff.String(), expectedInPxeMenu)

	// When iPXE is not classInfo then we will expect to get the pxe file
	for _, option := range []string{
		"98:01:a7:99:ac:6b/PXEClient:Arch:00000:UNDI:002001/what",
		"98:01:a7:99:ac:6b/PXEClient:Arch:00007:UNDI:003001/what"} {
		wt, err := c.Receive(option, "octet")
		require.Nil(t, err)

		var buff bytes.Buffer
		_, err = wt.WriteTo(&buff)
		require.Nil(t, err)
		require.Equal(t, "my fake fakeIpxe", buff.String())
	}

	// Test error conditions, unknown class, wrong mack address and wrong path
	for _, option := range []string{
		"not a mac address/PXEClient:Arch:00000:UNDI:002001/what",
		"98:01:a7:99:ac:6b/unknown class/what",
		"98:01:a7:99:ac:6b/not enough of path elements"} {
		_, err := c.Receive(option, "octet")
		require.NotNil(t, err)

		fmt.Printf("Error %v", err)
	}
}

func TestLogInfo(t *testing.T) {
	s, cleanup := talosPxeServerForTest(t)
	defer cleanup()
	capture, cleanup := NewLogCapture()
	defer cleanup()
	msg := "This is stupid but coverage looks good so meh"
	s.logInfo(msg)
	capture.RequireInLog(t, msg)
}

func talosPxeServerForTest(t *testing.T) (*Server, func()) {
	tmpDir := NewTempDir(t, "talosPxeServerForTest")
	current := ipxeFileName
	ipxeFileName = "fakeIpxe"
	_ = tmpDir.Write(ipxeFileName, "my fake fakeIpxe")

	cleanup := func() {
		ipxeFileName = current
		tmpDir.Cleanup()
	}

	return &Server{
		IP:         net.IPv4(127, 0, 0, 1),
		ServerRoot: tmpDir.path,
		DHCPPort:   portDHCP,
		TFTPPort:   portTFTP,
		PXEPort:    portPXE,
		HTTPPort:   portHTTP,
		DNSPort:    portDNS,
	}, cleanup
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

type TempDir struct {
	*testing.T
	path string
}

func NewTempDir(t *testing.T, prefix string) *TempDir {
	tmpDir, err := ioutil.TempDir("", prefix)
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
	err := ioutil.WriteFile(filePath, bytes.NewBufferString(content).Bytes(), 0755)
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
