package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	s, cleanup := talosPxeServerForTest(t)
	defer cleanup()

	var err error

	go func() {
		err = s.Serve()
		require.Nil(t, err)
	}()

	time.Sleep(5 * time.Second)

	require.Nil(t, err)
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

	s, err := NewServer(net.IPv4(127, 0, 0, 1), tmpDir.path, "lo", defaultControlplane)
	require.Nil(t, err)

	s.DHCPPort = portDHCP
	s.TFTPPort = portTFTP
	s.PXEPort = portPXE
	s.HTTPPort = portHTTP
	s.DNSPort = portDNS

	// TFTP server has to be started because if it is not started then calling Shutdown() is throwing panic
	// as the tftp is closing connection that does not exist
	tftpListener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.IP, s.TFTPPort))
	require.Nil(t, err)
	go func() {
		err = s.serveTFTP(tftpListener)
		require.Nil(t, err)
	}()

	cleanup := func() {
		ipxeFileName = current
		tmpDir.Cleanup()
		s.Shutdown()
	}
	return s, cleanup
}
