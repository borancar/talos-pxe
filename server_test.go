package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogInfo(t *testing.T) {
	s, cleanup := talosPxeServerForTest(t, true)
	defer cleanup()
	capture, cleanup := NewLogCapture()
	defer cleanup()
	msg := "This is stupid but coverage looks good so meh"
	s.logInfo(msg)
	capture.RequireInLog(t, msg)
}

func talosPxeServerForTest(t *testing.T, startTFTP bool) (*Server, func()) {
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

	if startTFTP {

		// TFTP server has to be started because if it is not started then calling Shutdown() is throwing panic
		// as the tftp is closing connection that does not exist
		tftpListener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.IP, s.TFTPPort))
		require.Nil(t, err)
		go func() {
			err = s.serveTFTP(tftpListener)
			require.Nil(t, err)
		}()
	}

	cleanup := func() {
		ipxeFileName = current
		tmpDir.Cleanup()
		s.Shutdown()
	}
	return s, cleanup
}
