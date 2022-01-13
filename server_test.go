package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getInterface(t *testing.T) {
	privAddr, err := getPrivateAddress()
	require.Nil(t, err)
	require.NotEqualf(t, "", privAddr, "Private address should not be empty")
	log.Infof("Private address is %s", privAddr)

	interf, netIpMas, err := getInterface(privAddr)
	require.Nil(t, err)
	require.NotNil(t, interf)
	require.NotNil(t, netIpMas)
	log.Infof("Interface: %v, netMask: %v", interf, netIpMas)

	interf, netIpMas, err = getInterface(net.IP{})
	require.NotNil(t, err)
	require.Nil(t, interf)
	require.Nil(t, netIpMas)
}

func TestLogInfo(t *testing.T) {
	s, cleanup := talosPxeServerForTest(t, false)
	defer cleanup()
	capture, cleanupLogger := NewLogCapture()
	defer cleanupLogger()
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

	if startTFTP {
		// TFTP server has to be started because if it is not started then calling Shutdown() is throwing panic
		// as the tftp is closing connection that does not exist
		tftpListener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.IP, s.TFTPPort))
		require.Nil(t, err)
		go func() {
			err := s.serveTFTP(tftpListener)
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
