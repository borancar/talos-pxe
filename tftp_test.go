package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/pin/tftp"
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
	s, cleanup := talosPxeServerForTest(t, true)
	defer cleanup()

	require.NotNil(t, s)

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
