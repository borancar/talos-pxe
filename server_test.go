package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

type myTestIpxeWrapperMenuHandler struct {
	paths []string
	t     *testing.T
}

func (h *myTestIpxeWrapperMenuHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.paths = append(h.paths, req.URL.Path)

	// for requests for ipxe path we expect that writer is ResponseRecorder
	if req.URL.Path == "ipxe" || req.URL.Path == "/ipxe" {
		_, ok := w.(*httptest.ResponseRecorder)
		require.True(h.t, ok)
		if req.URL.Path == "ipxe" {
			// return 404 so we can test that menu is served from ipxeWrapperMenuHandler
			w.WriteHeader(404)
			return
		}
	}
}

func Test_ipxeWrapperMenuHandler(t *testing.T) {
	s, cleanup := talosPxeServerForTest(t, false)
	defer cleanup()
	primaryHandler := myTestIpxeWrapperMenuHandler{t: t}
	handler := s.ipxeWrapperMenuHandler(&primaryHandler)

	t.Run("check requests to not ipxe are handled", func(t *testing.T) {
		writer := myWriter{}
		req := http.Request{URL: &url.URL{Path: "foo"}}
		handler.ServeHTTP(&writer, &req)
		require.Len(t, primaryHandler.paths, 1)
		require.Equal(t, "foo", primaryHandler.paths[0])
	})

	t.Run("check that recorder is used for ipxe requests and on error we return the menu", func(t *testing.T) {
		capture, cleanupLogger := NewLogCapture()
		defer cleanupLogger()
		writer := myWriter{}
		req := http.Request{URL: &url.URL{Path: "ipxe"}}
		handler.ServeHTTP(&writer, &req)
		capture.RequireInLog(t, "Serving menu")
		require.Contains(t, string(writer.Data), expectedInPxeMenu)
	})

	t.Run("Error parsing form", func(t *testing.T) {
		capture, cleanupLogger := NewLogCapture()
		defer cleanupLogger()
		writer := myWriter{}
		// /ipxe does not cause error in my handler
		req := http.Request{URL: &url.URL{Path: "/ipxe", RawQuery: "%^"}}
		handler.ServeHTTP(&writer, &req)
		capture.RequireInLog(t, "Error ParseForm: invalid URL escape")
	})

	t.Run("Call to init is registered with dns server", func(t *testing.T) {
		capture, cleanupLogger := NewLogCapture()
		defer cleanupLogger()
		writer := myWriter{}
		// /ipxe does not cause error in my handler
		req := http.Request{URL: &url.URL{Path: "/ipxe", RawQuery: "type=init&ip=1.2.3.4"}}
		handler.ServeHTTP(&writer, &req)
		capture.RequireInLog(t, "Selecting init for 1.2.3.4")
		require.Equal(t, "1.2.3.4", s.DNSRecordsv4[s.Controlplane][0].String())
	})

	t.Run("Call to controlplane is registered with dns server", func(t *testing.T) {
		capture, cleanupLogger := NewLogCapture()
		defer cleanupLogger()
		writer := myWriter{}
		// /ipxe does not cause error in my handler
		req := http.Request{URL: &url.URL{Path: "/ipxe", RawQuery: "type=controlplane&ip=1.2.3.5"}}
		handler.ServeHTTP(&writer, &req)
		capture.RequireInLog(t, "Selecting controlplane for 1.2.3.5")
		require.Equal(t, "1.2.3.5", s.DNSRecordsv4[s.Controlplane][1].String())
	})

	t.Run("Call to worker is NOT registered with dns server", func(t *testing.T) {
		capture, cleanupLogger := NewLogCapture()
		defer cleanupLogger()
		writer := myWriter{}
		// /ipxe does not cause error in my handler
		req := http.Request{URL: &url.URL{Path: "/ipxe", RawQuery: "type=worker&ip=1.2.3.7"}}
		handler.ServeHTTP(&writer, &req)
		capture.RequireInLog(t, "Selecting worker for 1.2.3.7")
		require.Len(t, s.DNSRecordsv4[s.Controlplane], 2)
	})
}

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

// we need a fake writer because one of the tested behaviours is about httptest.ResponseRecorder
// so we can not use it
type myWriter struct {
	Code int
	Data []byte
}

func (m *myWriter) Header() http.Header {
	return http.Header{}
}

func (m *myWriter) Write(bytes []byte) (int, error) {
	m.Data = append(m.Data, bytes...)
	return len(bytes), nil
}

func (m *myWriter) WriteHeader(statusCode int) {
	m.Code = statusCode
}
