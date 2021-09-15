package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/digineo/go-dhclient"
	"github.com/google/gopacket/layers"
	"github.com/milosgajdos/tenus"
	web "github.com/poseidon/matchbox/matchbox/http"
	"github.com/poseidon/matchbox/matchbox/server"
	"github.com/poseidon/matchbox/matchbox/storage"
        "github.com/coredhcp/coredhcp/plugins/allocators"
        "github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

var log = logrus.New()

const (
	portDNS    = 53
	portDHCP   = 67
	portTFTP   = 69
	portHTTP   = 8080
	portPXE    = 4011
	forwardDns = "1.1.1.1:53"
)

// Architecture describes a kind of CPU architecture.
type Architecture int

// Architecture types that Pixiecore knows how to boot.
//
// These architectures are self-reported by the booting machine. The
// machine may support additional execution modes. For example, legacy
// PC BIOS reports itself as an ArchIA32, but may also support ArchX64
// execution.
const (
	// ArchIA32 is a 32-bit x86 machine. It _may_ also support X64
	// execution, but Pixiecore has no way of knowing.
	ArchIA32 Architecture = iota
	// ArchX64 is a 64-bit x86 machine (aka amd64 aka X64).
	ArchX64
)

func (a Architecture) String() string {
	switch a {
	case ArchIA32:
		return "IA32"
	case ArchX64:
		return "X64"
	default:
		return "Unknown architecture"
	}
}

// A Machine describes a machine that is attempting to boot.
type Machine struct {
	MAC  net.HardwareAddr
	Arch Architecture
}

// Firmware describes a kind of firmware attempting to boot.
//
// This should only be used for selecting the right bootloader within
// Pixiecore, kernel selection should key off the more generic
// Architecture.
type Firmware int

// The bootloaders that Pixiecore knows how to handle.
const (
	FirmwareX86PC         Firmware = iota // "Classic" x86 BIOS with PXE/UNDI support
	FirmwareEFI32                         // 32-bit x86 processor running EFI
	FirmwareEFI64                         // 64-bit x86 processor running EFI
	FirmwareEFIBC                         // 64-bit x86 processor running EFI
	FirmwareX86Ipxe                       // "Classic" x86 BIOS running iPXE (no UNDI support)
	FirmwarePixiecoreIpxe                 // Pixiecore's iPXE, which has replaced the underlying firmware
)

type DHCPRecord struct {
	IP net.IP
	expires time.Time
}

// A Server boots machines using a Booter.
type Server struct {
	ServerRoot string

	IP net.IP
	GWIP net.IP

	Net *net.IPNet

	ForwardDns []string

	Intf string

	Controlplane string

	ProxyDHCP bool

	DHCPLock sync.Mutex
	DHCPRecords map[string]*DHCPRecord
	DHCPAllocator allocators.Allocator

	DNSRWLock sync.RWMutex
	DNSRecordsv4 map[string][]net.IP
	DNSRecordsv6 map[string][]net.IP
	DNSRRecords map[string][]string

	// These ports can technically be set for testing, but the
	// protocols burned in firmware on the client side hardcode these,
	// so if you change them in production, nothing will work.
	DHCPPort int
	TFTPPort int
	PXEPort  int
	HTTPPort int
	DNSPort  int

	errs chan error
}

func (s *Server) Ipxe(classId, classInfo string) ([]byte, error) {
	var resultBuffer bytes.Buffer

	if classId == "PXEClient:Arch:00000:UNDI:002001" && classInfo == "[iPXE]" {
		ipxeMenuTemplate.Execute(&resultBuffer, s)
		return resultBuffer.Bytes(), nil
	}

	return nil, fmt.Errorf("Unknown class %s:%s", classId, classInfo)
}

// Serve listens for machines attempting to boot, and uses Booter to
// help them.
func (s *Server) Serve() error {
	if s.DHCPPort == 0 {
		s.DHCPPort = portDHCP
	}
	if s.TFTPPort == 0 {
		s.TFTPPort = portTFTP
	}
	if s.PXEPort == 0 {
		s.PXEPort = portPXE
	}
	if s.HTTPPort == 0 {
		s.HTTPPort = portHTTP
	}
	if s.DNSPort == 0 {
		s.DNSPort = portDNS
	}

	if len(s.ForwardDns) == 0 {
		s.ForwardDns = []string{forwardDns}
	}

	tftp, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.IP, s.TFTPPort))
	if err != nil {
		return err
	}
	pxe, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", s.IP, s.PXEPort))
	if err != nil {
		tftp.Close()
		return err
	}
	http, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.IP, s.HTTPPort))
	if err != nil {
		tftp.Close()
		pxe.Close()
		return err
	}
	dns, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.IP, s.DNSPort))
	if err != nil {
		http.Close()
		tftp.Close()
		pxe.Close()
		return err
	}

	// 6 buffer slots, one for each goroutine, plus one for
	// Shutdown(). We only ever pull the first error out, but shutdown
	// will likely generate some spurious errors from the other
	// goroutines, and we want them to be able to dump them without
	// blocking.
	s.errs = make(chan error, 6)

	log.Info("Starting servers")

	go func() { s.errs <- s.servePXE(pxe) }()
	go func() { s.errs <- s.serveTFTP(tftp) }()
	go func() { s.errs <- s.startMatchbox(http) }()
	go func() { s.errs <- s.startDhcp() }()
	go func() { s.errs <- s.serveDNS(dns) }()

	// Wait for either a fatal error, or Shutdown().
	err = <-s.errs
	dns.Close()
	http.Close()
	tftp.Close()
	pxe.Close()
	return err
}

func (s *Server) startMatchbox(l net.Listener) error {
	store := storage.NewFileStore(&storage.Config{
		Root: s.ServerRoot,
	})

	server := server.NewServer(&server.Config{
		Store: store,
	})

	config := &web.Config{
		Core: server,
		Logger: log,
		AssetsPath: filepath.Join(s.ServerRoot, "assets"),
	}

	httpServer := web.NewServer(config)
	if err := http.Serve(l, s.ipxeWrapperMenuHandler(httpServer.HTTPHandler())); err != nil {
		return fmt.Errorf("Matchbox server shut down: %s", err)
	}

	return nil
}

// Shutdown causes Serve() to exit, cleaning up behind itself.
func (s *Server) Shutdown() {
	select {
	case s.errs <- nil:
	default:
	}
}

var ipxeMenuTemplate = template.Must(template.New("iPXE Menu").Parse(`#!ipxe
isset ${proxydhcp/next-server} || goto start
set next-server ${proxydhcp/next-server}
set filename ${proxydhcp/filename}

:start
menu iPXE boot menu for Talos
item --gap                      Talos Nodes
item --key i init               Bootstrap Node
item --key c controlplane       Master Node
item --key w worker             Worker Node
item --gap                      Other
item --key s shell              iPXE Shell
item --key r reboot             Reboot
item --key e exit               Exit
choose --timeout 0 --default worker selected || goto cancel
set menu-timeout 0
goto ${selected}

:init
chain http://{{ .IP }}:8080/ipxe?uuid=${uuid}&ip=${ip}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=init

:controlplane
chain http://{{ .IP }}:8080/ipxe?uuid=${uuid}&ip=${ip}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=controlplane

:worker
chain http://{{ .IP }}:8080/ipxe?uuid=${uuid}&ip=${ip}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=worker

:reboot
reboot

:shell
shell

:exit
exit
`))

func getPrivateAddress() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr).IP

	return localAddr, nil
}

func getInterface(addr net.IP) (*net.Interface, net.IPMask, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range ifaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}

		for _, ifaceAddr := range ifaceAddrs {
			switch v := ifaceAddr.(type) {
				case *net.IPAddr:
					if v.IP.Equal(addr) {
						return &iface, v.IP.DefaultMask(), nil
					}

				case *net.IPNet:
					if v.IP.Equal(addr) {
						return &iface, v.Mask, nil
					}
			}
		}
	}

	return nil, nil, fmt.Errorf("Could not find interface for address")
}

func getValidInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var validInterfaces []net.Interface

	for _, iface := range ifaces {
		if iface.Flags & net.FlagLoopback != 0 {
			continue
		}

		if iface.Flags & net.FlagUp == 0 {
			continue
		}

		validInterfaces = append(validInterfaces, iface)
	}

	if len(validInterfaces) == 0 {
		return nil, fmt.Errorf("Could not find any non-loopback interfaces that are active")
	}

	return validInterfaces, nil
}

func runDhclient(ctx context.Context, iface *net.Interface) (*dhclient.Lease, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	leaseCh := make(chan *dhclient.Lease)
	client := dhclient.Client{
		Iface: iface,
		OnBound: func(lease *dhclient.Lease) {
			leaseCh <- lease
		},
	}

	for _, param := range dhclient.DefaultParamsRequestList {
		client.AddParamRequest(layers.DHCPOpt(param))
	}

	hostname, _ := os.Hostname()
	client.AddOption(layers.DHCPOptHostname, []byte(hostname))

	client.Start()
	defer client.Stop()

	select {
	case lease := <-leaseCh:
		return lease, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("Could not get DHCP")
	}
}

func (s *Server) ipxeWrapperMenuHandler(primaryHandler http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "ipxe" && req.URL.Path != "/ipxe" {
			primaryHandler.ServeHTTP(w, req)
			return
		}

		rr := httptest.NewRecorder()
		primaryHandler.ServeHTTP(rr, req)

		if status := rr.Code; status == http.StatusOK {
			req.ParseForm()
			machineType := req.Form.Get("type")
			remoteIp := net.ParseIP(req.Form.Get("ip"))
			log.Infof("Selecting %s for %s", machineType, remoteIp)

			if machineType == "init" || machineType == "controlplane" {
				s.registerDNSEntry(s.Controlplane, remoteIp)
			}

			for key, values := range rr.HeaderMap {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			w.WriteHeader(rr.Code)

			w.Write(rr.Body.Bytes())
		} else {
			log.Info("Serving menu")

			if err := ipxeMenuTemplate.Execute(w, s); err != nil {
				log.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}

	return http.HandlerFunc(fn)
}

func getAvailableRange(netIp net.IPNet, netServer net.IP) (net.IP, net.IP) {
    mask := binary.BigEndian.Uint32(netIp.Mask)
    start := binary.BigEndian.Uint32(netServer.To4())

    first := start + 1
    last := ((start & mask) | (mask ^ 0xffffffff)) - 1

    firstIp := make(net.IP, 4)
    lastIp := make(net.IP, 4)

    binary.BigEndian.PutUint32(firstIp, first)
    binary.BigEndian.PutUint32(lastIp, last)

    return firstIp, lastIp
}

func main() {
	serverRootFlag := flag.String("root", ".", "Server root, where to serve the files from")
	ifNameFlag := flag.String("if", "eth0", "Interface to use")
	ipAddrFlag := flag.String("addr", "192.168.123.1/24", "Address to listen on")
	gwAddrFlag := flag.String("gw", "", "Override gateway address")
	dnsAddrFlag := flag.String("dns", "", "Override DNS address")
	controlplaneFlag := flag.String("controlplane", "controlplane.talos.", "Controlplane address")
	flag.Parse()

	validInterfaces, err := getValidInterfaces()
	if err != nil {
		log.Panic(err)
	}

	log.Infof("Valid interfaces are:\n")
	for _, iface := range validInterfaces {
		log.Infof(" - %s\n", iface.Name)
	}

	log.Infof("Select interface %s", *ifNameFlag)

	eth, err := tenus.NewLinkFrom(*ifNameFlag)
	if err != nil {
		log.Panic(err)
	}

	if err := eth.SetLinkUp(); err != nil {
		log.Panic(err)
	}

	log.Infof("Brought %s up\n", eth.NetInterface().Name)

	lease, err := runDhclient(context.Background(), eth.NetInterface())

	server := &Server{
		ServerRoot: *serverRootFlag,
		Intf: eth.NetInterface().Name,
		Controlplane: *controlplaneFlag,
		DHCPRecords: make(map[string]*DHCPRecord),
		DNSRecordsv4: make(map[string][]net.IP),
		DNSRecordsv6: make(map[string][]net.IP),
		DNSRRecords: make(map[string][]string),
	}

	if lease != nil {
		log.Infof("Obtained address %s\n", lease.FixedAddress)

		net := &net.IPNet{
			IP: lease.FixedAddress,
			Mask: lease.Netmask,
		}

		if err := eth.SetLinkIp(net.IP, net); err != nil && err != syscall.EEXIST {
			log.Panic(err)
		}

		for _, routerIp := range lease.Router {
			log.Infof("Adding default GW %s\n", routerIp)
			if err := eth.SetLinkDefaultGw(&routerIp); err != nil && err != syscall.EEXIST {
				log.Panic(err)
			}
		}

		for _, dns := range lease.DNS {
			log.Infof("Adding DNS %s\n", dns)
			server.ForwardDns = append(server.ForwardDns, fmt.Sprintf("%s:53", dns))
		}

		server.IP = lease.FixedAddress
		server.ProxyDHCP = true
	} else {
		netIp, netNet, err := net.ParseCIDR(*ipAddrFlag)
		firstIp, lastIp := getAvailableRange(*netNet, netIp)
		log.Infof("Setting manual address %s, leasing out subnet %s (available range %s - %s)\n", netIp, netNet, firstIp, lastIp)

		server.IP = netIp
		server.Net = netNet
		server.ProxyDHCP = false

		server.DHCPAllocator, err = bitmap.NewIPv4Allocator(firstIp, lastIp)
		if err != nil {
			log.Panic(err)
		}

		if err != nil {
			log.Panic(err)
		}

		if err := eth.SetLinkIp(netIp, netNet); err != nil && err != syscall.EEXIST {
			log.Panic(err)
		}
	}

	if *gwAddrFlag != "" {
	    log.Infof("Overriding gateway address with %s", *gwAddrFlag)
	    server.GWIP = net.ParseIP(*gwAddrFlag)
	} else {
	    server.GWIP = server.IP
	}

	if *dnsAddrFlag != "" {
	    log.Infof("Overriding DNS addressw with %s", *dnsAddrFlag)
	    server.ForwardDns = []string{*dnsAddrFlag}
	}

	if err := server.Serve(); err != nil {
		log.Panic(err)
	}
}
