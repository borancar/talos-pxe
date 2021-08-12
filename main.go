package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/digineo/go-dhclient"
	"github.com/google/gopacket/layers"
	"github.com/milosgajdos/tenus"
	web "github.com/poseidon/matchbox/matchbox/http"
	"github.com/poseidon/matchbox/matchbox/server"
	"github.com/poseidon/matchbox/matchbox/storage"
)

var log = logrus.New()

var dnsmasqConfTemplate = template.Must(template.New("dnsmasq config").Parse(`
port=0

log-dhcp

enable-tftp
tftp-root=/srv/tftp

# Legacy PXE
dhcp-match=set:bios,option:client-arch,0
dhcp-boot=tag:bios,undionly.kpxe,,{{ .Ip }}

# UEFI
dhcp-match=set:efi32,option:client-arch,6
dhcp-boot=tag:efi32,ipxe.efi
dhcp-match=set:efibc,option:client-arch,7
dhcp-boot=tag:efibc,ipxe.efi
dhcp-match=set:efi64,option:client-arch,9
dhcp-boot=tag:efi64,ipxe.efi

# iPXE - chainload to matchbox ipxe boot script
dhcp-userclass=set:ipxe,iPXE
dhcp-boot=tag:ipxe,http://{{ .Ip }}:8080/boot.ipxe

pxe-prompt="Booting", 1

{{- if .ProxyServer }}
dhcp-range={{ .Proxy.DhcpIp }},proxy,{{ .Proxy.Netmask }}
{{- else }}
dhcp-range={{ .Standalone.IpMin }},{{ .Standalone.IpMax }},12h
{{- end }}
`))

var ipxeMenuTemplate = template.Must(template.New("iPXE Menu").Parse(`#!ipxe
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
chain http://{{ .Ip }}:8080/ipxe?uuid=${uuid}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=init

:controlplane
chain http://{{ .Ip }}:8080/ipxe?uuid=${uuid}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=controlplane

:worker
chain http://{{ .Ip }}:8080/ipxe?uuid=${uuid}&mac=${mac:hexhyp}&domain=${domain}&hostname=${hostname}&serial=${serial}&type=worker

:reboot
reboot

:shell
shell

:exit
exit
`))

func logStream(name string, s io.ReadCloser, stream *os.File) error {
	buf := make([]byte, 4096)

	nb, err := s.Read(buf)
	for nb != 0 {
		stream.Write(buf)
		nb, err = s.Read(buf)
	}

	if err != io.EOF {
		return err
	}

	return nil
}

func followProcess(cmd *exec.Cmd) error {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	//go logStream(cmd.Args[0], stdout, os.Stdout)
	go io.Copy(os.Stdout, stdout)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	//go logStream(cmd.Args[0], stderr, os.Stderr)
	go io.Copy(os.Stderr, stderr)
	if err := cmd.Run(); err != nil {
		return err
	}
	stdin.Close()

	return nil
}

type ProxyServer struct {
	DhcpIp string
	Netmask string
}

type StandaloneServer struct {
	IpMin, IpMax string
}

type PXEServer struct {
	Ip string
	ProxyServer bool
	Proxy *ProxyServer
	Standalone *StandaloneServer
}

func startDnsmasq(server PXEServer) error {
	f, err := os.Create("/etc/dnsmasq.conf")
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	if err := dnsmasqConfTemplate.Execute(w, server); err != nil {
		return err
	}
	w.Flush()

	cmd := exec.Command("/usr/sbin/dnsmasq", "-d")
	if err := followProcess(cmd); err != nil {
		return err
	}

	return nil
}

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

func ipxeWrapperMenuHandler(primaryHandler http.Handler, pxeServer PXEServer) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "ipxe" && req.URL.Path != "/ipxe" {
			primaryHandler.ServeHTTP(w, req)
			return
		}

		rr := httptest.NewRecorder()
		primaryHandler.ServeHTTP(rr, req)

		if status := rr.Code; status == http.StatusOK {
			for key, values := range rr.HeaderMap {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			w.WriteHeader(rr.Code)

			w.Write(rr.Body.Bytes())
		} else {
			log.Info("Serving menu")

			if err := ipxeMenuTemplate.Execute(w, pxeServer); err != nil {
				log.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}

	return http.HandlerFunc(fn)
}

func startMatchbox(pxeServer PXEServer) error {
	store := storage.NewFileStore(&storage.Config{
		Root: "/srv",
	})

	server := server.NewServer(&server.Config{
		Store: store,
	})

	config := &web.Config{
		Core: server,
		Logger: log,
		AssetsPath: "/srv/assets",
	}

	httpServer := web.NewServer(config)
	go http.ListenAndServe("0.0.0.0:8080", ipxeWrapperMenuHandler(httpServer.HTTPHandler(), pxeServer))

	return nil
}

func main() {
	eth0, err := tenus.NewLinkFrom("eth0")
	if err != nil {
		log.Panic(err)
	}

	if err := eth0.SetLinkUp(); err != nil {
		log.Panic(err)
	}

	log.Infof("Brought %s up\n", eth0.NetInterface().Name)

	validInterfaces, err := getValidInterfaces()
	if err != nil {
		log.Panic(err)
	}

	log.Infof("Valid interfaces are:\n")
	for _, iface := range validInterfaces {
		log.Infof(" - %s\n", iface.Name)
	}

	lease, err := runDhclient(context.Background(), &validInterfaces[0])

	server := PXEServer{}

	if lease != nil {
		log.Infof("Obtained address %s\n", lease.FixedAddress)

		net := &net.IPNet{
			IP: lease.FixedAddress,
			Mask: lease.Netmask,
		}

		if err := eth0.SetLinkIp(net.IP, net); err != nil {
			log.Panic(err)
		}

		server.ProxyServer = true
		server.Ip = lease.FixedAddress.String()
		server.Proxy = &ProxyServer{
			DhcpIp: lease.ServerID.String(),
			Netmask: fmt.Sprintf("%d.%d.%d.%d", lease.Netmask[0], lease.Netmask[1], lease.Netmask[2], lease.Netmask[3]),
		}
	} else {
		ip := "192.168.122.1"
		ipMin := "192.168.122.2"
		ipMax := "192.168.122.100"

		fmt.Printf("Setting manual address %s\n", ip)

		netIp, netNet, err := net.ParseCIDR(ip + "/24")
		if err != nil {
			log.Panic(err)
		}

		if err := eth0.SetLinkIp(netIp, netNet); err != nil {
			log.Panic(err)
		}

		server.ProxyServer = false;
		server.Ip = ip
		server.Standalone = &StandaloneServer {
			IpMin: ipMin,
			IpMax: ipMax,
		}
	}

	log.Infof("Starting matchbox...\n")

	if err := startMatchbox(server); err != nil {
		log.Panic(err)
	}

	log.Infof("Starting dnsmasq...\n")

	if err := startDnsmasq(server); err != nil {
		log.Panic(err)
	}
}
