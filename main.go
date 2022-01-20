package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"text/template"
	"time"

	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
	"github.com/digineo/go-dhclient"
	"github.com/milosgajdos/tenus"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var log = logrus.New()

const (
	portDNS             = 53
	portDHCP            = 67
	portTFTP            = 69
	portHTTP            = 8080
	portPXE             = 4011
	forwardDns          = "1.1.1.1:53"
	defaultControlplane = "controlplane.talos."
)

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

func main() {
	serverRootFlag := flag.String("root", ".", "Server root, where to serve the files from")
	ifNameFlag := flag.String("if", "eth0", "Interface to use")
	ipAddrFlag := flag.String("addr", "192.168.123.1/24", "Cidr to use in case if there is not DHCP server present in the network")
	gwAddrFlag := flag.String("gw", "", "Override gateway address")
	dnsAddrFlag := flag.String("dns", "", "Override DNS address")
	controlplaneFlag := flag.String("controlplane", defaultControlplane, "Controlplane address")
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

	var server *Server

	lease, _ := getDHCPlease(eth.NetInterface(), time.Second*10)
	if lease != nil {
		log.Infof("Obtained address %s\n", lease.FixedAddress)

		ipNet := &net.IPNet{
			IP:   lease.FixedAddress,
			Mask: lease.Netmask,
		}

		if err := eth.SetLinkIp(ipNet.IP, ipNet); err != nil && err != syscall.EEXIST {
			log.Panic(err)
		}

		for _, routerIp := range lease.Router {
			log.Infof("Adding default GW %s\n", routerIp)
			if err := eth.SetLinkDefaultGw(&routerIp); err != nil && err != syscall.EEXIST {
				log.Panic(err)
			}
		}

		server, err = NewServer(lease.FixedAddress, *serverRootFlag, eth.NetInterface().Name, *controlplaneFlag)
		if err != nil {
			log.Panic(err)
		}

		if len(lease.DNS) > 0 {
			var dnsForwards = make([]string, len(lease.DNS))
			for i, oneDnsServer := range lease.DNS {
				log.Infof("Adding DNS %s\n", oneDnsServer)
				dnsForwards[i] = fmt.Sprintf("%s:53", oneDnsServer)
			}
			if err := server.ConfigureDnsServer(dnsForwards, portDNS); err != nil {
				log.Panicf("Error configuring DNS: %v", err)
			}
		}

		server.Net = ipNet
		server.ProxyDHCP = true
	} else {
		// If lese is nil we assume that there is no DHCP server present in the network, so we are going to server it
		netIp, ipNet, err := net.ParseCIDR(*ipAddrFlag)
		if err != nil {
			log.Panicf("Error parsing cidr %s, %v", *ipAddrFlag, err)
		}
		firstIp, lastIp := getAvailableRange(*ipNet, netIp)
		log.Infof("Setting manual address %s, leasing out subnet %s (available range %s - %s)\n", netIp, ipNet, firstIp, lastIp)

		server, err = NewServer(netIp, *serverRootFlag, eth.NetInterface().Name, *controlplaneFlag)
		if err != nil {
			log.Panicf("Error creating server: %v", err)
		}

		server.Net = ipNet
		server.ProxyDHCP = false

		server.DHCPAllocator, err = bitmap.NewIPv4Allocator(firstIp, lastIp)
		if err != nil {
			log.Panic(err)
		}

		if err := eth.SetLinkIp(netIp, ipNet); err != nil && err != syscall.EEXIST {
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
		log.Panicf("Error from server.Serve: %v", err)
	}
}

func getDHCPlease(iface *net.Interface, timeout time.Duration) (*dhclient.Lease, error) {
	leaseCh := make(chan *dhclient.Lease)
	hostname, _ := os.Hostname()
	client := dhclient.Client{
		Iface:    iface,
		Hostname: hostname,
		OnBound: func(lease *dhclient.Lease) {
			leaseCh <- lease
		},
	}

	// Start will configure all DefaultParamsRequestList and the host name
	client.Start()
	defer client.Stop()

	select {
	case lease := <-leaseCh:
		return lease, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("Could not get DHCP due to timeout of %v ", timeout)
	}
}

func getValidInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var validInterfaces []net.Interface

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		validInterfaces = append(validInterfaces, iface)
	}

	if len(validInterfaces) == 0 {
		return nil, fmt.Errorf("Could not find any non-loopback interfaces that are active")
	}

	return validInterfaces, nil
}
