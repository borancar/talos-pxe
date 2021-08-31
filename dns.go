package main

import (
	"context"
	"fmt"
	"net"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const (
	DNSTTL = 60
)

type ServiceLookupPlugin struct{
	Next plugin.Handler
	Fall fall.F
	Server *Server
	Zones []string
}

func (s ServiceLookupPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Printf("DNS request: %v", r)
	state := request.Request{W: w, Req: r}
	qname := state.Name()

	answers := []dns.RR{}

	zone := plugin.Zones(s.Zones).Matches(qname)
	if zone == "" {
		if state.QType() != dns.TypePTR {
			return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
		}
	}

	switch state.QType() {
	case dns.TypePTR:
		names := s.GetREntry(dnsutil.ExtractAddressFromReverse(qname))
		if len(names) == 0 {
			return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
		}
		answers = ptr(qname, DNSTTL, names)
	case dns.TypeA:
		ips := s.GetHostV4(qname)
		answers = a(qname, DNSTTL, ips)
	case dns.TypeAAAA:
		ips := s.GetHostV6(qname)
		answers = aaaa(qname, DNSTTL, ips)
	}

	// Only on NXDOMAIN we will fallthrough.
	if len(answers) == 0 && !s.otherRecordsExist(qname) {
		if s.Fall.Through(qname) {
			return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
		}

		return dns.RcodeServerFailure, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers

	w.WriteMsg(m)

	return dns.RcodeSuccess, nil
}

func (s ServiceLookupPlugin) otherRecordsExist(qname string) bool {
	if len(s.GetHostV4(qname)) > 0 {
		return true
	}
	if len(s.GetHostV6(qname)) > 0 {
		return true
	}
	return false
}

func (s ServiceLookupPlugin) GetREntry(ip string) []string {
	s.Server.DNSRWLock.RLock()
	defer s.Server.DNSRWLock.RUnlock()
	return s.Server.DNSRRecords[ip]
}

func (s ServiceLookupPlugin) GetHostV4(name string) []net.IP {
	s.Server.DNSRWLock.RLock()
	defer s.Server.DNSRWLock.RUnlock()
	return s.Server.DNSRecordsv4[name]
}

func (s ServiceLookupPlugin) GetHostV6(name string) []net.IP {
	s.Server.DNSRWLock.RLock()
	defer s.Server.DNSRWLock.RUnlock()
	return s.Server.DNSRecordsv6[name]
}

func (s ServiceLookupPlugin) Name() string {
	return "servicelookupplugin"
}

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
		r.A = ip
		answers[i] = r
	}
	return answers
}

// aaaa takes a slice of net.IPs and returns a slice of AAAA RRs.
func aaaa(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
		r.AAAA = ip
		answers[i] = r
	}
	return answers
}

// ptr takes a slice of host names and filters out the ones that aren't in Origins, if specified, and returns a slice of PTR RRs.
func ptr(zone string, ttl uint32, names []string) []dns.RR {
	answers := make([]dns.RR, len(names))
	for i, n := range names {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.Ptr = dns.Fqdn(n)
		answers[i] = r
	}
	return answers
}

func (s *Server) serveDNS(l net.PacketConn) error {
	zone := "talos."

	zoneConfig := &dnsserver.Config{
		Zone: zone,
		Transport: "dns",
		ListenHosts: []string{""},
		Port: fmt.Sprintf("%d", s.DNSPort),
		Debug: true,
	}

	zoneConfig.AddPlugin(func(next plugin.Handler) plugin.Handler {
		serviceLookup := ServiceLookupPlugin{
			Server: s,
			Zones: []string{zone},
		}
		serviceLookup.Next = next

		return serviceLookup
	})

	proxyConfig := &dnsserver.Config{
		Zone: ".",
		Transport: "dns",
		ListenHosts: []string{""},
		Port: fmt.Sprintf("%d", s.DNSPort),
		Debug: true,
	}

	proxyConfig.AddPlugin(func(next plugin.Handler) plugin.Handler {
		forwardProxy := forward.New()
		for _, forwardDns := range s.ForwardDns {
			forwardProxy.SetProxy(forward.NewProxy(forwardDns, "dns"))
		}
		forwardProxy.Next = next

		return forwardProxy
	})

	dnsServer, err := dnsserver.NewServer(s.IP.String(), []*dnsserver.Config{zoneConfig, proxyConfig})
	if err != nil {
		return err
	}
	err = dnsServer.ServePacket(l)
	if err != nil {
		return err
	}

	return nil
}
