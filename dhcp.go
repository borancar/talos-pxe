// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/iana"
)

func (s *Server) handlerDHCP4() server4.Handler {
	leaseTime := 5 * time.Minute

	return func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
		log.Debugf("DHCPv4: got %s", m.Summary())

		if m.OpCode != dhcpv4.OpcodeBootRequest {
			log.Infof("Not a boot request")
			return
		}

		resp, err := dhcpv4.NewReplyFromRequest(m,
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.IP)),
		)
		if err != nil {
			log.Error(err)
			return
		}

		efi := false
		ipxe := false

		for _, a := range m.ClientArch() {
			switch {
			case a == iana.EFI_ITANIUM:
				fallthrough
			case a >= iana.EFI_IA32 && a <= iana.EFI_ARM64:
				fallthrough
			case a >= iana.EFI_X86_HTTP && a <= iana.EFI_ARM64_HTTP:
				fallthrough
			case a >= iana.EFI_RISCV32 && a <= iana.EFI_RISCV128_HTTP:
				fallthrough
			case a >= iana.EFI_MIPS32 && a <= iana.EFI_SUNWAY64:
				efi = true
			}
		}

		for _, u := range m.UserClass() {
			switch {
			case u == "iPXE":
				ipxe = true
			}
		}

		if !s.ProxyDHCP {
			s.DHCPLock.Lock()
			defer s.DHCPLock.Unlock()

			record, ok := s.DHCPRecords[m.ClientHWAddr.String()]
			if !ok {
				newIp, err := s.DHCPAllocator.Allocate(net.IPNet{})
				if err != nil {
					log.Error(err)
					return
				}

				record = &DHCPRecord{
					IP:      newIp.IP,
					expires: time.Now().Add(leaseTime),
				}
				s.DHCPRecords[m.ClientHWAddr.String()] = record

			} else {
				if record.expires.Before(time.Now().Add(leaseTime)) {
					record.expires = time.Now().Add(leaseTime).Round(time.Second)
				}
			}

			resp, err = dhcpv4.NewReplyFromRequest(m,
				dhcpv4.WithNetmask(s.Net.Mask),
				dhcpv4.WithYourIP(record.IP),
				dhcpv4.WithGatewayIP(s.GWIP),
				dhcpv4.WithOption(dhcpv4.OptRouter(s.GWIP)),
				dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(leaseTime)),
				dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.IP)),
			)
			if err != nil {
				log.Error(err)
				return
			}
		} else {
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClassIdentifier, []byte("PXEClient")))

			if m.Options[dhcpv4.OptionClientMachineIdentifier.Code()] != nil {
				resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, m.Options[dhcpv4.OptionClientMachineIdentifier.Code()]))
			}

			// Some EFI firmwares refuse to boot if PXE Boot Server Discovery Control is set, so
			// only set it if not on EFI
			if !efi {
				pxe := []byte{
					// PXE Boot Server Discovery Control - bypass, just boot from filename.
					6, 1, 8, byte(dhcpv4.OptionEnd),
				}

				resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, pxe))
			}
		}

		resp.Options.Update(dhcpv4.OptDNS(s.IP))
		resp.ServerIPAddr = s.IP

		if m.IsOptionRequested(dhcpv4.OptionBootfileName) {
			log.Infof("received PXE boot request from %s", m.ClientHWAddr)

			log.Infof("sending PXE response to %s", m.ClientHWAddr)

			resp.UpdateOption(dhcpv4.OptTFTPServerName(s.IP.String()))

			if ipxe {
				// In proxyDHCP, iPXE ignores TFTPServerName option if DHCP sent it, so we have to use tftp://
				resp.UpdateOption(dhcpv4.OptBootFileName(fmt.Sprintf("tftp://%s/%s/%s/%s", s.IP, m.ClientHWAddr, m.ClassIdentifier(), m.UserClass())))
			} else {
				// other clients don't understand tftp://, but they will accept TFTPServerName, even in proxyDHCP
				resp.UpdateOption(dhcpv4.OptBootFileName(fmt.Sprintf("%s/%s/%s", m.ClientHWAddr, m.ClassIdentifier(), m.UserClass())))
			}
		}

		//resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionInterfaceMTU, dhcpv4.Uint16(match.MTU).ToBytes()))

		switch mt := m.MessageType(); mt { //nolint:exhaustive
		case dhcpv4.MessageTypeDiscover:
			resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
		case dhcpv4.MessageTypeRequest:
			resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
		default:
			log.Errorf("unhandled message type: %v", mt)

			return
		}

		log.Debug(resp.Summary())
		_, err = conn.WriteTo(resp.ToBytes(), peer)
		if err != nil {
			log.Printf("failure sending response: %s", err)
		}
	}
}

type DHCPLogger struct {
}

func (l DHCPLogger) PrintMessage(prefix string, message *dhcpv4.DHCPv4) {
	log.Infof("%s: %v", prefix, message)
}

func (l DHCPLogger) Printf(format string, v ...interface{}) {
	log.Infof(format, v...)
}

func (s *Server) startDhcp() error {
	logger := DHCPLogger{}

	server, err := server4.NewServer(
		s.Intf,
		nil,
		s.handlerDHCP4(),
		server4.WithLogger(logger),
	)

	if err != nil {
		return err
	}
	s.serverDHCP = server
	return server.Serve()
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
