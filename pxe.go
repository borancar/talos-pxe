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
	"fmt"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/net/ipv4"
)

// TODO: this may actually be the BINL protocol, a
// Microsoft-proprietary fork of PXE that is more universally
// supported in UEFI than PXE itself. Need to comb through the
// TianoCore EDK2 source code to figure out if what this is doing is
// actually BINL, and if so rename everything.

// TODO test it, to unit test it i need examples of binary representation of some pxe requests

func (s *Server) servePXE(conn net.PacketConn) error {
	buf := make([]byte, 1024)
	l := ipv4.NewPacketConn(conn)
	if err := l.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return fmt.Errorf("Couldn't get interface metadata on PXE port: %s", err)
	}

	for !s.closed {
		n, msg, addr, err := l.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("Receiving packet: %s", err)
		}

		log.Infof("Received proxyDHCP PXE request from %s", addr)

		m, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			log.Debugf("Packet from %s is not a DHCP packet: %s", addr, err)
			continue
		}

		if m.OpCode != dhcpv4.OpcodeBootRequest || !m.IsOptionRequested(dhcpv4.OptionBootfileName) {
			log.Debugf("Ignoring packet from %s (%s): %s", m.ClientHWAddr, addr, err)
			continue
		}

		resp, err := dhcpv4.NewReplyFromRequest(m,
			dhcpv4.WithOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck)),
			dhcpv4.WithOption(dhcpv4.OptBootFileName(fmt.Sprintf("%s/%s/%s", m.ClientHWAddr, m.ClassIdentifier(), m.UserClass()))),
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.IP)),
			dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClassIdentifier, []byte("PXEClient"))),
		)
		resp.ServerIPAddr = s.IP

		if m.Options[dhcpv4.OptionClientMachineIdentifier.Code()] != nil {
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, m.Options[dhcpv4.OptionClientMachineIdentifier.Code()]))
		}

		log.Debug(resp.Summary())
		if _, err := l.WriteTo(resp.ToBytes(), &ipv4.ControlMessage{
			IfIndex: msg.IfIndex,
		}, addr); err != nil {
			log.Errorf("Failed to send PXE response to %s (%s): %s", m.ClientHWAddr, addr, err)
		}
	}
	return nil
}
