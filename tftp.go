// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"

	"go.universe.tf/netboot/tftp"
)

func (s *Server) serveTFTP(l net.PacketConn) error {
	ts := tftp.Server{
		Handler:     s.handleTFTP,
		TransferLog: s.logTFTPTransfer,
	}
	err := ts.Serve(l)
	if err != nil {
		return fmt.Errorf("TFTP server shut down: %s", err)
	}
	return nil
}

func extractInfo(path string) (net.HardwareAddr, string, string, error) {
	pathElements := strings.Split(path, "/")
	if len(pathElements) != 3 {
		return nil, "", "", errors.New("not found")
	}

	mac, err := net.ParseMAC(pathElements[0])
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid MAC address %q", pathElements[0])
	}

	classId := pathElements[1]
	classInfo := pathElements[2]

	return mac, classId, classInfo, nil
}

func (s *Server) logTFTPTransfer(clientAddr net.Addr, path string, err error) {
	_, _, _, pathErr := extractInfo(path)
	if pathErr != nil {
		log.Errorf("unable to extract mac from request:%v", pathErr)
		return
	}
	if err != nil {
		log.Errorf("Send of %q to %s failed: %s", path, clientAddr, err)
	} else {
		log.Infof("Sent %q to %s", path, clientAddr)
	}
}

func (s *Server) handleTFTP(path string, clientAddr net.Addr) (io.ReadCloser, int64, error) {
	_, classId, classInfo, err := extractInfo(path)
	if err != nil {
		return nil, 0, fmt.Errorf("unknown path %q", path)
	}

	bs, err := s.Ipxe(classId, classInfo)
	if err != nil {
		return nil, 0, err
	}

	return ioutil.NopCloser(bytes.NewBuffer(bs)), int64(len(bs)), nil
}
