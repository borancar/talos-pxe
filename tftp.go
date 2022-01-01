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
	"path/filepath"
	"strings"

	"github.com/pin/tftp"
)

var (
	ipxeFileName = "ipxe.efi"
)

type TFTPHook struct {
}

func (h *TFTPHook) OnSuccess(stats tftp.TransferStats) {
	log.Infof("Transferred %s to %s", stats.Filename, stats.RemoteAddr)
}

func (h *TFTPHook) OnFailure(stats tftp.TransferStats, err error) {
	log.Errorf("Failure transferring %s to %s: %s", stats.Filename, stats.RemoteAddr, err)
}

// readHandlerTFTP is called when client starts file download from server
func (s *Server) readHandlerTFTP(path string, rf io.ReaderFrom) error {
	_, classId, classInfo, err := extractInfo(path)
	if err != nil {
		return fmt.Errorf("unknown path %q", path)
	}

	bs, err := s.prepIpxeContent(classId, classInfo)
	if err != nil {
		return err
	}

	rf.(tftp.OutgoingTransfer).SetSize(int64(len(bs)))
	_, _ = rf.ReadFrom(bytes.NewBuffer(bs))

	return nil
}

// prepIpxeContent serves ipxe menu or the ipxe.efi file
func (s *Server) prepIpxeContent(classId, classInfo string) ([]byte, error) {

	if strings.Contains(classInfo, "iPXE") {
		var menuBuffer bytes.Buffer
		_ = ipxeMenuTemplate.Execute(&menuBuffer, s)
		return menuBuffer.Bytes(), nil
	}

	if classId == "PXEClient:Arch:00000:UNDI:002001" || classId == "PXEClient:Arch:00007:UNDI:003001" {
		data, err := ioutil.ReadFile(filepath.Join(s.ServerRoot, ipxeFileName))
		if err != nil {
			return nil, err
		}
		return data, nil
	}

	return nil, fmt.Errorf("Unknown class %s:%s", classId, classInfo)
}

func (s *Server) serveTFTP(l net.PacketConn) error {
	ts := tftp.NewServer(s.readHandlerTFTP, nil)
	ts.SetHook(&TFTPHook{})
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

func (s *Server) logInfo(msg string) {
	log.Info(msg)
}
