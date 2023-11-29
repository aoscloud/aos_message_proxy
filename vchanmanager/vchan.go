// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2023 Renesas Electronics Corporation.
// Copyright (C) 2023 EPAM Systems, Inc.
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

//go:build !test

package vchanmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"time"
	"unsafe"

	"github.com/aoscloud/aos_common/aoserrors"
)

/*
#cgo LDFLAGS: -lxenvchan

#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <libxenvchan.h>

#include "include/vchanapi.h"

struct libxenvchan *server_init(int domain, char *xs_path) {
  struct libxenvchan *ctrl = libxenvchan_server_init(NULL, domain, xs_path, 0, 0);
  if (ctrl == NULL) {
    return NULL;
  }

  ctrl->blocking = 1;

  return ctrl;
}
*/
import "C"

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const headerSize = C.size_t(unsafe.Sizeof(C.struct_VChanMessageHeader{}))

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type connection struct {
	vchanReader *C.struct_libxenvchan
	vchanWriter *C.struct_libxenvchan
}

// VChan vchan implementation.
type VChan struct {
	conn       net.Conn
	mTLSConfig *tls.Config
	xsRxPath   string
	xsTxPath   string
	domain     int
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var errUnexpectedNumberBytes = aoserrors.Errorf("unexpected number of bytes")

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new vchan instance.
func NewVChan(xsRxPath string, xsTxPath string, domain int, mTLSConfig *tls.Config) *VChan {
	return &VChan{
		mTLSConfig: mTLSConfig,
		xsRxPath:   xsRxPath,
		xsTxPath:   xsTxPath,
		domain:     domain,
	}
}

// Close closes vchan.
func (v *VChan) Close() error {
	if v.conn == nil {
		return nil
	}

	return aoserrors.Wrap(v.conn.Close())
}

// Connect connects to vchan.
func (v *VChan) Connect(ctx context.Context) (err error) {
	if v.conn, err = v.newConnection(); err != nil {
		return err
	}

	if v.mTLSConfig == nil {
		return nil
	}

	tlsConn := tls.Server(v.conn, v.mTLSConfig)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return aoserrors.Errorf("tls handshake failed: %v", err)
	}

	v.conn = tlsConn

	return nil
}

// ReadMessage reads data from vchan.
func (v *VChan) ReadMessage() (data []byte, err error) {
	buffer, err := v.readVchan(headerSize)
	if err != nil {
		return nil, err
	}

	header := (*C.struct_VChanMessageHeader)(unsafe.Pointer(&buffer[0]))

	if buffer, err = v.readVchan(header.mDataSize); err != nil {
		return nil, err
	}

	recievedSha256 := C.GoBytes(unsafe.Pointer(&header.mSha256[0]), C.int(sha256.Size)) //nolint:gocritic

	sha256Payload := sha256.Sum256(buffer)
	if !bytes.Equal(sha256Payload[:], recievedSha256) {
		return nil, ErrChecksumFailed
	}

	return buffer, nil
}

// WriteMessage writes data to vchan.
func (v *VChan) WriteMessage(data []byte) (err error) {
	if err = v.writeVchan(prepareHeader(data)); err != nil {
		return err
	}

	if err = v.writeVchan(data); err != nil {
		return err
	}

	return nil
}

// Disconnect disconnects from vchan.
func (v *VChan) Disconnect() error {
	return v.Close()
}

/***********************************************************************************************************************
 * Interfaces
 **********************************************************************************************************************/

func (vc *connection) Read(buffer []byte) (int, error) {
	bufferSize := C.size_t(len(buffer))

	n, errno := C.libxenvchan_recv(vc.vchanReader, unsafe.Pointer(&buffer[0]), bufferSize)

	return int(n), errno
}

func (vc *connection) Write(buffer []byte) (int, error) {
	n, errno := C.libxenvchan_send(vc.vchanWriter, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)))

	return int(n), errno
}

func (vc *connection) Close() error {
	if vc.vchanReader != nil {
		C.libxenvchan_close(vc.vchanReader)
	}

	if vc.vchanWriter != nil {
		C.libxenvchan_close(vc.vchanWriter)
	}

	return nil
}

func (vc *connection) LocalAddr() net.Addr {
	return nil
}

func (vc *connection) RemoteAddr() net.Addr {
	return nil
}

func (vc *connection) SetDeadline(t time.Time) error {
	return nil
}

func (vc *connection) SetReadDeadline(t time.Time) error {
	return nil
}

func (vc *connection) SetWriteDeadline(t time.Time) error {
	return nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *VChan) newConnection() (conn *connection, err error) {
	defer func() {
		if err != nil {
			v.Close()
		}
	}()

	vchanReader, err := v.initVchan(v.domain, v.xsRxPath)
	if err != nil {
		return nil, err
	}

	vchanWriter, err := v.initVchan(v.domain, v.xsTxPath)
	if err != nil {
		return nil, err
	}

	return &connection{
		vchanReader: vchanReader,
		vchanWriter: vchanWriter,
	}, nil
}

func (v *VChan) initVchan(domain int, xsPath string) (*C.struct_libxenvchan, error) {
	cstr := C.CString(xsPath)
	defer C.free(unsafe.Pointer(cstr))

	// To address Golang's inability to access bitfields in C structures,
	// it is necessary to use server_init() instead of libxenvchan_server_init().

	vchan, err := C.libxenvchan_server_init(nil, C.int(domain), cstr, 0, 0)
	if vchan == nil {
		return nil, aoserrors.Errorf("libxenvchan_server_init failed: %v", err)
	}

	return vchan, nil
}

func (v *VChan) readVchan(buffSize int) ([]byte, error) {
	buffer := make([]byte, buffSize)

	n, err := v.conn.Read(buffer)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if n != buffSize {
		return nil, aoserrors.Wrap(errUnexpectedNumberBytes)
	}

	return buffer, nil
}

func (v *VChan) writeVchan(buffer []byte) error {
	n, err := v.conn.Write(buffer)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if n != len(buffer) {
		return aoserrors.Wrap(errUnexpectedNumberBytes)
	}

	return nil
}

func prepareHeader(data []byte) []byte {
	header := C.struct_VChanMessageHeader{
		mDataSize: C.uint32_t(len(data)),
	}

	sha256Payload := sha256.Sum256(data)

	//nolint:gocritic
	C.memcpy(unsafe.Pointer(
		&header.mSha256[0]), unsafe.Pointer(&sha256Payload[0]), C.size_t(len(sha256Payload)))

	return (*[headerSize]byte)(unsafe.Pointer(&header))[:]
}
