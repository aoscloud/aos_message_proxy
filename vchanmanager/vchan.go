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
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/aosedge/aos_common/aoserrors"
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

type aosError int32

const (
	eNone aosError = iota
	eFailed
	eRuntime
	eNoMemory
	eOutOfRange
	eNotFound
	eInvalidArgument
	eTimeout
	eAlreadyExist
	eWrongState
	eInvalidChecksum
	eAlreadyLoggedIn
	eNotSupported
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type connection struct {
	name        string
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

var (
	errUnexpectedNumberBytes = errors.New("unexpected number of bytes")
	errReadVChan             = errors.New("read failed")
	errWriteVChan            = errors.New("write failed")
)

var lock sync.Mutex //nolint: gochecknoglobals

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
func (v *VChan) Connect(ctx context.Context, name string) (err error) {
	if v.conn, err = v.newConnection(name); err != nil {
		return err
	}

	if v.mTLSConfig == nil {
		return nil
	}

	defer func() {
		if err != nil {
			v.conn.Close()
		}
	}()

	tlsConn := tls.Server(v.conn, v.mTLSConfig)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return aoserrors.Errorf("tls handshake failed: %v", err)
	}

	v.conn = tlsConn

	return nil
}

// ReadMessage reads data from vchan.
func (v *VChan) ReadMessage() (msg Message, err error) {
	buffer, err := v.readVchan(int(headerSize))
	if err != nil {
		return msg, err
	}

	header := (*C.struct_VChanMessageHeader)(unsafe.Pointer(&buffer[0]))

	// check if there is a system error
	if header.mErrno != 0 {
		return Message{
			MsgSource: MessageSource(header.mSource),
			Err:       convertErrnoToError(header.mErrno),
		}, nil
	}

	// check if there is an aos error
	if header.mAosError != C.int(eNone) {
		return Message{
			MsgSource: MessageSource(header.mSource),
			Err:       convertAosErrorToError(aosError(header.mAosError)),
		}, nil
	}

	// check if empty message response
	if header.mDataSize == 0 {
		return Message{
			MsgSource: MessageSource(header.mSource),
		}, nil
	}

	if buffer, err = v.readVchan(int(header.mDataSize)); err != nil {
		return msg, err
	}

	receivedSha256 := C.GoBytes(unsafe.Pointer(&header.mSha256[0]), C.int(sha256.Size)) //nolint:gocritic

	sha256Payload := sha256.Sum256(buffer)
	if !bytes.Equal(sha256Payload[:], receivedSha256) {
		return msg, errChecksumFailed
	}

	return Message{
		MsgSource: MessageSource(header.mSource),
		Data:      buffer,
	}, nil
}

// WriteMessage writes data to vchan.
func (v *VChan) WriteMessage(msg Message) (err error) {
	if err = v.writeVchan(prepareHeader(msg)); err != nil {
		return err
	}

	if len(msg.Data) > 0 {
		if err = v.writeVchan(msg.Data); err != nil {
			return err
		}
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

	ret, err := C.libxenvchan_read(vc.vchanReader, unsafe.Pointer(&buffer[0]), bufferSize)
	if err != nil {
		return int(ret), err
	}

	if ret < 0 {
		return int(ret), errReadVChan
	}

	return int(ret), nil
}

func (vc *connection) Write(buffer []byte) (int, error) {
	bufferSize := C.size_t(len(buffer))

	ret, err := C.libxenvchan_write(vc.vchanWriter, unsafe.Pointer(&buffer[0]), bufferSize)
	if err != nil {
		return int(ret), err
	}

	if ret < 0 {
		return int(ret), errWriteVChan
	}

	return int(ret), nil
}

func (vc *connection) Close() error {
	lock.Lock()
	defer lock.Unlock()

	if vc.vchanReader != nil {
		log.WithFields(log.Fields{"name": vc.name}).Debug("Close read vchan")

		C.libxenvchan_close(vc.vchanReader)
	}

	if vc.vchanWriter != nil {
		log.WithFields(log.Fields{"name": vc.name}).Debug("Close write vchan")

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

func (v *VChan) newConnection(name string) (conn *connection, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	lock.Lock()
	defer lock.Unlock()

	log.WithFields(log.Fields{"rxPath": v.xsRxPath, "txPath": v.xsTxPath}).Debug("New connection")

	conn = &connection{name: name}

	conn.vchanReader, err = v.initVchan(v.domain, v.xsRxPath)
	if err != nil {
		return conn, err
	}

	conn.vchanWriter, err = v.initVchan(v.domain, v.xsTxPath)
	if err != nil {
		return conn, err
	}

	return conn, nil
}

func (v *VChan) initVchan(domain int, xsPath string) (*C.struct_libxenvchan, error) {
	cstr := C.CString(xsPath)
	defer C.free(unsafe.Pointer(cstr))

	// To address Golang's inability to access bitfields in C structures,
	// it is necessary to use server_init() instead of libxenvchan_server_init().

	vchan, err := C.server_init(C.int(domain), cstr)
	if vchan == nil {
		return nil, aoserrors.Errorf("libxenvchan_server_init failed: %v", err)
	}

	log.WithFields(log.Fields{"rxPath": xsPath}).Debug("VChan created")

	return vchan, nil
}

func (v *VChan) readVchan(buffSize int) ([]byte, error) {
	buffer := make([]byte, buffSize)
	read := 0

	for read < len(buffer) {
		n, err := v.conn.Read(buffer[read:])
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		read += n
	}

	return buffer, nil
}

func (v *VChan) writeVchan(buffer []byte) error {
	write := 0

	for write < len(buffer) {
		n, err := v.conn.Write(buffer[write:])
		if err != nil {
			return aoserrors.Wrap(err)
		}

		write += n
	}

	return nil
}

func prepareHeader(msg Message) []byte {
	header := C.struct_VChanMessageHeader{
		mSource:   C.uint32_t(msg.MsgSource),
		mDataSize: C.uint32_t(len(msg.Data)),
	}

	sha256Payload := sha256.Sum256(msg.Data)

	//nolint:gocritic
	C.memcpy(unsafe.Pointer(&header.mSha256[0]), unsafe.Pointer(&sha256Payload[0]), C.size_t(len(sha256Payload)))

	methodName := C.CString(msg.MethodName)
	defer C.free(unsafe.Pointer(methodName))

	C.strncpy(&header.mMethodName[0], methodName, 255) //nolint: gomnd

	header.mMethodName[255] = 0

	return (*[headerSize]byte)(unsafe.Pointer(&header))[:]
}

func convertAosErrorToError(err aosError) error {
	switch err {
	case eFailed:
		return aoserrors.Errorf("failed")
	case eRuntime:
		return aoserrors.Errorf("runtime")
	case eNoMemory:
		return aoserrors.Errorf("no memory")
	case eOutOfRange:
		return aoserrors.Errorf("out of range")
	case eNotFound:
		return aoserrors.Errorf("not found")
	case eInvalidArgument:
		return aoserrors.Errorf("invalid argument")
	case eTimeout:
		return aoserrors.Errorf("timeout")
	case eAlreadyExist:
		return aoserrors.Errorf("already exist")
	case eWrongState:
		return aoserrors.Errorf("wrong state")
	case eInvalidChecksum:
		return aoserrors.Errorf("invalid checksum")
	case eAlreadyLoggedIn:
		return aoserrors.Errorf("already logged in")
	case eNotSupported:
		return aoserrors.Errorf("not supported")
	default:
		return aoserrors.Errorf("unknown error")
	}
}

func convertErrnoToError(errno C.int) error {
	return aoserrors.Errorf(syscall.Errno(errno).Error())
}
