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
	"crypto/sha256"
	"fmt"
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
import "C" // nolint:typecheck

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const headerSize = C.size_t(unsafe.Sizeof(C.struct_VChanMessageHeader{}))

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// VChan vchan implementation.
type VChan struct {
	vchan *C.struct_libxenvchan
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var errUnexpectedNumberBytes = fmt.Errorf("unexpected number of bytes")

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new vchan instance.
func NewVChan() *VChan {
	return &VChan{}
}

// Close closes vchan.
func (v *VChan) Close() {
	C.libxenvchan_close(v.vchan)
}

// Init initializes vchan.
func (v *VChan) Init(domain int, xsPath string) (err error) {
	cstr := C.CString(xsPath)
	defer C.free(unsafe.Pointer(cstr))

	// To address Golang's inability to access bitfields in C structures,
	// it is necessary to use server_init() instead of libxenvchan_server_init().

	v.vchan, err = C.server_init(C.int(domain), cstr)
	if v.vchan == nil {
		return aoserrors.Errorf("libxenvchan_server_init failed: %v", err)
	}

	return nil
}

// Read reads data from vchan.
func (v *VChan) Read() (data []byte, err error) {
	buffer, err := v.readVchan(headerSize)
	if err != nil {
		return nil, err
	}

	header := (*C.struct_VChanMessageHeader)(unsafe.Pointer(&buffer[0]))

	if buffer, err = v.readVchan(C.size_t(header.dataSize)); err != nil {
		return nil, err
	}

	recievedSha256 := C.GoBytes(unsafe.Pointer(&header.sha256[0]), C.int(sha256.Size))

	sha256Payload := sha256.Sum256(buffer)
	if !bytes.Equal(sha256Payload[:], recievedSha256) {
		return nil, ErrChecksumFailed
	}

	return buffer, nil
}

// Write writes data to vchan.
func (v *VChan) Write(data []byte) (err error) {
	if err := v.writeVchan(prepareHeader(data)); err != nil {
		return err
	}

	if err := v.writeVchan(data); err != nil {
		return err
	}

	return nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *VChan) readVchan(buffSize C.size_t) ([]byte, error) {
	buffer := make([]byte, buffSize)

	n, errno := C.libxenvchan_recv(v.vchan, unsafe.Pointer(&buffer[0]), buffSize)
	if n < 0 {
		return nil, aoserrors.Errorf("libxenvchan_recv failed: %v", errno)
	}

	if n != C.int(buffSize) {
		return nil, aoserrors.Wrap(errUnexpectedNumberBytes)
	}

	return buffer, nil
}

func (v *VChan) writeVchan(buffer []byte) error {
	n, errno := C.libxenvchan_send(v.vchan, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)))
	if n < 0 {
		return aoserrors.Errorf("libxenvchan_send failed: %v", errno)
	}

	if n != C.int(len(buffer)) {
		return aoserrors.Wrap(errUnexpectedNumberBytes)
	}

	return nil
}

func prepareHeader(data []byte) []byte {
	header := C.struct_VChanMessageHeader{
		dataSize: C.uint32_t(len(data)),
	}

	sha256Payload := sha256.Sum256(data)

	C.memcpy(unsafe.Pointer(&header.sha256[0]), unsafe.Pointer(&sha256Payload[0]), C.size_t(len(sha256Payload)))

	return (*[headerSize]byte)(unsafe.Pointer(&header))[:]
}
