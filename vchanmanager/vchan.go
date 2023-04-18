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
	"sync"
	"syscall"
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

static void fdZero(void *set) {
    FD_ZERO((fd_set*)set);
}

static void fdSet(int sysfd, void *set) {
    FD_SET(sysfd, (fd_set*)set);
}

static int fdIsSet (int sysfd, void *set) {
    return FD_ISSET(sysfd, (fd_set*)set);
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

// VChan vchan implementation.
type VChan struct {
	sync.Mutex

	vchan *C.struct_libxenvchan
}

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

	if v.vchan, err = C.libxenvchan_server_init(
		(*C.struct_xentoollog_logger)(nil), C.int(domain), cstr, C.size_t(0), C.size_t(0)); v.vchan == nil {
		return aoserrors.Errorf("vchan server init failed: %v", err)
	}

	return nil
}

// Read reads data from vchan.
func (v *VChan) Read(ctx context.Context) (data []byte, err error) {
	buffer, err := v.readData(ctx, headerSize)
	if err != nil {
		return nil, err
	}

	header := (*C.struct_VChanMessageHeader)(unsafe.Pointer(&buffer[0]))

	if buffer, err = v.readData(ctx, C.size_t(header.dataSize)); err != nil {
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

func (v *VChan) readData(ctx context.Context, readSize C.size_t) ([]byte, error) {
	buffer := make([]byte, readSize)
	bytesRead := C.size_t(0)

	libxenvchanFd := C.libxenvchan_fd_for_select(v.vchan)
	for bytesRead < readSize {
		select {
		case <-ctx.Done():
			return nil, ErrContextCanceled

		default:
			var rfds syscall.FdSet

			C.fdZero(unsafe.Pointer(&rfds))
			C.fdSet(C.int(libxenvchanFd), unsafe.Pointer(&rfds))

			_, err := syscall.Select(int(libxenvchanFd)+1, &rfds, nil, nil, nil)
			if err != nil {
				return nil, err
			}

			if C.fdIsSet(C.int(libxenvchanFd), unsafe.Pointer(&rfds)) == 0 {
				continue
			}

			readBuff, err := v.readVchan(readSize - bytesRead)
			if err != nil {
				return nil, err
			}

			copy(buffer[bytesRead:], readBuff)
			bytesRead += C.size_t(len(readBuff))
		}
	}

	return buffer, nil
}

func (v *VChan) readVchan(buffSize C.size_t) ([]byte, error) {
	var (
		buffer = make([]byte, buffSize)
		read   C.int
	)

	for C.libxenvchan_data_ready(v.vchan) > 0 && read < C.int(buffSize) {
		v.Lock()
		n, errno := C.libxenvchan_read(v.vchan, unsafe.Pointer(&buffer[read]), buffSize-C.size_t(read))
		v.Unlock()
		if n < 0 {
			return nil, aoserrors.Errorf("vchan server read failed: %v", errno)
		}

		read += n
	}

	return buffer[:read], nil
}

func (v *VChan) writeVchan(buffer []byte) error {
	var (
		n        C.int
		buffSize = C.size_t(len(buffer))
	)

	for n < C.int(buffSize) {
		v.Lock()
		ret, errno := C.libxenvchan_write(v.vchan, unsafe.Pointer(&buffer[n]), buffSize-C.size_t(n))
		v.Unlock()
		if ret < 0 {
			return aoserrors.Errorf("vchan server write failed: %v", errno)
		}

		n += ret
	}

	if n != C.int(len(buffer)) {
		return aoserrors.New("unexpected number of bytes")
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
