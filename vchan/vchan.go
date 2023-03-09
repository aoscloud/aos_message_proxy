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

package vchan

// #cgo CFLAGS: -I./include
// #include "cvchan/vchan_io.h"
// #ifdef MOCKED
// #cgo LDFLAGS: -lcrypto
// #endif
import "C"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/servicemanager/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/filechunker"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	channelSize      = 20
	reconnectTimeout = 10 * time.Second
	headerSize       = C.size_t(unsafe.Sizeof(C.struct_VchanMessageHeader{}))
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Downloader interface for downloading images.
type Downloader interface {
	Download(ctx context.Context, url string) (fileName string, err error)
}

// Unpacker interface for unpacking images.
type Unpacker interface {
	Unpack(archivePath string, contentType string) (string, error)
}

// Vchan vchan instance.
type Vchan struct {
	sync.Mutex

	vchan                *C.struct_libxenvchan
	recvChan             chan []byte
	sendChan             chan []byte
	ctx                  context.Context
	cancel               context.CancelFunc
	waitConnection       sync.WaitGroup
	connectionLostNotify chan struct{}
	cfg                  *config.Config
	downloadManager      Downloader
	unpackerManager      Unpacker
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var errUnexpectedNumberBytes = fmt.Errorf("unexpected number of bytes")

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new vchan instance.
func New(cfg *config.Config, downloadManager Downloader, unpackerManager Unpacker) (*Vchan, error) {
	vchan := &Vchan{
		recvChan:             make(chan []byte, channelSize),
		sendChan:             make(chan []byte, channelSize),
		connectionLostNotify: make(chan struct{}, 1),
		cfg:                  cfg,
		downloadManager:      downloadManager,
		unpackerManager:      unpackerManager,
	}

	vchan.ctx, vchan.cancel = context.WithCancel(context.Background())

	go vchan.run()

	return vchan, nil
}

// GetReceivingChannel returns channel for receiving data.
func (v *Vchan) GetReceivingChannel() <-chan []byte {
	return v.recvChan
}

// GetSendingChannel returns channel for sending data.
func (v *Vchan) GetSendingChannel() chan<- []byte {
	return v.sendChan
}

// Close closes vchan.
func (v *Vchan) Close() {
	if v.cancel != nil {
		v.cancel()
	}

	if v.vchan != nil {
		C.libxenvchan_close(v.vchan)
	}

	close(v.recvChan)
	close(v.sendChan)
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *Vchan) run() {
	for {
		err := v.serverInit()
		if err == nil {
			v.waitConnection.Add(2)
			go v.reader()
			go v.writer()
			v.waitConnection.Wait()
		} else {
			log.Errorf("Failed connect to vchan: %v", err)
		}

		log.Debugf("Reconnect to vchan in %v...", reconnectTimeout)

		select {
		case <-v.ctx.Done():
			return

		case <-time.After(reconnectTimeout):
		}
	}
}

func (v *Vchan) writer() {
	defer v.waitConnection.Done()

	for {
		select {
		case data := <-v.sendChan:
			if err := v.write(data); err != nil {
				log.Errorf("Failed write to vchan: %v", aoserrors.Wrap(err))

				return
			}

		case <-v.connectionLostNotify:
			return

		case <-v.ctx.Done():
			return
		}
	}
}

func (v *Vchan) write(data []byte) error {
	v.Lock()
	defer v.Unlock()

	if err := v.writeVchan(prepareHeader(data)); err != nil {
		return err
	}

	if err := v.writeVchan(data); err != nil {
		return err
	}

	return nil
}

func (v *Vchan) reader() {
	defer v.waitConnection.Done()
	defer func() { v.connectionLostNotify <- struct{}{} }()

	for {
		select {
		case <-v.ctx.Done():
			return

		default:
			buffer, err := v.readVchan(headerSize)
			if err != nil {
				log.Errorf("Failed read from vchan: %v", err)

				return
			}

			header := (*C.struct_VchanMessageHeader)(unsafe.Pointer(&buffer[0]))

			if buffer, err = v.readVchan(C.size_t(header.dataSize)); err != nil {
				log.Errorf("Failed read from vchan: %v", err)

				return
			}

			recievedSha256 := C.GoBytes(unsafe.Pointer(&header.sha256[0]), C.int(sha256.Size))

			sha256Payload := sha256.Sum256(buffer)
			if !bytes.Equal(sha256Payload[:], recievedSha256) {
				log.Errorf("Error: sha256 checksum validation failed")

				continue
			}

			if request, ok := v.isImageContentRequest(buffer); ok {
				go func() {
					v.download(
						request.ImageContentRequest.Url, request.ImageContentRequest.RequestId,
						request.ImageContentRequest.ContentType)
				}()

				continue
			}

			// This is necessary to avoid writing to a closed channel
			select {
			case <-v.ctx.Done():
				return
			default:
				v.recvChan <- buffer[:]
			}
		}
	}
}

func (v *Vchan) download(url string, requestId uint64, contentType string) {
	fileName, err := v.downloadManager.Download(v.ctx, url)
	if err != nil {
		log.Errorf("Failed to download image content: %v", aoserrors.Wrap(err))

		if err := v.sendFailedImageContentResponse(requestId, err); err != nil {
			log.Errorf("Failed to send failed image content response: %v", err)
		}

		return
	}

	log.Debugf("Downloaded file: %s", fileName)

	imageContentInfo, imagesContent, err := v.getImageContent(fileName, contentType, requestId)
	if err != nil {
		log.Errorf("Failed chunk file: %v", err)

		if err := v.sendFailedImageContentResponse(requestId, err); err != nil {
			log.Errorf("Failed to send failed image content response: %v", err)
		}

		return
	}

	if err := v.sendImageContentInfo(imageContentInfo, imagesContent); err != nil {
		log.Errorf("Failed to send image content: %v", err)
	}
}

func (v *Vchan) sendImageContentInfo(imageContentInfo *pb.ImageContentInfo, imagesContent []*pb.ImageContent) error {
	if err := v.sendImageContent(&pb.SMIncomingMessages{SMIncomingMessage: &pb.SMIncomingMessages_ImageContentInfo{
		ImageContentInfo: imageContentInfo,
	}}); err != nil {
		return err
	}

	for _, imageContent := range imagesContent {
		if err := v.sendImageContent(&pb.SMIncomingMessages{SMIncomingMessage: &pb.SMIncomingMessages_ImageContent{
			ImageContent: imageContent,
		}}); err != nil {
			return err
		}
	}

	return nil
}

func (v *Vchan) getImageContent(
	fileName, contentType string, requestId uint64,
) (*pb.ImageContentInfo, []*pb.ImageContent, error) {
	defer func() {
		if err := os.Remove(fileName); err != nil {
			log.Errorf("Failed remove file: %v", err)
		}
	}()

	unarchiveDir, err := v.unpackerManager.Unpack(fileName, contentType)
	if err != nil {
		return nil, nil, aoserrors.Wrap(err)
	}

	log.Debugf("Unpacked file: %s", unarchiveDir)

	contentInfo, err := filechunker.ChunkFiles(unarchiveDir, requestId)
	if err != nil {
		return nil, nil, aoserrors.Wrap(err)
	}

	return &pb.ImageContentInfo{
		RequestId:  contentInfo.RequestId,
		ImageFiles: convertImageFilesToPb(contentInfo.ImageFiles),
		Error:      contentInfo.Error,
	}, convertImageContentToPb(contentInfo.ImageContent), nil
}

func convertImageFilesToPb(files []filechunker.ImageFile) []*pb.ImageFile {
	var imageFiles []*pb.ImageFile

	for _, file := range files {
		imageFile := &pb.ImageFile{
			RelativePath: file.RelativePath,
			Sha256:       file.Sha256[:],
			Size:         file.Size,
		}

		imageFiles = append(imageFiles, imageFile)
	}

	return imageFiles
}

func convertImageContentToPb(content []filechunker.ImageContent) []*pb.ImageContent {
	var imageContent []*pb.ImageContent

	for _, c := range content {
		imageContent = append(imageContent, &pb.ImageContent{
			RequestId:    c.RequestId,
			RelativePath: c.RelativePath,
			PartsCount:   c.PartsCount,
			Part:         c.Part,
			Data:         c.Data[:],
		})
	}

	return imageContent
}

func (v *Vchan) serverInit() (err error) {
	cstr := C.CString(v.cfg.XSPath)
	defer C.free(unsafe.Pointer(cstr))

	// To address Golang's inability to access bitfields in C structures,
	// it is necessary to use server_init() instead of libxenvchan_server_init().

	v.vchan, err = C.server_init(C.int(v.cfg.Domain), cstr)
	if v.vchan == nil {
		return aoserrors.Errorf("libxenvchan_server_init failed: %v", err)
	}

	return nil
}

func prepareHeader(data []byte) []byte {
	header := C.struct_VchanMessageHeader{
		dataSize: C.uint32_t(len(data)),
	}

	sha256Payload := sha256.Sum256(data)

	C.memcpy(unsafe.Pointer(&header.sha256[0]), unsafe.Pointer(&sha256Payload[0]), C.size_t(len(sha256Payload)))

	return (*[headerSize]byte)(unsafe.Pointer(&header))[:]
}

func (v *Vchan) sendFailedImageContentResponse(requestID uint64, err error) error {
	imageContentInfo := &pb.SMIncomingMessages{SMIncomingMessage: &pb.SMIncomingMessages_ImageContentInfo{
		ImageContentInfo: &pb.ImageContentInfo{
			RequestId: requestID,
			Error:     err.Error(),
		},
	}}

	data, err := proto.Marshal(imageContentInfo)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	return v.write(data)
}

func (v *Vchan) sendImageContent(imageMessage *pb.SMIncomingMessages) error {
	data, err := proto.Marshal(imageMessage)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	return v.write(data)
}

func (v *Vchan) isImageContentRequest(data []byte) (*pb.SMOutgoingMessages_ImageContentRequest, bool) {
	outgoingMessage := &pb.SMOutgoingMessages{}

	err := proto.Unmarshal(data, outgoingMessage)
	if err != nil {
		log.Errorf("Failed to unmarshal outgoing message: %v", aoserrors.Wrap(err))

		return nil, false
	}

	imageRequest, ok := outgoingMessage.GetSMOutgoingMessage().(*pb.SMOutgoingMessages_ImageContentRequest)

	return imageRequest, ok
}

func (v *Vchan) readVchan(buffSize C.size_t) ([]byte, error) {
	buffer := make([]byte, buffSize)

	n, errno := C.libxenvchan_read_all(v.vchan, unsafe.Pointer(&buffer[0]), buffSize)
	if n < 0 {
		return nil, aoserrors.Errorf("libxenvchan_read_all failed: %v", errno)
	}

	if n != C.int(buffSize) {
		return nil, aoserrors.Wrap(errUnexpectedNumberBytes)
	}

	return buffer, nil
}

func (v *Vchan) writeVchan(buffer []byte) error {
	n, errno := C.libxenvchan_write_all(v.vchan, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)))
	if n < 0 {
		return aoserrors.Errorf("libxenvchan_write_all failed: %v", errno)
	}

	if n != C.int(len(buffer)) {
		return aoserrors.Wrap(errUnexpectedNumberBytes)
	}

	return nil
}
