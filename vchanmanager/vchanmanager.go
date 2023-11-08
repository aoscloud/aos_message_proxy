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

package vchanmanager

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

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

// VChanItf interface for vchan.
type VChanItf interface {
	Init(domain int, xsPath string) error
	Read() ([]byte, error)
	Write(data []byte) error
	Close()
}

// Vchan vchan instance.
type VChanManager struct {
	sync.Mutex

	vchanReader     VChanItf
	vchanWriter     VChanItf
	recvChan        chan []byte
	sendChan        chan []byte
	cancel          context.CancelFunc
	cfg             *config.Config
	downloadManager Downloader
	unpackerManager Unpacker
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var (
	ErrContextCanceled = errors.New("operation canceled due to context cancellation")
	ErrChecksumFailed  = errors.New("checksum validation failed")
)

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new vchan instance.
func New(
	cfg *config.Config, downloadManager Downloader, unpackerManager Unpacker, vchanReader VChanItf, vchanWriter VChanItf,
) (*VChanManager, error) {
	if vchanReader == nil {
		return nil, aoserrors.New("reader vchan is nil")
	}

	if vchanWriter == nil {
		return nil, aoserrors.New("writer vchan is nil")
	}

	v := &VChanManager{
		recvChan:        make(chan []byte, channelSize),
		sendChan:        make(chan []byte, channelSize),
		cfg:             cfg,
		vchanReader:     vchanReader,
		vchanWriter:     vchanWriter,
		downloadManager: downloadManager,
		unpackerManager: unpackerManager,
	}

	var ctx context.Context

	ctx, v.cancel = context.WithCancel(context.Background())

	go v.runReader(ctx)
	go v.runWriter(ctx)

	return v, nil
}

// GetReceivingChannel returns channel for receiving data.
func (v *VChanManager) GetReceivingChannel() <-chan []byte {
	return v.recvChan
}

// GetSendingChannel returns channel for sending data.
func (v *VChanManager) GetSendingChannel() chan<- []byte {
	return v.sendChan
}

// Close closes vchan.
func (v *VChanManager) Close() {
	if v.cancel != nil {
		v.cancel()
	}

	if v.vchanReader != nil {
		v.vchanReader.Close()
	}

	if v.vchanWriter != nil {
		v.vchanWriter.Close()
	}

	close(v.recvChan)
	close(v.sendChan)
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *VChanManager) runReader(ctx context.Context) {
	for {
		// Initialization of vchan for a single domain must be synchronous.
		v.Lock()
		err := v.vchanReader.Init(v.cfg.VChan.Domain, v.cfg.VChan.XsRxPath)
		v.Unlock()

		if err == nil {
			v.reader(ctx)
		} else {
			log.Errorf("Failed connect to reader vchan: %v", aoserrors.Wrap(err))
		}

		log.Debugf("Reconnect to reader vchan in %v...", reconnectTimeout)

		select {
		case <-ctx.Done():
			return

		case <-time.After(reconnectTimeout):
		}
	}
}

func (v *VChanManager) runWriter(ctx context.Context) {
	for {
		// Initialization of vchan for a single domain must be synchronous.
		v.Lock()
		err := v.vchanWriter.Init(v.cfg.VChan.Domain, v.cfg.VChan.XsTxPath)
		v.Unlock()

		if err == nil {
			v.writer(ctx)
		} else {
			log.Errorf("Failed connect to writer vchan: %v", aoserrors.Wrap(err))
		}

		log.Debugf("Reconnect to writer vchan in %v...", reconnectTimeout)

		select {
		case <-ctx.Done():
			return

		case <-time.After(reconnectTimeout):
		}
	}
}

func (v *VChanManager) writer(ctx context.Context) {
	for {
		select {
		case data := <-v.sendChan:
			if err := v.vchanWriter.Write(data); err != nil {
				log.Errorf("Failed write to vchan: %v", aoserrors.Wrap(err))

				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func (v *VChanManager) reader(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		default:
			buffer, err := v.vchanReader.Read()
			if err != nil {
				if errors.Is(err, ErrContextCanceled) {
					return
				}

				log.Errorf("Failed read from vchan: %v", err)

				if errors.Is(err, ErrChecksumFailed) {
					continue
				}

				return
			}

			if request, ok := v.isImageContentRequest(buffer); ok {
				go func() {
					v.download(
						request.ImageContentRequest.GetUrl(), request.ImageContentRequest.GetRequestId(),
						request.ImageContentRequest.GetContentType(), ctx)
				}()

				continue
			}

			// This is necessary to avoid writing to a closed channel
			select {
			case <-ctx.Done():
				return
			default:
				v.recvChan <- buffer
			}
		}
	}
}

func (v *VChanManager) download(url string, requestID uint64, contentType string, ctx context.Context) {
	fileName, err := v.downloadManager.Download(ctx, url)
	if err != nil {
		log.Errorf("Failed to download image content: %v", aoserrors.Wrap(err))

		if err := v.sendFailedImageContentResponse(requestID, err); err != nil {
			log.Errorf("Failed to send failed image content response: %v", err)
		}

		return
	}

	log.Debugf("Downloaded file: %s", fileName)

	imageContentInfo, imagesContent, err := v.getImageContent(fileName, contentType, requestID)
	if err != nil {
		log.Errorf("Failed chunk file: %v", err)

		if err := v.sendFailedImageContentResponse(requestID, err); err != nil {
			log.Errorf("Failed to send failed image content response: %v", err)
		}

		return
	}

	if err := v.sendImageContentInfo(imageContentInfo, imagesContent); err != nil {
		log.Errorf("Failed to send image content: %v", err)
	}
}

func (v *VChanManager) sendImageContentInfo(
	imageContentInfo *pb.ImageContentInfo, imagesContent []*pb.ImageContent,
) error {
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

func (v *VChanManager) getImageContent(
	fileName, contentType string, requestID uint64,
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

	contentInfo, err := filechunker.ChunkFiles(unarchiveDir, requestID)
	if err != nil {
		return nil, nil, aoserrors.Wrap(err)
	}

	return &pb.ImageContentInfo{
		RequestId:  contentInfo.RequestID,
		ImageFiles: convertImageFilesToPb(contentInfo.ImageFiles),
		Error:      contentInfo.Error,
	}, convertImageContentToPb(contentInfo.ImageContent), nil
}

func convertImageFilesToPb(files []filechunker.ImageFile) []*pb.ImageFile {
	imageFiles := make([]*pb.ImageFile, len(files))

	for i, file := range files {
		imageFiles[i] = &pb.ImageFile{
			RelativePath: file.RelativePath,
			Sha256:       file.Sha256,
			Size:         file.Size,
		}
	}

	return imageFiles
}

func convertImageContentToPb(content []filechunker.ImageContent) []*pb.ImageContent {
	imageContent := make([]*pb.ImageContent, len(content))

	for i, c := range content {
		imageContent[i] = &pb.ImageContent{
			RequestId:    c.RequestID,
			RelativePath: c.RelativePath,
			PartsCount:   c.PartsCount,
			Part:         c.Part,
			Data:         c.Data,
		}
	}

	return imageContent
}

func (v *VChanManager) sendFailedImageContentResponse(requestID uint64, err error) error {
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

	return aoserrors.Wrap(v.vchanWriter.Write(data))
}

func (v *VChanManager) sendImageContent(imageMessage *pb.SMIncomingMessages) error {
	data, err := proto.Marshal(imageMessage)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	return aoserrors.Wrap(v.vchanWriter.Write(data))
}

func (v *VChanManager) isImageContentRequest(data []byte) (*pb.SMOutgoingMessages_ImageContentRequest, bool) {
	outgoingMessage := &pb.SMOutgoingMessages{}

	err := proto.Unmarshal(data, outgoingMessage)
	if err != nil {
		log.Errorf("Failed to unmarshal outgoing message: %v", aoserrors.Wrap(err))

		return nil, false
	}

	imageRequest, ok := outgoingMessage.GetSMOutgoingMessage().(*pb.SMOutgoingMessages_ImageContentRequest)

	return imageRequest, ok
}
