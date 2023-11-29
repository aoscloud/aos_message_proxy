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
	"fmt"
	"os"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/servicemanager/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

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
	Connect(ctx context.Context) error
	ReadMessage() ([]byte, error)
	WriteMessage(data []byte) error
	Disconnect() error
}

// Vchan vchan instance.
type VChanManager struct {
	vchanPub        VChanItf
	vchanPriv       VChanItf
	recvChan        chan []byte
	sendChan        chan []byte
	cancel          context.CancelFunc
	downloadManager Downloader
	unpackerManager Unpacker
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var (
	errChecksumFailed = errors.New("checksum validation failed")
	errVChanWrite     = errors.New("vchan write failed")
)

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new vchan instance.
func New(
	downloadManager Downloader, unpackerManager Unpacker, vchanPub VChanItf, vchanPriv VChanItf,
) (*VChanManager, error) {
	if vchanPub == nil || vchanPriv == nil {
		return nil, aoserrors.Errorf("vchan is nil")
	}

	v := &VChanManager{
		recvChan:        make(chan []byte, channelSize),
		sendChan:        make(chan []byte, channelSize),
		vchanPub:        vchanPub,
		vchanPriv:       vchanPriv,
		downloadManager: downloadManager,
		unpackerManager: unpackerManager,
	}

	var ctx context.Context

	ctx, v.cancel = context.WithCancel(context.Background())

	sendChanPub := make(chan []byte, channelSize)
	sendChanPriv := make(chan []byte, channelSize)

	go v.filterWriter(ctx, sendChanPub, sendChanPriv)

	go v.run(ctx, vchanPub, sendChanPub)
	go v.run(ctx, vchanPriv, sendChanPriv)

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

	v.vchanPub.Disconnect()
	v.vchanPriv.Disconnect()

	close(v.recvChan)
	close(v.sendChan)
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *VChanManager) run(ctx context.Context, vchan VChanItf, sendChan chan []byte) {
	for {
		if err := vchan.Connect(ctx); err == nil {
			errCh := make(chan error, 2) //nolint:gomnd // 2 is enough
			localCtx, cancel := context.WithCancel(ctx)

			go v.reader(localCtx, vchan, errCh)
			go v.writer(localCtx, vchan, sendChan, errCh)

			select {
			case <-ctx.Done():
				cancel()

				return

			case err := <-errCh:
				log.Errorf("Failed to read/write from/to vchan: %v", err)

				if err = vchan.Disconnect(); err != nil {
					log.Errorf("Failed to disconnect from vchan: %v", err)
				}

				cancel()
			}

		} else {
			log.Errorf("Failed connect to reader vchan: %v", aoserrors.Wrap(err))
		}

		log.Debugf("Reconnect to vchan in %v...", reconnectTimeout)

		select {
		case <-ctx.Done():
			return

		case <-time.After(reconnectTimeout):
		}
	}
}

func (v *VChanManager) filterWriter(ctx context.Context, sendChanPub, sendChanPriv chan []byte) {
	for {
		select {
		case data, ok := <-v.sendChan:
			if !ok {
				return
			}

			if isPublicMessage(data) {
				sendChanPub <- data

				continue
			}

			sendChanPriv <- data

		case <-ctx.Done():
			return
		}
	}
}

func (v *VChanManager) writer(ctx context.Context, vchan VChanItf, sendChan chan []byte, errCh chan<- error) {
	for {
		select {
		case data := <-sendChan:
			if err := vchan.WriteMessage(data); err != nil {
				errCh <- err

				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func (v *VChanManager) reader(ctx context.Context, vchan VChanItf, errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return

		default:
			buffer, err := vchan.ReadMessage()
			if err != nil {
				if errors.Is(err, errChecksumFailed) {
					log.Error("Failed to validate checksum")

					continue
				}

				errCh <- err

				return
			}

			if request, ok := v.isImageContentRequest(buffer); ok {
				go func() {
					if err := v.download(
						request.ImageContentRequest.GetUrl(), request.ImageContentRequest.GetRequestId(),
						request.ImageContentRequest.GetContentType(), vchan, ctx); err != nil {
						if errors.Is(err, errVChanWrite) {
							errCh <- err

							return
						}

						log.Errorf("Failed to download image content: %v", err)
					}
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

func (v *VChanManager) download(
	url string, requestID uint64, contentType string, vchan VChanItf, ctx context.Context,
) error {
	fileName, err := v.downloadManager.Download(ctx, url)
	if err != nil {
		log.Errorf("Failed to download image content: %v", aoserrors.Wrap(err))

		return v.sendFailedImageContentResponse(requestID, vchan, err)
	}

	log.Debugf("Downloaded file: %s", fileName)

	imageContentInfo, imagesContent, err := v.getImageContent(fileName, contentType, requestID)
	if err != nil {
		log.Errorf("Failed chunk file: %v", err)

		return v.sendFailedImageContentResponse(requestID, vchan, err)
	}

	return v.sendImageContentInfo(imageContentInfo, imagesContent, vchan)
}

func (v *VChanManager) sendImageContentInfo(
	imageContentInfo *pb.ImageContentInfo, imagesContent []*pb.ImageContent, vchan VChanItf,
) error {
	if err := v.sendImageContent(&pb.SMIncomingMessages{SMIncomingMessage: &pb.SMIncomingMessages_ImageContentInfo{
		ImageContentInfo: imageContentInfo,
	}}, vchan); err != nil {
		return err
	}

	for _, imageContent := range imagesContent {
		if err := v.sendImageContent(&pb.SMIncomingMessages{SMIncomingMessage: &pb.SMIncomingMessages_ImageContent{
			ImageContent: imageContent,
		}}, vchan); err != nil {
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

func (v *VChanManager) sendFailedImageContentResponse(requestID uint64, vchan VChanItf, err error) error {
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

	if err := vchan.WriteMessage(data); err != nil {
		return fmt.Errorf("%w: %v", errVChanWrite, err)
	}

	return nil
}

func (v *VChanManager) sendImageContent(imageMessage *pb.SMIncomingMessages, vchan VChanItf) error {
	data, err := proto.Marshal(imageMessage)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err := vchan.WriteMessage(data); err != nil {
		return fmt.Errorf("%w: %v", errVChanWrite, err)
	}

	return nil
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

func isPublicMessage(data []byte) bool {
	incomingMessage := &pb.SMIncomingMessages{}

	err := proto.Unmarshal(data, incomingMessage)
	if err != nil {
		log.Errorf("Failed to unmarshal incoming message: %v", aoserrors.Wrap(err))

		return false
	}

	_, ok := incomingMessage.GetSMIncomingMessage().(*pb.SMIncomingMessages_ClockSync)

	return ok
}
