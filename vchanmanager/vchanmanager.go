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
	Read(ctx context.Context) ([]byte, error)
	Write(data []byte) error
	Close()
}

// Vchan vchan instance.
type VChanManager struct {
	vchan                VChanItf
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

var (
	ErrContextCanceled = errors.New("operation canceled due to context cancellation")
	ErrChecksumFailed  = errors.New("checksum validation failed")
)

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new vchan instance.
func New(
	cfg *config.Config, downloadManager Downloader, unpackerManager Unpacker, vchan VChanItf,
) (*VChanManager, error) {
	v := &VChanManager{
		recvChan:             make(chan []byte, channelSize),
		sendChan:             make(chan []byte, channelSize),
		connectionLostNotify: make(chan struct{}, 1),
		cfg:                  cfg,
		vchan:                vchan,
		downloadManager:      downloadManager,
		unpackerManager:      unpackerManager,
	}

	v.ctx, v.cancel = context.WithCancel(context.Background())

	go v.run()

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

	if v.vchan != nil {
		v.vchan.Close()
	}

	close(v.recvChan)
	close(v.sendChan)
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *VChanManager) run() {
	for {
		err := v.vchan.Init(v.cfg.Domain, v.cfg.XSPath)
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

func (v *VChanManager) writer() {
	defer v.waitConnection.Done()

	for {
		select {
		case data := <-v.sendChan:
			if err := v.vchan.Write(data); err != nil {
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

func (v *VChanManager) reader() {
	defer v.waitConnection.Done()
	defer func() { v.connectionLostNotify <- struct{}{} }()

	for {
		select {
		case <-v.ctx.Done():
			return

		default:
			buffer, err := v.vchan.Read(v.ctx)
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

func (v *VChanManager) download(url string, requestId uint64, contentType string) {
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

func (v *VChanManager) sendImageContentInfo(imageContentInfo *pb.ImageContentInfo, imagesContent []*pb.ImageContent) error {
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

	return v.vchan.Write(data)
}

func (v *VChanManager) sendImageContent(imageMessage *pb.SMIncomingMessages) error {
	data, err := proto.Marshal(imageMessage)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	return v.vchan.Write(data)
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
