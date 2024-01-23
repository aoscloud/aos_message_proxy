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
	"reflect"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pbIAM "github.com/aoscloud/aos_common/api/iamanager/v4"
	pbSM "github.com/aoscloud/aos_common/api/servicemanager/v3"
	"github.com/aoscloud/aos_common/utils/syncstream"
	"github.com/golang/protobuf/ptypes/empty"
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

const (
	IAM MessageSource = iota
	SM
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// MessageSource message source.
type MessageSource int

// Downloader interface for downloading images.
type DownloaderItf interface {
	Download(ctx context.Context, url string) (fileName string, err error)
}

// Unpacker interface for unpacking images.
type UnpackerItf interface {
	Unpack(archivePath string, contentType string) (string, error)
}

// VChanItf interface for vchan.
type VChanItf interface {
	Connect(ctx context.Context) error
	ReadMessage() (Message, error)
	WriteMessage(msg Message) error
	Disconnect() error
}

// Message vchan message.
type Message struct {
	MsgSource  MessageSource
	MethodName string
	Data       []byte
	Err        error
}

// Vchan vchan instance.
type VChanManager struct {
	vchanOpen       VChanItf
	vchanSecure     VChanItf
	recvSMChan      chan []byte
	sendChan        chan Message
	cancel          context.CancelFunc
	downloadManager DownloaderItf
	unpackerManager UnpackerItf
	syncstream      *syncstream.SyncStream
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
	downloadManager DownloaderItf, unpackerManager UnpackerItf, vchanOpen VChanItf, vchanSecure VChanItf,
) (*VChanManager, error) {
	if vchanOpen == nil || vchanSecure == nil {
		return nil, aoserrors.Errorf("vchan is nil")
	}

	v := &VChanManager{
		recvSMChan:      make(chan []byte, channelSize),
		sendChan:        make(chan Message, channelSize),
		vchanOpen:       vchanOpen,
		vchanSecure:     vchanSecure,
		downloadManager: downloadManager,
		unpackerManager: unpackerManager,
		syncstream:      syncstream.New(),
	}

	var ctx context.Context

	ctx, v.cancel = context.WithCancel(context.Background())

	sendChanOpen := make(chan Message, channelSize)
	sendChanSecure := make(chan Message, channelSize)

	go v.filterWriter(ctx, sendChanOpen, sendChanSecure)

	go v.run(ctx, vchanOpen, sendChanOpen)
	go v.run(ctx, vchanSecure, sendChanSecure)

	return v, nil
}

// ReceiveSMMessage returns channel for receiving SM messages.
func (v *VChanManager) ReceiveSMMessage() <-chan []byte {
	return v.recvSMChan
}

// SendSMMessage sends SM message.
func (v *VChanManager) SendSMMessage(data []byte) error {
	v.sendChan <- Message{
		MsgSource: SM,
		Data:      data,
	}

	return nil
}

// Close closes vchan.
func (v *VChanManager) Close() {
	if v.cancel != nil {
		v.cancel()
	}

	if err := v.vchanOpen.Disconnect(); err != nil {
		log.Errorf("Failed to disconnect from vchan: %v", err)
	}

	if err := v.vchanSecure.Disconnect(); err != nil {
		log.Errorf("Failed to disconnect from vchan: %v", err)
	}

	close(v.recvSMChan)
	close(v.sendChan)
}

// CreateKey creates key.
func (v *VChanManager) CreateKey(ctx context.Context, req *pbIAM.CreateKeyRequest) (*pbIAM.CreateKeyResponse, error) {
	rsp := &pbIAM.CreateKeyResponse{}

	err := v.sendIAMRequest(ctx, "/iamanager.v4.IAMCertificateService/CreateKey", req, rsp)

	return rsp, err
}

// ApplyCert applies certificate.
func (v *VChanManager) ApplyCert(context context.Context, req *pbIAM.ApplyCertRequest) (
	*pbIAM.ApplyCertResponse, error,
) {
	rsp := &pbIAM.ApplyCertResponse{}

	err := v.sendIAMRequest(context, "/iamanager.v4.IAMCertificateService/ApplyCert", req, rsp)

	return rsp, err
}

// GetCertTypes returns all IAM cert types.
func (v *VChanManager) GetCertTypes(context context.Context, req *pbIAM.GetCertTypesRequest) (
	rsp *pbIAM.CertTypes, err error,
) {
	rsp = &pbIAM.CertTypes{}

	err = v.sendIAMRequest(context, "/iamanager.v4.IAMProvisioningService/GetCertTypes", req, rsp)

	return rsp, err
}

// SetOwner sets owner.
func (v *VChanManager) SetOwner(context context.Context, req *pbIAM.SetOwnerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, v.sendIAMRequestNoResponse(context, "/iamanager.v4.IAMProvisioningService/SetOwner", req)
}

// Clear clears.
func (v *VChanManager) Clear(context context.Context, req *pbIAM.ClearRequest) (*empty.Empty, error) {
	return &empty.Empty{}, v.sendIAMRequestNoResponse(context, "/iamanager.v4.IAMProvisioningService/Clear", req)
}

// EncryptDisk encrypts disk.
func (v *VChanManager) EncryptDisk(ctx context.Context, req *pbIAM.EncryptDiskRequest) (*empty.Empty, error) {
	return &empty.Empty{}, v.sendIAMRequestNoResponse(ctx, "/iamanager.v4.IAMProvisioningService/EncryptDisk", req)
}

// FinishProvisioning notifies that provisioning is finished.
func (v *VChanManager) FinishProvisioning(context context.Context, req *empty.Empty) (*empty.Empty, error) {
	data, err := v.syncstream.Send(context, func() error {
		v.sendChan <- Message{
			MsgSource:  IAM,
			MethodName: "/iamanager.v4.IAMProvisioningService/FinishProvisioning",
		}

		return nil
	}, reflect.TypeOf(Message{}))
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	msg, ok := data.(Message)
	if !ok {
		return nil, aoserrors.Errorf("unexpected type of data")
	}

	if msg.Err != nil {
		return nil, msg.Err
	}

	return &empty.Empty{}, nil
}

// GetAllNodeIDs returns all known node IDs.
func (v *VChanManager) GetAllNodeIDs(context context.Context,
	req *empty.Empty,
) (rsp *pbIAM.NodesID, err error) {
	data, err := v.syncstream.Send(context, func() error {
		v.sendChan <- Message{
			MsgSource:  IAM,
			MethodName: "/iamanager.v4.IAMProvisioningService/GetAllNodeIDs",
		}

		return nil
	}, reflect.TypeOf(Message{}))
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	msg, ok := data.(Message)
	if !ok {
		return nil, aoserrors.Errorf("unexpected type of data")
	}

	if msg.Err != nil {
		return nil, msg.Err
	}

	rsp = &pbIAM.NodesID{}

	if err = proto.Unmarshal(msg.Data, rsp); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return rsp, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (v *VChanManager) run(ctx context.Context, vchan VChanItf, sendChan chan Message) {
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

func (v *VChanManager) filterWriter(ctx context.Context, sendChanOpen, sendChanSecure chan Message) {
	for {
		select {
		case msg, ok := <-v.sendChan:
			if !ok {
				return
			}

			if isPublicMessage(msg.Data) {
				sendChanOpen <- msg

				continue
			}

			sendChanSecure <- msg

		case <-ctx.Done():
			return
		}
	}
}

func (v *VChanManager) writer(ctx context.Context, vchan VChanItf, sendChan chan Message, errCh chan<- error) {
	for {
		select {
		case msg := <-sendChan:
			if err := vchan.WriteMessage(msg); err != nil {
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
			msg, err := vchan.ReadMessage()
			if err != nil {
				if errors.Is(err, errChecksumFailed) {
					log.Error("Failed to validate checksum")

					continue
				}

				errCh <- err

				return
			}

			if !v.handleImageContentRequest(msg, vchan, ctx, errCh) {
				v.processMessage(msg)
			}
		}
	}
}

func (v *VChanManager) handleImageContentRequest(
	msg Message, vchan VChanItf, ctx context.Context, errCh chan<- error,
) bool {
	request, ok := v.isImageContentRequest(msg.Data)
	if !ok {
		return false
	}

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

	return true
}

func (v *VChanManager) processMessage(msg Message) {
	switch msg.MsgSource {
	case IAM:
		if !v.syncstream.ProcessMessages(msg) {
			log.Errorf("Failed to process IAM message")
		}

	case SM:
		v.recvSMChan <- msg.Data
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
	imageContentInfo *pbSM.ImageContentInfo, imagesContent []*pbSM.ImageContent, vchan VChanItf,
) error {
	if err := v.sendImageContent(&pbSM.SMIncomingMessages{SMIncomingMessage: &pbSM.SMIncomingMessages_ImageContentInfo{
		ImageContentInfo: imageContentInfo,
	}}, vchan); err != nil {
		return err
	}

	for _, imageContent := range imagesContent {
		if err := v.sendImageContent(&pbSM.SMIncomingMessages{SMIncomingMessage: &pbSM.SMIncomingMessages_ImageContent{
			ImageContent: imageContent,
		}}, vchan); err != nil {
			return err
		}
	}

	return nil
}

func (v *VChanManager) getImageContent(
	fileName, contentType string, requestID uint64,
) (*pbSM.ImageContentInfo, []*pbSM.ImageContent, error) {
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

	return &pbSM.ImageContentInfo{
		RequestId:  contentInfo.RequestID,
		ImageFiles: convertImageFilesToPb(contentInfo.ImageFiles),
		Error:      contentInfo.Error,
	}, convertImageContentToPb(contentInfo.ImageContent), nil
}

func convertImageFilesToPb(files []filechunker.ImageFile) []*pbSM.ImageFile {
	imageFiles := make([]*pbSM.ImageFile, len(files))

	for i, file := range files {
		imageFiles[i] = &pbSM.ImageFile{
			RelativePath: file.RelativePath,
			Sha256:       file.Sha256,
			Size:         file.Size,
		}
	}

	return imageFiles
}

func convertImageContentToPb(content []filechunker.ImageContent) []*pbSM.ImageContent {
	imageContent := make([]*pbSM.ImageContent, len(content))

	for i, c := range content {
		imageContent[i] = &pbSM.ImageContent{
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
	imageContentInfo := &pbSM.SMIncomingMessages{SMIncomingMessage: &pbSM.SMIncomingMessages_ImageContentInfo{
		ImageContentInfo: &pbSM.ImageContentInfo{
			RequestId: requestID,
			Error:     err.Error(),
		},
	}}

	data, err := proto.Marshal(imageContentInfo)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err := vchan.WriteMessage(Message{
		MsgSource: SM,
		Data:      data,
	}); err != nil {
		return aoserrors.Errorf("%w: %v", errVChanWrite, err)
	}

	return nil
}

func (v *VChanManager) sendImageContent(imageMessage *pbSM.SMIncomingMessages, vchan VChanItf) error {
	data, err := proto.Marshal(imageMessage)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err := vchan.WriteMessage(Message{
		MsgSource: SM,
		Data:      data,
	}); err != nil {
		return aoserrors.Errorf("%w: %v", errVChanWrite, err)
	}

	return nil
}

func (v *VChanManager) isImageContentRequest(data []byte) (*pbSM.SMOutgoingMessages_ImageContentRequest, bool) {
	outgoingMessage := &pbSM.SMOutgoingMessages{}

	err := proto.Unmarshal(data, outgoingMessage)
	if err != nil {
		log.Errorf("Failed to unmarshal outgoing message: %v", aoserrors.Wrap(err))

		return nil, false
	}

	imageRequest, ok := outgoingMessage.GetSMOutgoingMessage().(*pbSM.SMOutgoingMessages_ImageContentRequest)

	return imageRequest, ok
}

func (v *VChanManager) sendIAMRequest(
	ctx context.Context, methodName string, req proto.Message, rsp proto.Message,
) error {
	data, err := v.syncstream.Send(ctx, func() error {
		return v.sendIAMMessage(methodName, req)
	}, reflect.TypeOf(Message{}))
	if err != nil {
		return aoserrors.Wrap(err)
	}

	msg, ok := data.(Message)
	if !ok {
		return aoserrors.Errorf("unexpected type of data")
	}

	if msg.Err != nil {
		return msg.Err
	}

	if err = proto.Unmarshal(msg.Data, rsp); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (v *VChanManager) sendIAMRequestNoResponse(ctx context.Context, methodName string, req proto.Message) error {
	data, err := v.syncstream.Send(ctx, func() error {
		return v.sendIAMMessage(methodName, req)
	}, reflect.TypeOf(Message{}))
	if err != nil {
		return aoserrors.Wrap(err)
	}

	msg, ok := data.(Message)
	if !ok {
		return aoserrors.Errorf("unexpected type of data")
	}

	if msg.Err != nil {
		return msg.Err
	}

	return nil
}

func isPublicMessage(data []byte) bool {
	incomingMessage := &pbSM.SMIncomingMessages{}

	err := proto.Unmarshal(data, incomingMessage)
	if err != nil {
		log.Errorf("Failed to unmarshal incoming message: %v", aoserrors.Wrap(err))

		return false
	}

	_, ok := incomingMessage.GetSMIncomingMessage().(*pbSM.SMIncomingMessages_ClockSync)

	return ok
}

func (v *VChanManager) sendIAMMessage(methodName string, req proto.Message) error {
	data, err := proto.Marshal(req)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	v.sendChan <- Message{
		MsgSource:  IAM,
		MethodName: methodName,
		Data:       data,
	}

	return nil
}
