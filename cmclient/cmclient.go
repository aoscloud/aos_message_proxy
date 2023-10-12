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

package cmclient

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/servicemanager/v3"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aoscloud/aos_messageproxy/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	cmRequestTimeout   = 30 * time.Second
	cmReconnectTimeout = 10 * time.Second
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// CMClient CM client instance.
type CMClient struct {
	connection            *grpc.ClientConn
	stream                pb.SMService_RegisterSMClient
	cancel                context.CancelFunc
	sendChan              chan<- []byte
	recvChan              <-chan []byte
	waitConnection        sync.WaitGroup
	savedOutgoingMessages []*pb.SMOutgoingMessages
	connectionLostNotify  chan struct{}
}

// CertificateProvider interface to get certificate.
type CertificateProvider interface {
	GetCertificate(certType string) (certURL, ketURL string, err error)
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new CM client.
func New(
	cfg *config.Config, certProvider CertificateProvider, cryptcoxontext *cryptutils.CryptoContext,
	recvChan <-chan []byte, sendChan chan<- []byte, insecureCon bool,
) (client *CMClient, err error) {
	log.Debug("Connecting to CM...")

	client = &CMClient{
		sendChan:             sendChan,
		recvChan:             recvChan,
		connectionLostNotify: make(chan struct{}, 1),
	}

	var secureOpt grpc.DialOption

	if insecureCon {
		secureOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		certURL, keyURL, err := certProvider.GetCertificate(cfg.CertStorage)
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		tlsConfig, err := cryptcoxontext.GetClientMutualTLSConfig(certURL, keyURL)
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		secureOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmRequestTimeout)
	defer cancel()

	if client.connection, err = grpc.DialContext(ctx, cfg.CMServerURL, secureOpt, grpc.WithBlock()); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	log.Debug("Connected to CM")

	ctx, client.cancel = context.WithCancel(context.Background())

	go client.run(ctx)

	return client, nil
}

// Close closes CM client.
func (client *CMClient) Close() {
	log.Debug("Close CM client")

	if client.cancel != nil {
		client.cancel()
	}

	if client.connection != nil {
		if err := client.connection.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (client *CMClient) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		default:
			err := client.registerStream()
			if err == nil {
				client.waitConnection.Add(2) // nolint:gomnd

				go client.receiveOutgoingMessages(ctx)
				go client.receiveIncomingMessages()

				client.waitConnection.Wait()
			} else {
				log.Errorf("Failed to register stream: %v", err)
			}

			log.Debugf("Reconnect to CM in %v...", cmReconnectTimeout)

			select {
			case <-ctx.Done():
				log.Debug("CM client is closed")

				return

			case <-time.After(cmReconnectTimeout):
			}
		}
	}
}

func (client *CMClient) receiveIncomingMessages() {
	defer client.waitConnection.Done()
	defer func() { client.connectionLostNotify <- struct{}{} }()

	if err := client.processMessages(); err != nil {
		if errors.Is(err, io.EOF) {
			log.Debug("Connection is closed")
		} else {
			log.Errorf("Connection error: %v", err)
		}
	}
}

func (client *CMClient) processMessages() (err error) {
	for {
		message, err := client.stream.Recv()
		if err != nil {
			if code, ok := status.FromError(err); ok && code.Code() == codes.Canceled {
				log.Debug("SM client connection closed")

				return nil
			}

			return aoserrors.Wrap(err)
		}

		data, err := proto.Marshal(message)
		if err != nil {
			log.Errorf("Failed to marshal message: %v", aoserrors.Wrap(err))

			continue
		}

		client.sendChan <- data
	}
}

func (client *CMClient) receiveOutgoingMessages(ctx context.Context) {
	defer client.waitConnection.Done()

	for _, outgoingMessage := range client.savedOutgoingMessages {
		err := client.stream.Send(outgoingMessage)
		if err != nil {
			log.Errorf("Failed to send outgoing message: %v", aoserrors.Wrap(err))

			return
		}

		client.savedOutgoingMessages = client.savedOutgoingMessages[1:]
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-client.connectionLostNotify:
			return

		case data, ok := <-client.recvChan:
			if !ok {
				return
			}

			outgoingMessage := &pb.SMOutgoingMessages{}

			err := proto.Unmarshal(data, outgoingMessage)
			if err != nil {
				log.Errorf("Failed to unmarshal outgoing message: %v", aoserrors.Wrap(err))

				continue
			}

			if err := client.stream.Send(outgoingMessage); err != nil {
				log.Errorf("Failed to send outgoing message: %v", aoserrors.Wrap(err))

				client.savedOutgoingMessages = append(client.savedOutgoingMessages, outgoingMessage)

				return
			}
		}
	}
}

func (client *CMClient) registerStream() (err error) {
	if client.stream, err = pb.NewSMServiceClient(client.connection).RegisterSM(context.Background()); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}
