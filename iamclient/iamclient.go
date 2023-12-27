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

package iamclient

import (
	"context"
	"sync"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aoscloud/aos_messageproxy/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const iamRequestTimeout = 30 * time.Second

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Client IAM client instance.
type Client struct {
	sync.Mutex

	publicService    pb.IAMPublicServiceClient
	publicConnection *grpc.ClientConn
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new IAM client.
func New(
	config *config.Config, cryptcoxontext *cryptutils.CryptoContext, insecureConn bool,
) (client *Client, err error) {
	log.Debug("Connecting to IAM...")

	client = &Client{}

	defer func() {
		if err != nil {
			client.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), iamRequestTimeout)
	defer cancel()

	securePublicOpt := grpc.WithTransportCredentials(insecure.NewCredentials())

	if !insecureConn {
		tlsConfig, err := cryptcoxontext.GetClientTLSConfig()
		if err != nil {
			return client, aoserrors.Wrap(err)
		}

		securePublicOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	}

	if client.publicConnection, err = grpc.DialContext(
		ctx, config.IAMPublicServerURL, securePublicOpt, grpc.WithBlock()); err != nil {
		return client, aoserrors.Wrap(err)
	}

	client.publicService = pb.NewIAMPublicServiceClient(client.publicConnection)

	log.Debug("Connected to IAM")

	return client, nil
}

// Close closes IAM client.
func (client *Client) Close() {
	if client.publicConnection != nil {
		client.publicConnection.Close()
	}

	log.Debug("Disconnected from IAM")
}

// GetCertificate gets certificate and key url from IAM by type.
func (client *Client) GetCertificate(certType string) (certURL, keyURL string, err error) {
	log.WithFields(log.Fields{
		"type": certType,
	}).Debug("Get certificate")

	ctx, cancel := context.WithTimeout(context.Background(), iamRequestTimeout)
	defer cancel()

	response, err := client.publicService.GetCert(
		ctx, &pb.GetCertRequest{Type: certType})
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"certURL": response.GetCertUrl(), "keyURL": response.GetKeyUrl(),
	}).Debug("Certificate info")

	return response.GetCertUrl(), response.GetKeyUrl(), nil
}
