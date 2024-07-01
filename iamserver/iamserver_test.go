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

package iamserver_test

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aosedge/aos_common/aoserrors"
	pb "github.com/aosedge/aos_common/api/iamanager/v4"
	"github.com/aosedge/aos_messageproxy/config"
	"github.com/aosedge/aos_messageproxy/iamserver"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	iamServerURL = "localhost:8089"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type testCertHandler struct {
	certTypes []string
	subject   string
	csr       []byte
	certURL   string
	password  string
	serial    string
	err       error
	ids       []string
}

type testClient struct {
	connection *grpc.ClientConn
}

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestProvisioningService(t *testing.T) {
	certHandler := &testCertHandler{}

	tmpDir, err := os.MkdirTemp("", "iam_")
	if err != nil {
		log.Fatalf("Error creating temporary dir: %v", err)
	}

	defer os.RemoveAll(tmpDir)

	server, err := iamserver.New(&config.Config{
		IAMConfig: config.IAMConfig{
			IAMServerURL: iamServerURL,
		},
	},
		nil, certHandler, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(iamServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	provisioningService := pb.NewIAMProvisioningServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetAllNodeIDs

	certHandler.ids = []string{"test1", "test2", "test3"}

	idsResponse, err := provisioningService.GetAllNodeIDs(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if !reflect.DeepEqual(idsResponse.GetIds(), certHandler.ids) {
		t.Errorf("Wrong node IDs: %v", idsResponse.GetIds())
	}

	// GetCertTypes

	certHandler.certTypes = []string{"test1", "test2", "test3"}

	certTypesResponse, err := provisioningService.GetCertTypes(ctx, &pb.GetCertTypesRequest{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if !reflect.DeepEqual(certTypesResponse.GetTypes(), certHandler.certTypes) {
		t.Errorf("Wrong cert types: %v", certTypesResponse.GetTypes())
	}

	// SetOwner

	password := "password"

	setOwnerReq := &pb.SetOwnerRequest{Type: "online", Password: password}

	if _, err = provisioningService.SetOwner(ctx, setOwnerReq); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certHandler.password != password {
		t.Errorf("Wrong password: %s", certHandler.password)
	}

	// Clear

	clearReq := &pb.ClearRequest{Type: "online"}

	if _, err = provisioningService.Clear(ctx, clearReq); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certHandler.password != "" {
		t.Errorf("Wrong password: %s", certHandler.password)
	}

	// EncryptDisk

	if _, err = provisioningService.EncryptDisk(ctx, &pb.EncryptDiskRequest{Password: password}); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	// FinishProvisioning

	if _, err = provisioningService.FinishProvisioning(ctx, &empty.Empty{}); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}
}

func TestCertificateService(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{
		IAMConfig: config.IAMConfig{
			IAMServerURL: iamServerURL,
		},
	},
		nil, certHandler, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(iamServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	certificateService := pb.NewIAMCertificateServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// CreateKey

	certHandler.csr = []byte("this is csr")

	createKeyRequest := &pb.CreateKeyRequest{Type: "online"}

	createKeyResponse, err := certificateService.CreateKey(ctx, createKeyRequest)
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if createKeyResponse.GetType() != createKeyRequest.GetType() {
		t.Errorf("Wrong response type: %s", createKeyResponse.GetType())
	}

	if createKeyResponse.GetCsr() != string(certHandler.csr) {
		t.Errorf("Wrong CSR value: %s", createKeyResponse.GetCsr())
	}

	// ApplyCertificate

	certificateRequest := &pb.ApplyCertRequest{Type: "online"}

	certificateResponse, err := certificateService.ApplyCert(ctx, certificateRequest)
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certificateResponse.GetType() != certificateRequest.GetType() {
		t.Errorf("Wrong response type: %s", certificateResponse.GetType())
	}

	if certificateResponse.GetCertUrl() != certHandler.certURL {
		t.Errorf("Wrong cert URL: %s", certificateResponse.GetCertUrl())
	}
}

/***********************************************************************************************************************
 * Interfaces
 **********************************************************************************************************************/

func (handler *testCertHandler) CreateKey(
	context context.Context, req *pb.CreateKeyRequest,
) (*pb.CreateKeyResponse, error) {
	handler.subject = req.GetSubject()

	return &pb.CreateKeyResponse{Csr: string(handler.csr), Type: req.GetType()}, handler.err
}

func (handler *testCertHandler) ApplyCert(
	context context.Context, req *pb.ApplyCertRequest,
) (*pb.ApplyCertResponse, error) {
	return &pb.ApplyCertResponse{CertUrl: handler.certURL, Serial: handler.serial, Type: req.GetType()}, handler.err
}

func (handler *testCertHandler) GetCertTypes(
	context context.Context, req *pb.GetCertTypesRequest,
) (*pb.CertTypes, error) {
	return &pb.CertTypes{Types: handler.certTypes}, nil
}

func (handler *testCertHandler) GetAllNodeIDs(context context.Context, req *empty.Empty) (*pb.NodesID, error) {
	return &pb.NodesID{
		Ids: handler.ids,
	}, nil
}

func (handler *testCertHandler) SetOwner(context context.Context, req *pb.SetOwnerRequest) (*empty.Empty, error) {
	handler.password = req.GetPassword()

	return &empty.Empty{}, nil
}

func (handler *testCertHandler) Clear(context context.Context, req *pb.ClearRequest) (*empty.Empty, error) {
	handler.password = ""

	return &empty.Empty{}, nil
}

func (handler *testCertHandler) EncryptDisk(ctx context.Context, req *pb.EncryptDiskRequest) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (handler *testCertHandler) FinishProvisioning(context context.Context, req *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newTestClient(url string) (client *testClient, err error) {
	client = &testClient{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if client.connection, err = grpc.DialContext(
		ctx, url, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return client, nil
}

func (client *testClient) close() {
	if client.connection != nil {
		client.connection.Close()
	}
}
