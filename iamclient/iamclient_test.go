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

// Package config provides set of API to provide aos configuration

package iamclient_test

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/iamclient"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const publicServerURL = "localhost:8090"

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type testServer struct {
	pb.UnimplementedIAMPublicServiceServer
	pb.UnimplementedIAMPublicIdentityServiceServer

	publicServer *grpc.Server

	certURL map[string]string
	keyURL  map[string]string
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var tmpDir string

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
 * Main
 **********************************************************************************************************************/

func TestMain(m *testing.M) {
	var err error

	tmpDir, err = ioutil.TempDir("", "iam_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %v", err)
	}

	ret := m.Run()

	if err := os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error removing tmp dir: %v", err)
	}

	os.Exit(ret)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestGetCertificate(t *testing.T) {
	testServer, err := newTestServer(publicServerURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer testServer.close()

	client, err := iamclient.New(&config.Config{
		IAMPublicServerURL: publicServerURL,
	}, nil, true)
	if err != nil {
		t.Fatalf("Can't create IAM client: %v", err)
	}
	defer client.Close()

	testServer.certURL = map[string]string{"vchan1": "vchanCertURL", "vchan2": "vchanCertURL"}
	testServer.keyURL = map[string]string{"vchan1": "onlineKeyURL", "vchan2": "offlineKeyURL"}

	for _, certType := range []string{"vchan1", "vchan2"} {
		certURL, keyURL, err := client.GetCertificate(certType)
		if err != nil {
			t.Errorf("Can't get %s certificate: %v", certType, err)

			continue
		}

		if certURL != testServer.certURL[certType] {
			t.Errorf("Wrong %s cert URL: %s", certType, certURL)
		}

		if keyURL != testServer.keyURL[certType] {
			t.Errorf("Wrong %s key URL: %s", certType, keyURL)
		}
	}
}

/***********************************************************************************************************************
 * Interfaces
 **********************************************************************************************************************/

func (server *testServer) GetCert(
	context context.Context, req *pb.GetCertRequest,
) (rsp *pb.GetCertResponse, err error) {
	rsp = &pb.GetCertResponse{Type: req.Type}

	certURL, ok := server.certURL[req.Type]
	if !ok {
		return rsp, aoserrors.New("not found")
	}

	keyURL, ok := server.keyURL[req.Type]
	if !ok {
		return rsp, aoserrors.New("not found")
	}

	rsp.CertUrl = certURL
	rsp.KeyUrl = keyURL

	return rsp, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newTestServer(publicServerURL string) (*testServer, error) {
	server := &testServer{}

	publicListener, err := net.Listen("tcp", publicServerURL)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	server.publicServer = grpc.NewServer()

	pb.RegisterIAMPublicServiceServer(server.publicServer, server)
	pb.RegisterIAMPublicIdentityServiceServer(server.publicServer, server)

	go func() {
		if err := server.publicServer.Serve(publicListener); err != nil {
			log.Errorf("Can't serve grpc server: %v", err)
		}
	}()

	return server, nil
}

func (server *testServer) close() {
	if server.publicServer != nil {
		server.publicServer.Stop()
	}
}
