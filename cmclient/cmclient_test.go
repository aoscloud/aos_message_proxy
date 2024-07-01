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

package cmclient_test

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/aosedge/aos_common/aoserrors"
	pb "github.com/aosedge/aos_common/api/servicemanager/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/aosedge/aos_messageproxy/cmclient"
	"github.com/aosedge/aos_messageproxy/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const serverURL = "localhost:8093"

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type testServer struct {
	grpcServer *grpc.Server
	stream     pb.SMService_RegisterSMServer
	pb.UnimplementedSMServiceServer
	registerChannel chan struct{}
	outgoingChannel chan *pb.SMOutgoingMessages
}

type MessageHandlerTest struct {
	receiver chan []byte
	sender   chan []byte
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

func TestOutgoingMessages(t *testing.T) {
	defer func() {
		time.Sleep(1 * time.Second)
	}()

	server, err := newTestServer(serverURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}

	defer server.close()

	receiver := make(chan []byte, 1)
	sender := make(chan []byte, 1)

	msgHandler := &MessageHandlerTest{
		receiver: receiver,
		sender:   sender,
	}

	client, err := cmclient.New(&config.Config{CMServerURL: serverURL}, nil, nil, msgHandler, true)
	if err != nil {
		t.Fatalf("Can't create UM client: %v", err)
	}
	defer client.Close()

	tCases := []struct {
		name string
		data *pb.SMOutgoingMessages
	}{
		{
			name: "NodeConfiguration message",
			data: &pb.SMOutgoingMessages{
				SMOutgoingMessage: &pb.SMOutgoingMessages_NodeConfiguration{
					NodeConfiguration: &pb.NodeConfiguration{
						NodeId: "zephyr", NodeType: "model1", RemoteNode: false, RunnerFeatures: []string{"crun"},
					},
				},
			},
		},
		{
			name: "UnitConfigStatus message",
			data: &pb.SMOutgoingMessages{
				SMOutgoingMessage: &pb.SMOutgoingMessages_UnitConfigStatus{
					UnitConfigStatus: &pb.UnitConfigStatus{
						VendorVersion: "1.0.0",
					},
				},
			},
		},
		{
			name: "NodeMonitoring message 1",
			data: &pb.SMOutgoingMessages{
				SMOutgoingMessage: &pb.SMOutgoingMessages_NodeMonitoring{
					NodeMonitoring: &pb.NodeMonitoring{
						MonitoringData: &pb.MonitoringData{
							Cpu: 30, Ram: 100, InTraffic: 100, OutTraffic: 100,
						},
					},
				},
			},
		},
		{
			name: "NodeMonitoring message 2",
			data: &pb.SMOutgoingMessages{
				SMOutgoingMessage: &pb.SMOutgoingMessages_NodeMonitoring{
					NodeMonitoring: &pb.NodeMonitoring{
						MonitoringData: &pb.MonitoringData{
							Cpu: 60, Ram: 10000, InTraffic: 1000, OutTraffic: 1000,
						},
					},
				},
			},
		},
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			data, err := proto.Marshal(tCase.data)
			if err != nil {
				t.Fatalf("Can't marshal message: %v", err)
			}

			receiver <- data

			select {
			case message := <-server.outgoingChannel:
				if !proto.Equal(message, tCase.data) {
					t.Fatalf("Received message is not equal to expected one")
				}

			case <-time.After(5 * time.Second):
				t.Fatalf("Timeout waiting for message")
			}
		})
	}
}

func TestIncomingMessages(t *testing.T) {
	defer func() {
		time.Sleep(1 * time.Second)
	}()

	server, err := newTestServer(serverURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}

	defer server.close()

	receiver := make(chan []byte, 1)
	sender := make(chan []byte, 1)

	msgHandler := &MessageHandlerTest{
		receiver: receiver,
		sender:   sender,
	}

	client, err := cmclient.New(&config.Config{CMServerURL: serverURL}, nil, nil, msgHandler, true)
	if err != nil {
		t.Fatalf("Can't create UM client: %v", err)
	}
	defer client.Close()

	select {
	case <-server.registerChannel:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timeout waiting for registration message")
	}

	tCases := []struct {
		name string
		data *pb.SMIncomingMessages
	}{
		{
			name: "SetUnitConfig message",
			data: &pb.SMIncomingMessages{
				SMIncomingMessage: &pb.SMIncomingMessages_SetUnitConfig{
					SetUnitConfig: &pb.SetUnitConfig{
						UnitConfig:    "unit config",
						VendorVersion: "1.0.0",
					},
				},
			},
		},
		{
			name: "ConnectionStatus message",
			data: &pb.SMIncomingMessages{
				SMIncomingMessage: &pb.SMIncomingMessages_ConnectionStatus{
					ConnectionStatus: &pb.ConnectionStatus{
						CloudStatus: pb.ConnectionEnum_CONNECTED,
					},
				},
			},
		},
		{
			name: "RunInstances message 1",
			data: &pb.SMIncomingMessages{
				SMIncomingMessage: &pb.SMIncomingMessages_RunInstances{
					RunInstances: &pb.RunInstances{
						Services: []*pb.ServiceInfo{
							{
								ServiceId:  "service1",
								ProviderId: "provider1",
								Url:        "http://localhost:8080",
								Gid:        1000,
							},
						},
					},
				},
			},
		},
		{
			name: "RunInstances message 2",
			data: &pb.SMIncomingMessages{
				SMIncomingMessage: &pb.SMIncomingMessages_RunInstances{
					RunInstances: &pb.RunInstances{
						Services: []*pb.ServiceInfo{
							{
								ServiceId:  "service2",
								ProviderId: "provider2",
								Url:        "http://localhost:8080",
								Gid:        1001,
							},
						},
					},
				},
			},
		},
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			if err := server.stream.Send(tCase.data); err != nil {
				t.Fatalf("Can't send message: %v", err)
			}

			select {
			case data := <-sender:
				message := &pb.SMIncomingMessages{}
				if err := proto.Unmarshal(data, message); err != nil {
					t.Fatalf("Can't unmarshal message: %v", err)
				}

				if !proto.Equal(message, tCase.data) {
					t.Fatalf("Received message is not equal to expected one")
				}

			case <-time.After(5 * time.Second):
				t.Fatalf("Timeout waiting for message")
			}
		})
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newTestServer(url string) (server *testServer, err error) {
	server = &testServer{
		registerChannel: make(chan struct{}, 1),
		outgoingChannel: make(chan *pb.SMOutgoingMessages),
	}

	listener, err := net.Listen("tcp", url)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	server.grpcServer = grpc.NewServer()

	pb.RegisterSMServiceServer(server.grpcServer, server)

	go func() {
		if err := server.grpcServer.Serve(listener); err != nil {
			log.Errorf("Can't serve grpc server: %v", err)
		}
	}()

	return server, nil
}

func (server *testServer) RegisterSM(stream pb.SMService_RegisterSMServer) error {
	server.stream = stream
	server.registerChannel <- struct{}{}

	for {
		message, err := server.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return aoserrors.Wrap(err)
		}

		server.outgoingChannel <- message
	}
}

func (server *testServer) close() {
	if server.grpcServer != nil {
		server.grpcServer.Stop()
	}
}

func (handler *MessageHandlerTest) ReceiveSMMessage() <-chan []byte {
	return handler.receiver
}

func (handler *MessageHandlerTest) SendSMMessage(data []byte) error {
	handler.sender <- data

	return nil
}
