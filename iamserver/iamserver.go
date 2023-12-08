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

package iamserver

import (
	"context"
	"net"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/iamclient"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// CertHandlerItf certificate handler interface.
type CertHandlerItf interface {
	GetAllNodeIDs(context context.Context, req *empty.Empty) (rsp *pb.NodesID, err error)
	CreateKey(context context.Context, req *pb.CreateKeyRequest) (*pb.CreateKeyResponse, error)
	ApplyCert(context context.Context, req *pb.ApplyCertRequest) (*pb.ApplyCertResponse, error)
	GetCertTypes(context context.Context, req *pb.GetCertTypesRequest) (*pb.CertTypes, error)
	SetOwner(context context.Context, req *pb.SetOwnerRequest) (*empty.Empty, error)
	Clear(context context.Context, req *pb.ClearRequest) (*empty.Empty, error)
	EncryptDisk(ctx context.Context, req *pb.EncryptDiskRequest) (*empty.Empty, error)
	FinishProvisioning(context context.Context, req *empty.Empty) (*empty.Empty, error)
}

// Server IAM server instance.
type Server struct {
	pb.UnimplementedIAMProvisioningServiceServer
	pb.UnimplementedIAMCertificateServiceServer

	listener      net.Listener
	grpcServer    *grpc.Server
	cryptoContext *cryptutils.CryptoContext
	certHandler   CertHandlerItf
	certProvider  iamclient.CertificateProvider
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new IAM server instance.
func New(
	cfg *config.Config, cryptoContext *cryptutils.CryptoContext, certHandler CertHandlerItf,
	certProvider iamclient.CertificateProvider, provisioningMode bool,
) (server *Server, err error) {
	server = &Server{
		cryptoContext: cryptoContext,
		certHandler:   certHandler,
		certProvider:  certProvider,
	}

	defer func() {
		if err != nil {
			server.Close()
		}
	}()

	var opts []grpc.ServerOption

	if !provisioningMode {
		mTLSConfig, err := server.certProvider.GetServerMutualTLSConfig(cfg.IAMConfig.CertStorage)
		if err != nil {
			return server, aoserrors.Wrap(err)
		}

		opts = append(opts, grpc.Creds(credentials.NewTLS(mTLSConfig)))
	}

	if err = server.createServer(cfg.IAMConfig.IAMServerURL, provisioningMode, opts...); err != nil {
		return server, err
	}

	return server, nil
}

// Close closes IAM server instance.
func (server *Server) Close() (err error) {
	return server.closeServer()
}

// CreateKey creates private key.
func (server *Server) CreateKey(context context.Context, req *pb.CreateKeyRequest) (
	rsp *pb.CreateKeyResponse, err error,
) {
	log.WithFields(log.Fields{
		"type": req.GetType(), "nodeID": req.GetNodeId(), "subject": req.GetSubject(),
	}).Debug("Process create key request")

	rsp, err = server.certHandler.CreateKey(context, req)

	return rsp, aoserrors.Wrap(err)
}

// ApplyCert applies certificate.
func (server *Server) ApplyCert(
	context context.Context, req *pb.ApplyCertRequest,
) (rsp *pb.ApplyCertResponse, err error) {
	log.WithFields(log.Fields{"type": req.GetType(), "nodeID": req.GetNodeId()}).Debug("Process apply cert request")

	rsp, err = server.certHandler.ApplyCert(context, req)

	return rsp, aoserrors.Wrap(err)
}

// GetAllNodeIDs returns all known node IDs.
func (server *Server) GetAllNodeIDs(context context.Context,
	req *empty.Empty,
) (rsp *pb.NodesID, err error) {
	log.Debug("Process get all node IDs")

	rsp, err = server.certHandler.GetAllNodeIDs(context, req)

	return rsp, aoserrors.Wrap(err)
}

// GetCertTypes returns all IAM cert types.
func (server *Server) GetCertTypes(context context.Context,
	req *pb.GetCertTypesRequest,
) (rsp *pb.CertTypes, err error) {
	log.WithField("nodeID", req.GetNodeId()).Debug("Process get cert types")

	rsp, err = server.certHandler.GetCertTypes(context, req)

	return rsp, aoserrors.Wrap(err)
}

// SetOwner makes IAM owner of secure storage.
func (server *Server) SetOwner(context context.Context, req *pb.SetOwnerRequest) (rsp *empty.Empty, err error) {
	log.WithFields(log.Fields{"type": req.GetType(), "nodeID": req.GetNodeId()}).Debug("Process set owner request")

	rsp, err = server.certHandler.SetOwner(context, req)

	return rsp, aoserrors.Wrap(err)
}

// Clear clears certificates and keys storages.
func (server *Server) Clear(context context.Context, req *pb.ClearRequest) (rsp *empty.Empty, err error) {
	log.WithFields(log.Fields{"type": req.GetType(), "nodeID": req.GetNodeId()}).Debug("Process clear request")

	rsp, err = server.certHandler.Clear(context, req)

	return rsp, aoserrors.Wrap(err)
}

// EncryptDisk perform disk encryption.
func (server *Server) EncryptDisk(ctx context.Context, req *pb.EncryptDiskRequest) (rsp *empty.Empty, err error) {
	log.WithFields(log.Fields{"nodeID": req.GetNodeId()}).Debug("Process encrypt disk request")

	rsp, err = server.certHandler.EncryptDisk(ctx, req)

	return rsp, aoserrors.Wrap(err)
}

// FinishProvisioning notifies IAM that provisioning is finished.
func (server *Server) FinishProvisioning(context context.Context, req *empty.Empty) (rsp *empty.Empty, err error) {
	log.Debug("Process finish provisioning request")

	rsp, err = server.certHandler.FinishProvisioning(context, req)

	return rsp, aoserrors.Wrap(err)
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (server *Server) createServer(url string, provisioningMode bool, opts ...grpc.ServerOption) (err error) {
	log.WithField("url", url).Debug("Create IAM server")

	if server.listener, err = net.Listen("tcp", url); err != nil {
		return aoserrors.Wrap(err)
	}

	server.grpcServer = grpc.NewServer(opts...)

	pb.RegisterIAMCertificateServiceServer(server.grpcServer, server)

	if provisioningMode {
		pb.RegisterIAMProvisioningServiceServer(server.grpcServer, server)
	}

	go func() {
		if err := server.grpcServer.Serve(server.listener); err != nil {
			log.Errorf("Can't serve grpc server: %s", err)
		}
	}()

	return nil
}

func (server *Server) closeServer() (err error) {
	log.Debug("Close IAM server")

	if server.grpcServer != nil {
		server.grpcServer.Stop()
	}

	if server.listener != nil {
		if listenerErr := server.listener.Close(); listenerErr != nil {
			if err == nil {
				err = listenerErr
			}
		}
	}

	return aoserrors.Wrap(err)
}
