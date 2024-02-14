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

//go:build test

// This file is used for successful build on the CI server.
// It is used instead of the vchan.go file.

package vchanmanager

import (
	"context"
	"crypto/tls"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type VChan struct{}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

func NewVChan(xsRxPath string, xsTxPath string, domain int, mTlsConfig *tls.Config) *VChan {
	return &VChan{}
}

func (v *VChan) Close() error {
	return nil
}

func (v *VChan) Connect(ctx context.Context, name string) error {
	return nil
}

func (v *VChan) ReadMessage() (Message, error) {
	return Message{}, nil
}

func (v *VChan) WriteMessage(msg Message) error {
	return nil
}

func (v *VChan) Disconnect() error {
	return nil
}
