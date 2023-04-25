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

import "context"

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type VChan struct{}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

func NewVChan() *VChan {
	return &VChan{}
}

func (v *VChan) Init(domain int, xsPath string) error {
	return nil
}

func (v *VChan) Read(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (v *VChan) Write(data []byte) error {
	return nil
}

func (v *VChan) Close() {}
