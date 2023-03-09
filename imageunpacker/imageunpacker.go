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

package imageunpacker

import (
	"os"

	"github.com/aoscloud/aos_common/aoserrors"

	"github.com/aoscloud/aos_messageproxy/config"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// ImageUnpacker instance.
type ImageUnpacker struct {
	imageStore    string
	contentUnpack map[string]func(string) (string, error)
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new ImageUnpacker instance.
func New(cfg *config.Config) (*ImageUnpacker, error) {
	if err := os.MkdirAll(cfg.ImageStoreDir, 0o755); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	imageUnpacker := &ImageUnpacker{
		imageStore: cfg.ImageStoreDir,
	}

	imageUnpacker.contentUnpack = map[string]func(string) (string, error){
		"service": imageUnpacker.serviceUnpack,
	}

	return imageUnpacker, nil
}

// Unpack unpacks image content.
func (unpacker *ImageUnpacker) Unpack(archivePath string, contentType string) (string, error) {
	// TODO: implement handling content type
	unpackerFunc, ok := unpacker.contentUnpack[contentType]
	if !ok {
		return "", aoserrors.Errorf("Unsupported content type: %s", contentType)
	}

	return unpackerFunc(archivePath)
}
