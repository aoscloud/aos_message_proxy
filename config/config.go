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

package config

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Downloader download configuration.
type Downloader struct {
	DownloadDir            string            `json:"downloadDir"`
	MaxConcurrentDownloads int               `json:"maxConcurrentDownloads"`
	RetryDelay             aostypes.Duration `json:"retryDelay"`
	MaxRetryDelay          aostypes.Duration `json:"maxRetryDelay"`
}

// Config instance.
type Config struct {
	WorkingDir         string     `json:"workingDir"`
	XSPath             string     `json:"xsPath"`
	Domain             int        `json:"domain"`
	IAMPublicServerURL string     `json:"iamPublicServerURL"`
	CMServerURL        string     `json:"cmServerURL"`
	CertStorage        string     `json:"certStorage"`
	CACert             string     `json:"caCert"`
	ImageStoreDir      string     `json:"imageStoreDir"`
	Downloader         Downloader `json:"downloader"`
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new Config instance.
func New(fileName string) (*Config, error) {
	rawConfig, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	cfg := &Config{
		Downloader: Downloader{
			MaxConcurrentDownloads: 4,
			RetryDelay:             aostypes.Duration{Duration: 1 * time.Minute},
			MaxRetryDelay:          aostypes.Duration{Duration: 30 * time.Minute},
		},
	}

	if err = json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if cfg.Downloader.DownloadDir == "" {
		cfg.Downloader.DownloadDir = path.Join(cfg.WorkingDir, "download")
	}

	if cfg.ImageStoreDir == "" {
		cfg.ImageStoreDir = path.Join(cfg.WorkingDir, "image_store")
	}

	return cfg, nil
}
