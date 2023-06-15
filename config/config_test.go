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

package config_test

import (
	"io/ioutil"
	"log"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"

	"github.com/aoscloud/aos_messageproxy/config"
)

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var (
	testCfg *config.Config
	tmpDir  string
)

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		log.Fatalf("Error creating service images: %s", err)
	}

	ret := m.Run()

	cleanup()

	os.Exit(ret)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestGetCrypt(t *testing.T) {
	if testCfg.CertStorage != "proxy" {
		t.Errorf("Expected CertStorage to be proxy, got %s", testCfg.CertStorage)
	}

	if testCfg.CACert != "CACert" {
		t.Errorf("Expected CACert to be CACert, got %s", testCfg.CACert)
	}
}

func TestCMServer(t *testing.T) {
	if testCfg.CMServerURL != "aoscm:8093" {
		t.Errorf("Expected CMServerURL to be aoscm:8093, got %s", testCfg.CMServerURL)
	}
}

func TestGetIAMPublicServerURL(t *testing.T) {
	if testCfg.IAMPublicServerURL != "localhost:8090" {
		t.Errorf("Expected IAMPublicServerURL to be localhost:8090, got %s", testCfg.IAMPublicServerURL)
	}
}

func TestGetImageStoreDir(t *testing.T) {
	if testCfg.ImageStoreDir != "/var/aos/storage" {
		t.Errorf("Expected ImageStoreDir to be /var/aos/storage, got %s", testCfg.ImageStoreDir)
	}
}

func TestGetWorkingDir(t *testing.T) {
	if testCfg.WorkingDir != "workingDir" {
		t.Errorf("Expected WorkingDir to be workingDir, got %s", testCfg.WorkingDir)
	}
}

func TestGetXenConfig(t *testing.T) {
	if testCfg.VChan.XsRxPath != "xsPathRead" {
		t.Errorf("Expected XSPath to be xsPathRead, got %s", testCfg.VChan.XsRxPath)
	}

	if testCfg.VChan.Domain != 1 {
		t.Errorf("Expected Domain to be 1, got %d", testCfg.VChan.Domain)
	}

	if testCfg.VChan.XsTxPath != "xsPathWrite" {
		t.Errorf("Expected XSPath to be xsPathWrite, got %s", testCfg.VChan.XsTxPath)
	}
}

func TestGetDownloader(t *testing.T) {
	originalConfig := config.Downloader{
		DownloadDir:            "/path/to/download",
		MaxConcurrentDownloads: 10,
		RetryDelay:             aostypes.Duration{Duration: 10 * time.Second},
		MaxRetryDelay:          aostypes.Duration{Duration: 30 * time.Second},
	}

	if !reflect.DeepEqual(originalConfig, testCfg.Downloader) {
		t.Errorf("Wrong downloader config value: %v", testCfg.Downloader)
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func createConfigFile(fileName string) (err error) {
	configContent := `{
	"CACert": "CACert",	
	"certStorage": "proxy",
	"iamPublicServerUrl": "localhost:8090",
	"cmServerUrl": "aoscm:8093",
	"imageStoreDir": "/var/aos/storage",
	"workingDir" : "workingDir",
	"vchan": {
		"xsRxPath": "xsPathRead",
		"xsTxPath": "xsPathWrite",
		"domain": 1
	},
	"downloader": {
		"downloadDir": "/path/to/download",
		"maxConcurrentDownloads": 10,
		"retryDelay": "10s",
		"maxRetryDelay": "30s",
		"downloadPartLimit": 57
	}
}`

	if err := ioutil.WriteFile(fileName, []byte(configContent), 0o600); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func setup() (err error) {
	if tmpDir, err = ioutil.TempDir("", "aos_"); err != nil {
		return aoserrors.Wrap(err)
	}

	fileName := path.Join(tmpDir, "aos_proxy.cfg")

	if err = createConfigFile(fileName); err != nil {
		return aoserrors.Wrap(err)
	}

	if testCfg, err = config.New(fileName); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func cleanup() {
	os.RemoveAll(tmpDir)
}
