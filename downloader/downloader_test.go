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

package downloader_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/downloader"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const Kilobyte = uint64(1 << 10)

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var (
	tmpDir      string
	serverDir   string
	downloadDir string
)

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

	if err = setup(); err != nil {
		log.Fatalf("Error setting up: %v", err)
	}

	ret := m.Run()

	if err = cleanup(); err != nil {
		log.Errorf("Error cleaning up: %v", err)
	}

	os.Exit(ret)
}

func TestDownload(t *testing.T) {
	if err := clearDirs(); err != nil {
		t.Fatalf("Can't clear dirs: %v", err)
	}

	fileName := path.Join(serverDir, "package.txt")

	if err := ioutil.WriteFile(fileName, []byte("Hello downloader\n"), 0o600); err != nil {
		t.Fatalf("Can't create package file: %v", err)
	}
	defer os.RemoveAll(fileName)

	downloadInstance, err := downloader.New(&config.Config{
		Downloader: config.Downloader{
			DownloadDir:            downloadDir,
			MaxConcurrentDownloads: 1,
		},
	})
	if err != nil {
		t.Fatalf("Can't create downloader: %v", err)
	}

	downloadedFile, err := downloadInstance.Download(context.Background(), "http://localhost:8001/package.txt")
	if err != nil {
		t.Fatalf("Can't download package: %s", err)
	}

	if downloadedFile != filepath.Join(downloadDir, "package.txt") {
		t.Fatalf("Wrong file name: %v", downloadedFile)
	}
}

func TestInterruptResumeDownload(t *testing.T) {
	if err := clearDirs(); err != nil {
		t.Fatalf("Can't clear dirs: %v", err)
	}

	if err := setWondershaperLimit("lo", "128"); err != nil {
		t.Fatalf("Can't set speed limit: %v", err)
	}

	defer clearWondershaperLimit("lo") // nolint:errcheck

	fileName := path.Join(serverDir, "package.txt")

	if err := generateFile(fileName, 512*Kilobyte); err != nil {
		t.Fatalf("Can't generate file: %v", err)
	}
	defer os.RemoveAll(fileName)

	killConnectionIn("localhost", 8001, 32*time.Second)

	downloadInstance, err := downloader.New(&config.Config{
		Downloader: config.Downloader{
			DownloadDir:            downloadDir,
			MaxConcurrentDownloads: 1,
		},
	})
	if err != nil {
		t.Fatalf("Can't create downloader: %v", err)
	}

	downloadedFile, err := downloadInstance.Download(context.Background(), "http://localhost:8001/package.txt")
	if err != nil {
		t.Fatalf("Can't download package: %s", err)
	}

	if downloadedFile != filepath.Join(downloadDir, "package.txt") {
		t.Fatalf("Wrong file name: %v", downloadedFile)
	}
}

func TestConcurrentDownloads(t *testing.T) {
	const (
		numDownloads    = 10
		fileNamePattern = "package%d.txt"
	)

	if err := clearDirs(); err != nil {
		t.Fatalf("Can't clear dirs: %v", err)
	}

	if err := setWondershaperLimit("lo", "1024"); err != nil {
		t.Fatalf("Can't set speed limit: %v", err)
	}

	defer clearWondershaperLimit("lo") // nolint:errcheck

	for i := 0; i < numDownloads; i++ {
		if err := generateFile(path.Join(serverDir, fmt.Sprintf(fileNamePattern, i)), 100*Kilobyte); err != nil {
			t.Fatalf("Can't generate file: %v", err)
		}
	}

	defer func() {
		for i := 0; i < numDownloads; i++ {
			os.RemoveAll(path.Join(serverDir, fmt.Sprintf(fileNamePattern, i)))
		}
	}()

	downloadInstance, err := downloader.New(&config.Config{
		Downloader: config.Downloader{
			DownloadDir:            downloadDir,
			MaxConcurrentDownloads: 5,
		},
	})
	if err != nil {
		t.Fatalf("Can't create downloader: %v", err)
	}

	wg := sync.WaitGroup{}

	for i := 0; i < numDownloads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			_, err := downloadInstance.Download(
				context.Background(), "http://localhost:8001/"+fmt.Sprintf(fileNamePattern, i))
			if err != nil {
				t.Errorf("Can't download package: %v", err)
			}
		}(i)
	}

	wg.Wait()
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func killConnectionIn(host string, port int16, delay time.Duration) {
	go func() {
		time.Sleep(delay)

		log.Debug("Kill connection")

		if _, err := exec.Command(
			"ss", "-K", "src", host, "dport", "=", strconv.Itoa(int(port))).CombinedOutput(); err != nil {
			log.Errorf("Can't kill connection: %v", err)
		}
	}()
}

func setWondershaperLimit(iface string, limit string) (err error) {
	if output, err := exec.Command("wondershaper", "-a", iface, "-d", limit).CombinedOutput(); err != nil {
		return aoserrors.Errorf("%v (%s)", err, (string(output)))
	}

	return nil
}

func generateFile(fileName string, size uint64) (err error) {
	if output, err := exec.Command("dd", "if=/dev/urandom", "of="+fileName, "bs=1",
		"count="+strconv.FormatUint(size, 10)).CombinedOutput(); err != nil {
		return aoserrors.Errorf("%v (%s)", err, (string(output)))
	}

	return nil
}

func clearDirs() error {
	if err := os.RemoveAll(downloadDir); err != nil {
		return aoserrors.Wrap(err)
	}

	if err := os.RemoveAll(serverDir); err != nil {
		return aoserrors.Wrap(err)
	}

	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func setup() (err error) {
	tmpDir, err = ioutil.TempDir("", "cm_")
	if err != nil {
		return aoserrors.Wrap(err)
	}

	downloadDir = filepath.Join(tmpDir, "download")
	serverDir = path.Join(tmpDir, "fileServer")

	if err = os.MkdirAll(serverDir, 0o755); err != nil {
		return aoserrors.Wrap(err)
	}

	go func() {
		log.Fatal(http.ListenAndServe(":8001", http.FileServer(http.Dir(serverDir))))
	}()

	time.Sleep(100 * time.Millisecond)

	return nil
}

func cleanup() (err error) {
	_ = clearWondershaperLimit("lo")

	if err = os.RemoveAll(tmpDir); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func clearWondershaperLimit(iface string) (err error) {
	if output, err := exec.Command("wondershaper", "-ca", iface).CombinedOutput(); err != nil {
		return aoserrors.Errorf("%v (%s)", err, (string(output)))
	}

	return nil
}
