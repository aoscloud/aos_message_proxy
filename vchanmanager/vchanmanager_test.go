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

package vchanmanager_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/servicemanager/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/vchanmanager"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const Kilobyte = uint64(1 << 10)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type testDownloader struct {
	downloadedFile string
}

type testUnpacker struct {
	filePath string
}

type testVChan struct {
	send chan []byte
	recv chan []byte
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

func TestReadWriteData(t *testing.T) {
	tVchan := &testVChan{
		send: make(chan []byte, 1),
		recv: make(chan []byte, 1),
	}
	vch, err := vchanmanager.New(&config.Config{
		VChan: config.VChanConfig{
			XsRxPath: "/tmp/xs_rx",
			XsTxPath: "/tmp/xs_tx",
			Domain:   1,
		},
	}, &testDownloader{}, nil, tVchan, tVchan)
	if err != nil {
		t.Errorf("Can't create a new vchannel manager: %v", err)
	}
	defer vch.Close()

	tCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Test 1",
			data: []byte("payload data"),
		},
		{
			name: "Test 2",
			data: []byte("payload data 2"),
		},
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			vch.GetSendingChannel() <- tCase.data

			select {
			case recievedData := <-tVchan.send:
				if string(recievedData) != string(tCase.data) {
					t.Errorf("Expected data: %s, recieved data: %s", tCase.data, recievedData)
				}

			case <-time.After(1 * time.Second):
				t.Errorf("Timeout")
			}
		})
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			tVchan.recv <- tCase.data

			select {
			case recievedData := <-vch.GetReceivingChannel():
				if string(recievedData) != string(tCase.data) {
					t.Errorf("Expected data: %s, recieved data: %s", tCase.data, recievedData)
				}

			case <-time.After(1 * time.Second):
				t.Errorf("Timeout")
			}
		})
	}
}

func TestDownload(t *testing.T) {
	tVchan := &testVChan{
		send: make(chan []byte, 1),
		recv: make(chan []byte, 1),
	}

	tmpDir, err := ioutil.TempDir("", "vchan_")
	if err != nil {
		t.Fatalf("Can't create a temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := path.Join(tmpDir, "package.txt")

	if err := generateFile(fileName, 1*Kilobyte); err != nil {
		t.Fatalf("Can't generate file: %v", err)
	}

	vch, err := vchanmanager.New(&config.Config{
		VChan: config.VChanConfig{
			XsRxPath: "/tmp/xs_rx",
			XsTxPath: "/tmp/xs_tx",
			Domain:   1,
		},
	}, &testDownloader{
		downloadedFile: fileName,
	}, &testUnpacker{
		filePath: tmpDir,
	}, tVchan, tVchan)
	if err != nil {
		t.Errorf("Can't create a new communication manager: %v", err)
	}
	defer vch.Close()

	file, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("Can't open file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatalf("Can't calculate hash: %v", err)
	}

	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("Can't seek file: %v", err)
	}

	data := make([]byte, 1*Kilobyte)

	if data, err = ioutil.ReadAll(file); err != nil {
		t.Fatalf("Can't read file: %v", err)
	}

	relPath, err := filepath.Rel(tmpDir, fileName)
	if err != nil {
		t.Fatalf("Can't get relative path: %v", err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		t.Fatalf("Can't get file info: %v", err)
	}

	imageContentRequest := &pb.SMOutgoingMessages{
		SMOutgoingMessage: &pb.SMOutgoingMessages_ImageContentRequest{
			ImageContentRequest: &pb.ImageContentRequest{
				RequestId:   1,
				ContentType: "service",
			},
		},
	}

	imageContentRequestRaw, err := proto.Marshal(imageContentRequest)
	if err != nil {
		t.Fatalf("Can't marshal data: %v", err)
	}

	tVchan.recv <- imageContentRequestRaw

	tCases := []struct {
		name string
		data *pb.SMIncomingMessages
	}{
		{
			name: "Test 1",
			data: &pb.SMIncomingMessages{
				SMIncomingMessage: &pb.SMIncomingMessages_ImageContentInfo{
					ImageContentInfo: &pb.ImageContentInfo{
						RequestId: 1,
						ImageFiles: []*pb.ImageFile{
							{
								RelativePath: relPath,
								Sha256:       hash.Sum(nil),
								Size:         uint64(fileInfo.Size()),
							},
						},
					},
				},
			},
		},
		{
			name: "Test 2",
			data: &pb.SMIncomingMessages{
				SMIncomingMessage: &pb.SMIncomingMessages_ImageContent{
					ImageContent: &pb.ImageContent{
						RequestId:    1,
						PartsCount:   1,
						RelativePath: relPath,
						Part:         1,
						Data:         data[:],
					},
				},
			},
		},
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			select {
			case recievedData := <-tVchan.send:
				data, err := proto.Marshal(tCase.data)
				if err != nil {
					t.Errorf("Can't marshal data: %v", err)
				}

				if !bytes.Equal(recievedData, data) {
					t.Error("Unexpected received data")
				}

			case <-time.After(6 * time.Second):
				t.Errorf("Timeout")
			}
		})
	}
}

/***********************************************************************************************************************
 * Interfaces
 **********************************************************************************************************************/

func (v *testVChan) Init(domain int, xsPath string) error {
	return nil
}

func (v *testVChan) Read() ([]byte, error) {
	return <-v.recv, nil
}

func (v *testVChan) Write(data []byte) error {
	v.send <- data

	return nil
}

func (v *testVChan) Close() {
}

func (td *testDownloader) Download(
	ctx context.Context, url string,
) (fileName string, err error) {
	return td.downloadedFile, nil
}

func (tu *testUnpacker) Unpack(archivePath string, contentType string) (string, error) {
	return tu.filePath, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func generateFile(fileName string, size uint64) (err error) {
	if output, err := exec.Command("dd", "if=/dev/urandom", "of="+fileName, "bs=1",
		"count="+strconv.FormatUint(size, 10)).CombinedOutput(); err != nil {
		return aoserrors.Errorf("%v (%s)", err, (string(output)))
	}

	return nil
}
