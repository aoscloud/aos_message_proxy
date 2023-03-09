package vchan_test

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

	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/vchan"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/servicemanager/v3"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
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
	vch, err := vchan.New(&config.Config{
		XSPath: "domain/path",
		Domain: 0,
	}, &testDownloader{}, nil)
	if err != nil {
		t.Errorf("Can't create a new communication manager: %v", err)
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
	tmpDir, err := ioutil.TempDir("", "vchan_")
	if err != nil {
		t.Fatalf("Can't create a temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := path.Join(tmpDir, "package.txt")

	if err := generateFile(fileName, 1*Kilobyte); err != nil {
		t.Fatalf("Can't generate file: %v", err)
	}

	vch, err := vchan.New(&config.Config{
		XSPath: "domain/path",
		Domain: 0,
	}, &testDownloader{
		downloadedFile: fileName,
	}, &testUnpacker{
		filePath: tmpDir,
	})
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

	vch.GetSendingChannel() <- imageContentRequestRaw

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
			case recievedData := <-vch.GetReceivingChannel():
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
