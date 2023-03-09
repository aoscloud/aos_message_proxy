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

package imageunpacker_test

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/imageunpacker"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/fs"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const blobsFolder = "blobs"

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var tmpDir string

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
***********************************************************************************************************************/

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		log.Fatalf("Error setting up: %s", err)
	}

	ret := m.Run()

	cleanup()

	os.Exit(ret)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestServiceUnpack(t *testing.T) {
	imageunpacker.DigestDirCb = dirDigestGenerate

	archivePath, aosSrvConfigDigest, err := prepareService()
	if err != nil {
		t.Fatalf("Error prepare service: %v", err)
	}
	defer os.Remove(archivePath)

	unpacker, err := imageunpacker.New(&config.Config{
		ImageStoreDir: filepath.Join(tmpDir, "image_store"),
	})
	if err != nil {
		t.Fatalf("Error creating unpacker: %v", err)
	}

	pathUnpack, err := unpacker.Unpack(archivePath, "service")
	if err != nil {
		t.Fatalf("Error unpacking service: %v", err)
	}

	expectedFiles := []string{
		"blobs/sha256/38acb15d02d5ac0f2a2789602e9df950c380d2799b4bdb59394e4eeabdd3a662/home/service.py",
		filepath.Join("blobs/sha256/", aosSrvConfigDigest.Hex()),
		"manifest.json",
	}

	var unpackedFiles []string

	if err := filepath.Walk(pathUnpack, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(pathUnpack, path)
		if err != nil {
			return nil
		}

		unpackedFiles = append(unpackedFiles, relPath)

		return nil
	}); err != nil {
		t.Errorf("Error walking unpacked service: %v", err)
	}

	if !reflect.DeepEqual(expectedFiles, unpackedFiles) {
		t.Errorf("Unpacked files are not equal to expected: %v", unpackedFiles)
	}
}

/***********************************************************************************************************************
* Private
***********************************************************************************************************************/

func dirDigestGenerate(files []string, open func(string) (io.ReadCloser, error)) (string, error) {
	return "sha256:38acb15d02d5ac0f2a2789602e9df950c380d2799b4bdb59394e4eeabdd3a662", nil
}

func prepareService() (string, digest.Digest, error) {
	imageDir, err := ioutil.TempDir("", "aos_")
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	defer os.RemoveAll(imageDir)

	if err := os.MkdirAll(filepath.Join(imageDir, "rootfs", "home"), 0o755); err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	if _, err := os.Create(filepath.Join(imageDir, "rootfs", "home", "service.py")); err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	rootFsPath := filepath.Join(imageDir, "rootfs")

	serviceSize, err := fs.GetDirSize(rootFsPath)
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	fsDigest, err := generateFsLayer(imageDir, rootFsPath)
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	aosSrvConfigDigest, err := generateAndSaveDigest(filepath.Join(imageDir, blobsFolder), []byte("{}"))
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	if err := genarateImageManfest(
		imageDir, &aosSrvConfigDigest, &fsDigest,
		serviceSize); err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	imageFile, err := ioutil.TempFile("", "aos_")
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	archivePath := imageFile.Name()
	imageFile.Close()

	if err = packImage(imageDir, archivePath); err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	return archivePath, aosSrvConfigDigest, nil
}

func packImage(source, name string) (err error) {
	log.WithFields(log.Fields{"source": source, "name": name}).Debug("Pack image")

	if output, err := exec.Command("tar", "-C", source, "-cf", name, "./").CombinedOutput(); err != nil {
		return aoserrors.Errorf("tar error: %s, code: %s", string(output), err)
	}

	return nil
}

func generateAndSaveDigest(folder string, data []byte) (retDigest digest.Digest, err error) {
	fullPath := filepath.Join(folder, "sha256")
	if err := os.MkdirAll(fullPath, 0o755); err != nil {
		return retDigest, aoserrors.Wrap(err)
	}

	h := sha256.New()
	h.Write(data)
	retDigest = digest.NewDigest("sha256", h)

	file, err := os.Create(filepath.Join(fullPath, retDigest.Hex()))
	if err != nil {
		return retDigest, aoserrors.Wrap(err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return retDigest, aoserrors.Wrap(err)
	}

	return retDigest, nil
}

func generateFsLayer(imgFolder, rootfs string) (digest digest.Digest, err error) {
	blobsDir := filepath.Join(imgFolder, blobsFolder)
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		return digest, aoserrors.Wrap(err)
	}

	tarFile := filepath.Join(blobsDir, "_temp.tar.gz")

	if output, err := exec.Command("tar", "-C", rootfs, "-czf", tarFile, "./").CombinedOutput(); err != nil {
		return digest, aoserrors.Errorf("error: %s, code: %s", string(output), err)
	}
	defer os.Remove(tarFile)

	file, err := os.Open(tarFile)
	if err != nil {
		return digest, aoserrors.Wrap(err)
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return digest, aoserrors.Wrap(err)
	}

	digest, err = generateAndSaveDigest(blobsDir, byteValue)
	if err != nil {
		return digest, aoserrors.Wrap(err)
	}

	os.RemoveAll(rootfs)

	return digest, nil
}

func genarateImageManfest(folderPath string, imgConfig, rootfsLayer *digest.Digest,
	rootfsLayerSize int64,
) (err error) {
	type serviceManifest struct {
		imagespec.Manifest
		AosService *imagespec.Descriptor `json:"aosService,omitempty"`
	}

	var manifest serviceManifest
	manifest.SchemaVersion = 2

	manifest.Config = imagespec.Descriptor{
		MediaType: "application/vnd.oci.image.config.v1+json",
		Digest:    *imgConfig,
	}

	layerDescriptor := imagespec.Descriptor{
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
		Digest:    *rootfsLayer,
		Size:      rootfsLayerSize,
	}

	manifest.Layers = append(manifest.Layers, layerDescriptor)

	data, err := json.Marshal(manifest)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	jsonFile, err := os.Create(filepath.Join(folderPath, "manifest.json"))
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if _, err := jsonFile.Write(data); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func setup() (err error) {
	if tmpDir, err = ioutil.TempDir("", "aos_"); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func cleanup() {
	os.RemoveAll(tmpDir)
}
