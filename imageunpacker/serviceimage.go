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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
	"github.com/aoscloud/aos_common/image"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/sumdb/dirhash"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	blobsFolder      = "blobs"
	manifestFileName = "manifest.json"
	tmpRootFSDir     = "tmprootfs"
	buffSize         = 1024 * 1024
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// ImageParts struct with paths for image parts.
type ImageParts struct {
	ImageConfigPath   string
	ServiceConfigPath string
	ServiceFSPath     string
}

type serviceManifest struct {
	imagespec.Manifest
	AosService *imagespec.Descriptor `json:"aosService,omitempty"`
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

// DigestDirCb this is a callback uses for mock testing.
var DigestDirCb = dirDigest //nolint:gochecknoglobals

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (unpacker *ImageUnpacker) serviceUnpack(archivePath string) (string, error) {
	log.WithFields(log.Fields{
		"archivePath": archivePath,
	}).Debug("Unpacking service image")

	imagePath, err := unpacker.extractPackageByURL(archivePath)
	if err != nil {
		return "", err
	}

	if err := validateUnpackedImage(imagePath); err != nil {
		return "", aoserrors.Wrap(err)
	}

	rootFSDigest, err := unpacker.prepareServiceFS(imagePath)
	if err != nil {
		return "", err
	}

	if err = updateRootFSDigestInManifest(imagePath, rootFSDigest); err != nil {
		return "", err
	}

	log.WithFields(log.Fields{
		"imagePath": imagePath,
	}).Debug("Service image unpacked")

	return imagePath, nil
}

func validateUnpackedImage(installDir string) (err error) {
	manifest, err := getImageManifest(installDir)
	if err != nil {
		return err
	}

	if err = validateDigest(installDir, manifest.Config.Digest); err != nil {
		return err
	}

	if manifest.AosService != nil {
		if err = validateDigest(installDir, manifest.AosService.Digest); err != nil {
			return err
		}

		byteValue, err := os.ReadFile(path.Join(
			installDir, blobsFolder, string(manifest.AosService.Digest.Algorithm()), manifest.AosService.Digest.Hex()))
		if err != nil {
			return aoserrors.Wrap(err)
		}

		var tmpServiceConfig aostypes.ServiceConfig

		if err = json.Unmarshal(byteValue, &tmpServiceConfig); err != nil {
			return aoserrors.Errorf("invalid Aos service config: %v", err)
		}
	}

	rootfsPath := path.Join(
		installDir, blobsFolder, string(manifest.Layers[0].Digest.Algorithm()), manifest.Layers[0].Digest.Hex())

	fi, err := os.Stat(rootfsPath)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if !fi.Mode().IsDir() {
		return validateDigest(installDir, manifest.Layers[0].Digest)
	}

	rootfsHash, err := dirhash.HashDir(rootfsPath, rootfsPath, DigestDirCb)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if manifest.Layers[0].Digest.String() != rootfsHash {
		return aoserrors.New("incorrect rootfs checksum")
	}

	return nil
}

func validateDigest(installDir string, digest digest.Digest) (err error) {
	if err = digest.Validate(); err != nil {
		return aoserrors.Wrap(err)
	}

	file, err := os.Open(path.Join(installDir, blobsFolder, string(digest.Algorithm()), digest.Hex()))
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer file.Close()

	buffer := make([]byte, buffSize)
	verifier := digest.Verifier()

	for {
		count, readErr := file.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return aoserrors.Wrap(readErr)
		}

		if _, err := verifier.Write(buffer[:count]); err != nil {
			return aoserrors.Wrap(err)
		}

		if readErr != nil {
			break
		}
	}

	if !verifier.Verified() {
		return aoserrors.New("hash verification failed")
	}

	return nil
}

func updateRootFSDigestInManifest(installDir string, digest digest.Digest) (err error) {
	manifest, err := getImageManifest(installDir)
	if err != nil {
		return err
	}

	manifest.Layers[0].Digest = digest

	return saveImageManifest(manifest, installDir)
}

func saveImageManifest(manifest *serviceManifest, installDir string) (err error) {
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.WriteFile(path.Join(installDir, manifestFileName), manifestData, 0o600); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (unpacker *ImageUnpacker) prepareServiceFS(imagePath string) (rootFSDigest digest.Digest, err error) {
	imageParts, err := getImageParts(imagePath)
	if err != nil {
		return "", err
	}

	originRootFSPath := imageParts.ServiceFSPath
	tmpRootFS := filepath.Join(imagePath, tmpRootFSDir)

	if err = image.UnpackTarImage(imageParts.ServiceFSPath, tmpRootFS); err != nil {
		return "", aoserrors.Wrap(err)
	}

	if err = os.RemoveAll(imageParts.ServiceFSPath); err != nil {
		log.Errorf("Can't remove temp file: %s", err)
	}

	rootFSHash, err := dirhash.HashDir(tmpRootFS, tmpRootFS, DigestDirCb)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	if rootFSDigest, err = digest.Parse(rootFSHash); err != nil {
		return "", aoserrors.Wrap(err)
	}

	if err = os.Rename(tmpRootFS, filepath.Join(path.Dir(originRootFSPath), rootFSDigest.Hex())); err != nil {
		return "", aoserrors.Wrap(err)
	}

	return rootFSDigest, nil
}

func (unpacker *ImageUnpacker) extractPackageByURL(archivePath string) (imagePath string, err error) {
	imagePath, err = os.MkdirTemp(unpacker.imageStore, "")
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	if err = image.UnpackTarImage(archivePath, imagePath); err != nil {
		return "", aoserrors.Wrap(err)
	}

	return imagePath, nil
}

func getImageParts(installDir string) (parts ImageParts, err error) {
	manifest, err := getImageManifest(installDir)
	if err != nil {
		return parts, err
	}

	parts.ImageConfigPath = path.Join(installDir, blobsFolder, string(manifest.Config.Digest.Algorithm()),
		manifest.Config.Digest.Hex())

	if manifest.AosService != nil {
		parts.ServiceConfigPath = path.Join(installDir, blobsFolder, string(manifest.AosService.Digest.Algorithm()),
			manifest.AosService.Digest.Hex())
	}

	rootFSDigest := manifest.Layers[0].Digest
	parts.ServiceFSPath = path.Join(installDir, blobsFolder, string(rootFSDigest.Algorithm()), rootFSDigest.Hex())

	return parts, nil
}

func getImageManifest(installDir string) (*serviceManifest, error) {
	manifestJSON, err := os.ReadFile(path.Join(installDir, manifestFileName))
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	manifest := &serviceManifest{}

	if err = json.Unmarshal(manifestJSON, manifest); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return manifest, nil
}

func dirDigest(files []string, open func(string) (io.ReadCloser, error)) (string, error) {
	h := sha256.New()

	files = append([]string(nil), files...)

	sort.Strings(files)

	for _, file := range files {
		if strings.Contains(file, "\n") {
			return "", aoserrors.New("file names with new lines are not supported")
		}

		r, err := open(file)
		if err != nil {
			return "", err
		}

		hf := sha256.New()

		_, err = io.Copy(hf, r)

		r.Close()

		if err != nil {
			return "", aoserrors.Wrap(err)
		}

		fmt.Fprintf(h, "%x\n", hf.Sum(nil))
	}

	return digest.NewDigest("sha256", h).String(), nil
}
