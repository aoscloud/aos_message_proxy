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

package filechunker

import (
	"crypto/sha256"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/servicemanager/v3"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const chunkSize = 1024 // 1kb

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type ContentInfo struct {
	*pb.ImageContentInfo
	ImageContent []*pb.ImageContent
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

func ChunkFile(rootDir string, requestID uint64) (ContentInfo, error) {
	imageContentInfo := ContentInfo{
		ImageContentInfo: &pb.ImageContentInfo{
			RequestId: requestID,
		},
	}

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return aoserrors.Wrap(err)
		}

		if info.IsDir() {
			return nil
		}

		imageFile, imageContents, err := prepareImageInfo(rootDir, path, requestID, info)
		if err != nil {
			return err
		}

		imageContentInfo.ImageFiles = append(imageContentInfo.ImageFiles, &imageFile)
		imageContentInfo.ImageContent = append(imageContentInfo.ImageContent, imageContents...)

		return nil
	})
	if err != nil {
		return imageContentInfo, err
	}

	return imageContentInfo, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func prepareImageInfo(
	rootDir, path string, requestID uint64, info os.FileInfo,
) (pb.ImageFile, []*pb.ImageContent, error) {
	file, err := os.Open(path)
	if err != nil {
		return pb.ImageFile{}, nil, aoserrors.Wrap(err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return pb.ImageFile{}, nil, aoserrors.Wrap(err)
	}

	if _, err := file.Seek(0, 0); err != nil {
		return pb.ImageFile{}, nil, aoserrors.Wrap(err)
	}

	partCounts := uint64(math.Ceil(float64(info.Size()) / float64(chunkSize)))

	relPath, err := filepath.Rel(rootDir, path)
	if err != nil {
		return pb.ImageFile{}, nil, aoserrors.Wrap(err)
	}

	imageContents, err := getChunkedFileContent(file, requestID, partCounts, relPath)
	if err != nil {
		return pb.ImageFile{}, nil, err
	}

	return pb.ImageFile{
		RelativePath: relPath,
		Sha256:       hash.Sum(nil),
		Size:         uint64(info.Size()),
	}, imageContents, nil
}

func getChunkedFileContent(
	file *os.File, requestID uint64, partCounts uint64, relPath string,
) (imageContents []*pb.ImageContent, err error) {
	var chunkNum uint64 = 1

	for {
		imageContent := &pb.ImageContent{
			RequestId:    requestID,
			RelativePath: relPath,
			PartsCount:   partCounts,
			Part:         chunkNum,
			Data:         make([]byte, chunkSize),
		}

		n, err := file.Read(imageContent.Data)
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		imageContent.Data = imageContent.Data[:n]

		imageContents = append(imageContents, imageContent)

		chunkNum++
	}

	return imageContents, nil
}
