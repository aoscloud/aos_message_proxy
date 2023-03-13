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

package downloader

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/action"
	"github.com/aoscloud/aos_common/utils/retryhelper"
	"github.com/cavaliergopher/grab/v3"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_messageproxy/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const updateDownloadsTime = 30 * time.Second

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Downloader instance.
type Downloader struct {
	sync.Mutex

	config        config.Downloader
	actionHandler *action.Handler

	currentDownloads map[string]*downloadResult
}

// ImageContentRequest request to download image content.
type ImageContentRequest struct {
	RequestId uint64
	Url       string
}

type downloadResult struct {
	ImageContentRequest
	ctx context.Context
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new Downloader instance.
func New(cfg *config.Config) (*Downloader, error) {
	if err := os.MkdirAll(cfg.Downloader.DownloadDir, 0o755); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return &Downloader{
		config:           cfg.Downloader,
		actionHandler:    action.New(cfg.Downloader.MaxConcurrentDownloads),
		currentDownloads: make(map[string]*downloadResult),
	}, nil
}

// Download downloads image content.
func (downloader *Downloader) Download(
	ctx context.Context, imageContentRequest ImageContentRequest,
) (fileName string, err error) {
	log.WithField("URL", imageContentRequest.Url).Debug("Download")

	result := &downloadResult{
		ImageContentRequest: imageContentRequest,
		ctx:                 ctx,
	}

	if err := <-downloader.actionHandler.Execute(
		strconv.FormatUint(imageContentRequest.RequestId, 10), func(requestId string) (err error) {
			fileName, err = downloader.process(result)

			return err
		}); err != nil {
		return "", err
	}

	return fileName, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (downloader *Downloader) process(result *downloadResult) (fileName string, err error) {
	log.WithFields(log.Fields{"URL": result.Url}).Debug("Process download")

	if err := retryhelper.Retry(result.ctx,
		func() (err error) {
			if fileName, err = downloader.download(result); err != nil {
				return err
			}
			return nil
		},
		func(retryCount int, delay time.Duration, err error) {
			log.WithFields(log.Fields{"URL": result.Url}).Debugf("Retry download in %s", delay)
		},
		0, downloader.config.RetryDelay.Duration, downloader.config.MaxRetryDelay.Duration); err != nil {
		return fileName, errors.New("can't download file from source")
	}

	return fileName, nil
}

func (downloader *Downloader) download(result *downloadResult) (string, error) {
	timer := time.NewTicker(updateDownloadsTime)
	defer timer.Stop()

	req, err := grab.NewRequest(downloader.config.DownloadDir, result.Url)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	req = req.WithContext(result.ctx)

	resp := grab.DefaultClient.Do(req)

	for {
		select {
		case <-timer.C:
			log.WithFields(log.Fields{"complete": resp.BytesComplete(), "total": resp.Size}).Debug("Download progress")

		case <-resp.Done:
			if err = resp.Err(); err != nil {
				log.WithFields(log.Fields{
					"file":       resp.Filename,
					"downloaded": resp.BytesComplete(), "reason": err,
				}).Warn("Download interrupted")

				return "", aoserrors.Wrap(err)
			}

			log.WithFields(log.Fields{
				"file":       resp.Filename,
				"downloaded": resp.BytesComplete(),
			}).Debug("Download completed")

			return resp.Filename, nil
		}
	}
}
