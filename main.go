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

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/coreos/go-systemd/journal"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_messageproxy/cmclient"
	"github.com/aoscloud/aos_messageproxy/config"
	"github.com/aoscloud/aos_messageproxy/downloader"
	"github.com/aoscloud/aos_messageproxy/iamclient"
	"github.com/aoscloud/aos_messageproxy/imageunpacker"
	"github.com/aoscloud/aos_messageproxy/vchan"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type journalHook struct {
	severityMap map[log.Level]journal.Priority
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

// GitSummary provided by govvv at compile-time.
var GitSummary = "Unknown" // nolint:gochecknoglobals

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetOutput(os.Stdout)
}

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

func main() {
	configFile := flag.String("c", "aos_messageproxy.cfg", "Path to config file")
	strLogLevel := flag.String("v", "info", `log level: "debug", "info", "warn", "error", "fatal", "panic"`)
	showVersion := flag.Bool("version", false, `Show message proxy version`)
	useJournal := flag.Bool("j", false, "Output logs to systemd journal")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Version: %s\n", GitSummary) // logs aren't initialized

		return
	}

	if *useJournal {
		log.AddHook(newJournalHook())
		log.SetOutput(ioutil.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}

	logLevel, err := log.ParseLevel(*strLogLevel)
	if err != nil {
		log.Fatalf("Error: %s", err)

		return
	}

	log.SetLevel(logLevel)

	log.WithFields(log.Fields{"configFile": *configFile, "version": GitSummary}).Info("Start message proxy")

	config, err := config.New(*configFile)
	if err != nil {
		log.Fatalf("Can't read config file: %s", err)

		return
	}

	downloadmanager, err := downloader.New(config)
	if err != nil {
		log.Fatalf("Can't create downloader: %s", err)

		return
	}

	unpackmanager, err := imageunpacker.New(config)
	if err != nil {
		log.Fatalf("Can't create unpacker: %s", err)

		return
	}

	vch, err := vchan.New(config, downloadmanager, unpackmanager)
	if err != nil {
		log.Fatalf("Can't create vchan: %s", err)

		return
	}
	defer vch.Close()

	cryptoContext, err := cryptutils.NewCryptoContext(config.CACert)
	if err != nil {
		log.Fatalf("Can't create crypto context: %s", err)

		return
	}
	defer cryptoContext.Close()

	iam, err := iamclient.New(config, cryptoContext, false)
	if err != nil {
		log.Fatalf("Can't create iam client: %s", err)

		return
	}
	defer iam.Close()

	cm, err := cmclient.New(config, iam, cryptoContext, vch.GetReceivingChannel(), vch.GetSendingChannel(), false)
	if err != nil {
		log.Fatalf("Can't create cm client: %s", err)

		return
	}
	defer cm.Close()

	terminateChannel := make(chan os.Signal, 1)

	signal.Notify(terminateChannel, os.Interrupt, syscall.SIGTERM)

	<-terminateChannel
}

func newJournalHook() (hook *journalHook) {
	hook = &journalHook{
		severityMap: map[log.Level]journal.Priority{
			log.DebugLevel: journal.PriDebug,
			log.InfoLevel:  journal.PriInfo,
			log.WarnLevel:  journal.PriWarning,
			log.ErrorLevel: journal.PriErr,
			log.FatalLevel: journal.PriCrit,
			log.PanicLevel: journal.PriEmerg,
		},
	}

	return hook
}

func (hook *journalHook) Fire(entry *log.Entry) (err error) {
	if entry == nil {
		return aoserrors.New("log entry is nil")
	}

	logMessage, err := entry.String()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	err = journal.Print(hook.severityMap[entry.Level], logMessage)

	return aoserrors.Wrap(err)
}

func (hook *journalHook) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	}
}
