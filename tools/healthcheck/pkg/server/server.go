// Copyright 2023 IQiYi Inc. All Rights Reserved.
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

package server

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	log "github.com/golang/glog"
)

// Shutdowner is an interface for a server that can be shutdown.
type Shutdowner interface {
	Shutdown()
}

var signalNames = map[syscall.Signal]string{
	syscall.SIGINT:  "SIGINT",
	syscall.SIGQUIT: "SIGQUIT",
	syscall.SIGTERM: "SIGTERM",
	syscall.SIGUSR1: "SIGUSR1",
}

// signalName returns a string containing the standard name for a given signal.
func signalName(s syscall.Signal) string {
	if name, ok := signalNames[s]; ok {
		return name
	}
	return fmt.Sprintf("SIG %d", s)
}

// ShutdownHandler configures signal handling and initiates a shutdown if a
// SIGINT, SIGQUIT or SIGTERM is received by the process.
func ShutdownHandler(server Shutdowner) {
	sigc := make(chan os.Signal, 3)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for s := range sigc {
			name := s.String()
			if sig, ok := s.(syscall.Signal); ok {
				if sig == syscall.SIGUSR1 {
					dumpStacks()
					continue
				}
				name = signalName(sig)
			}
			log.Infof("Received %v, initiating shutdown...", name)
			server.Shutdown()
		}
	}()
}

func dumpStacks() {
	buf := make([]byte, 16384)
	buf = buf[:runtime.Stack(buf, true)]
	log.Infof("=== BEGIN goroutine stack dump ===\n%s\n=== END goroutine stack dump ===", buf)
}
