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

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/lestrrat-go/file-rotatelogs"

	"github.com/dpvs-agent/cmd/device"
	"github.com/dpvs-agent/cmd/ipvs"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/restapi"
	"github.com/dpvs-agent/restapi/operations"
)

var (
	IpcSocket string = "/var/run/dpvs.ipc"
)

type DpvsAgentServer struct {
	LogDir        string `long:"log-dir" description:"default log dir is /var/log/ And log name dpvs-agent.log" default:"/var/log/"`
	IpcSocketPath string `long:"ipc-sockopt-path" description:"default ipc socket path /var/run/dpvs.ipc" default:"/var/run/dpvs.ipc"`
	restapi.Server
}

func unixDialer(ctx context.Context) (net.Conn, error) {
	retry := 0
	d := net.Dialer{Timeout: 10 * time.Second}
	raddr := net.UnixAddr{Name: IpcSocket, Net: "unix"}
	for {
		conn, err := d.DialContext(ctx, "unix", raddr.String())
		if err == nil {
			return conn, nil
		}
		// FIXME: A weird fact was observed in tests of large concurrency that the previous
		// "DailContext" returned the error "resource temporarily unavailable" occasionally.
		// No solution to it has found yet, thus just retry as a compromise.
		if strings.Contains(err.Error(), "resource temporarily unavailable") != true {
			return nil, err
		}
		retry++
		if retry > 10 {
			return nil, err
		}
	}
	return nil, errors.New("unknown error")
}

func (agent *DpvsAgentServer) instantiateAPI(restAPI *operations.DpvsAgentAPI) {
	if strings.HasSuffix(agent.IpcSocketPath, ".ipc") {
		s, err := os.Stat(agent.IpcSocketPath)
		if err == nil {
			if !s.IsDir() {
				IpcSocket = agent.IpcSocketPath
			}
		}
	}

	cp := pool.NewConnPool(&pool.Options{
		Dialer:   unixDialer,
		PoolSize: 1024,
		// PoolTimeout:        -1,
		// IdleTimeout:        -1,
		// IdleCheckFrequency: -1,
	})

	logDir := "/var/log/"
	if len(agent.LogDir) > 1 { // avoid root path '/' set
		s, err := os.Stat(agent.LogDir)
		if err == nil {
			if s.IsDir() {
				logDir = agent.LogDir
			}
		}
	}

	sep := "/"
	if strings.HasSuffix(logDir, "/") {
		sep = ""
	}

	logFile := strings.Join([]string{logDir, "dpvs-agent.log"}, sep)
	// logOpt := &hclog.LoggerOptions{Name: logFile}
	var logOpt *hclog.LoggerOptions
	logFileNamePattern := strings.Join([]string{logFile, "%Y%m%d%H%M"}, "-")
	logRotationInterval := 1 * time.Hour

	logF, err := rotatelogs.New(
		logFileNamePattern,
		rotatelogs.WithLinkName(logFile),
		rotatelogs.WithRotationTime(logRotationInterval),
	)
	// f, err := os.Create(logFile)
	if err == nil {
		logOpt = &hclog.LoggerOptions{Name: logFile, Output: logF}
	} else {
		os.Exit(-1)
	}

	hclog.SetDefault(hclog.New(logOpt))

	logger := hclog.Default().Named("main")

	// delete
	restAPI.VirtualserverDeleteVsVipPortHandler = ipvs.NewDelVsItem(cp, logger)
	restAPI.VirtualserverDeleteVsVipPortLaddrHandler = ipvs.NewDelVsLaddr(cp, logger)
	restAPI.VirtualserverDeleteVsVipPortRsHandler = ipvs.NewDelVsRs(cp, logger)
	restAPI.VirtualserverDeleteVsVipPortDenyHandler = ipvs.NewDelVsDeny(cp, logger)
	restAPI.VirtualserverDeleteVsVipPortAllowHandler = ipvs.NewDelVsAllow(cp, logger)

	// get
	restAPI.VirtualserverGetVsHandler = ipvs.NewGetVs(cp, logger)
	restAPI.VirtualserverGetVsVipPortHandler = ipvs.NewGetVsVipPort(cp, logger)
	restAPI.VirtualserverGetVsVipPortLaddrHandler = ipvs.NewGetVsLaddr(cp, logger)

	// put
	restAPI.VirtualserverPutVsVipPortHandler = ipvs.NewPutVsItem(cp, logger)
	restAPI.VirtualserverPutVsVipPortLaddrHandler = ipvs.NewPutVsLaddr(cp, logger)
	restAPI.VirtualserverPutVsVipPortRsHandler = ipvs.NewPutVsRs(cp, logger)
	restAPI.VirtualserverPutVsVipPortDenyHandler = ipvs.NewPutVsDeny(cp, logger)
	restAPI.VirtualserverPutVsVipPortAllowHandler = ipvs.NewPutVsAllow(cp, logger)

	// post
	restAPI.VirtualserverPostVsVipPortRsHandler = ipvs.NewPostVsRs(cp, logger)

	// get
	// restAPI.DeviceGetDeviceNameAddrHandler
	// restAPI.DeviceGetDeviceNameRouteHandler
	// restAPI.DeviceGetDeviceNameVlanHandler
	restAPI.DeviceGetDeviceNameNicHandler = device.NewGetDeviceNameNic(cp, logger)

	// put
	restAPI.DevicePutDeviceNameNetlinkHandler = device.NewSetDeviceNetlinkUp(cp, logger)
	restAPI.DevicePutDeviceNameAddrHandler = device.NewPutDeviceAddr(cp, logger)
	restAPI.DevicePutDeviceNameRouteHandler = device.NewPutDeviceRoute(cp, logger)
	restAPI.DevicePutDeviceNameVlanHandler = device.NewPutDeviceVlan(cp, logger)
	restAPI.DevicePutDeviceNameNetlinkAddrHandler = device.NewPutDeviceNetlinkAddr(cp, logger)
	restAPI.DevicePutDeviceNameNicHandler = device.NewPutDeviceNameNic(cp, logger)

	// delete
	restAPI.DeviceDeleteDeviceNameAddrHandler = device.NewDelDeviceAddr(cp, logger)
	restAPI.DeviceDeleteDeviceNameRouteHandler = device.NewDelDeviceRoute(cp, logger)
	restAPI.DeviceDeleteDeviceNameVlanHandler = device.NewDelDeviceVlan(cp, logger)
	restAPI.DeviceDeleteDeviceNameNetlinkAddrHandler = device.NewDelDeviceNetlinkAddr(cp, logger)
}

func (agent *DpvsAgentServer) InstantiateServer(api *operations.DpvsAgentAPI) *restapi.Server {
	agent.instantiateAPI(api)

	server := restapi.NewServer(api)
	server.ConfigureAPI()

	server.EnabledListeners = make([]string, len(agent.EnabledListeners))
	copy(server.EnabledListeners, agent.EnabledListeners)
	server.CleanupTimeout = agent.CleanupTimeout
	server.GracefulTimeout = agent.GracefulTimeout
	server.MaxHeaderSize = agent.MaxHeaderSize
	server.SocketPath = agent.SocketPath
	server.Host = agent.Host
	server.Port = agent.Port
	server.ListenLimit = agent.ListenLimit
	server.KeepAlive = agent.KeepAlive
	server.ReadTimeout = agent.ReadTimeout
	server.WriteTimeout = agent.WriteTimeout
	server.TLSHost = agent.TLSHost
	server.TLSPort = agent.TLSPort
	server.TLSCertificate = agent.TLSCertificate
	server.TLSCertificateKey = agent.TLSCertificateKey
	server.TLSCACertificate = agent.TLSCACertificate
	server.TLSListenLimit = agent.TLSListenLimit
	server.TLSKeepAlive = agent.TLSKeepAlive
	server.TLSReadTimeout = agent.TLSReadTimeout
	server.TLSWriteTimeout = agent.TLSWriteTimeout

	return server
}
