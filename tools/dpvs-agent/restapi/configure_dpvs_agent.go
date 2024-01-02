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

// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/dpvs-agent/restapi/operations"
	"github.com/dpvs-agent/restapi/operations/device"
	"github.com/dpvs-agent/restapi/operations/virtualserver"
)

//go:generate swagger generate server --target ../../dpvs-agent --name DpvsAgent --spec ../dpvs-agent-api.yaml --principal interface{}

func configureFlags(api *operations.DpvsAgentAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.DpvsAgentAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	if api.DeviceDeleteDeviceNameAddrHandler == nil {
		api.DeviceDeleteDeviceNameAddrHandler = device.DeleteDeviceNameAddrHandlerFunc(func(params device.DeleteDeviceNameAddrParams) middleware.Responder {
			return middleware.NotImplemented("operation device.DeleteDeviceNameAddr has not yet been implemented")
		})
	}
	if api.DeviceDeleteDeviceNameRouteHandler == nil {
		api.DeviceDeleteDeviceNameRouteHandler = device.DeleteDeviceNameRouteHandlerFunc(func(params device.DeleteDeviceNameRouteParams) middleware.Responder {
			return middleware.NotImplemented("operation device.DeleteDeviceNameRoute has not yet been implemented")
		})
	}
	if api.DeviceDeleteDeviceNameVlanHandler == nil {
		api.DeviceDeleteDeviceNameVlanHandler = device.DeleteDeviceNameVlanHandlerFunc(func(params device.DeleteDeviceNameVlanParams) middleware.Responder {
			return middleware.NotImplemented("operation device.DeleteDeviceNameVlan has not yet been implemented")
		})
	}
	if api.VirtualserverDeleteVsVipPortHandler == nil {
		api.VirtualserverDeleteVsVipPortHandler = virtualserver.DeleteVsVipPortHandlerFunc(func(params virtualserver.DeleteVsVipPortParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.DeleteVsVipPort has not yet been implemented")
		})
	}
	if api.VirtualserverDeleteVsVipPortLaddrHandler == nil {
		api.VirtualserverDeleteVsVipPortLaddrHandler = virtualserver.DeleteVsVipPortLaddrHandlerFunc(func(params virtualserver.DeleteVsVipPortLaddrParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.DeleteVsVipPortLaddr has not yet been implemented")
		})
	}
	if api.VirtualserverDeleteVsVipPortRsHandler == nil {
		api.VirtualserverDeleteVsVipPortRsHandler = virtualserver.DeleteVsVipPortRsHandlerFunc(func(params virtualserver.DeleteVsVipPortRsParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.DeleteVsVipPortRs has not yet been implemented")
		})
	}
	if api.DeviceGetDeviceHandler == nil {
		api.DeviceGetDeviceHandler = device.GetDeviceHandlerFunc(func(params device.GetDeviceParams) middleware.Responder {
			return middleware.NotImplemented("operation device.GetDevice has not yet been implemented")
		})
	}
	if api.DeviceGetDeviceNameAddrHandler == nil {
		api.DeviceGetDeviceNameAddrHandler = device.GetDeviceNameAddrHandlerFunc(func(params device.GetDeviceNameAddrParams) middleware.Responder {
			return middleware.NotImplemented("operation device.GetDeviceNameAddr has not yet been implemented")
		})
	}
	if api.DeviceGetDeviceNameRouteHandler == nil {
		api.DeviceGetDeviceNameRouteHandler = device.GetDeviceNameRouteHandlerFunc(func(params device.GetDeviceNameRouteParams) middleware.Responder {
			return middleware.NotImplemented("operation device.GetDeviceNameRoute has not yet been implemented")
		})
	}
	if api.DeviceGetDeviceNameVlanHandler == nil {
		api.DeviceGetDeviceNameVlanHandler = device.GetDeviceNameVlanHandlerFunc(func(params device.GetDeviceNameVlanParams) middleware.Responder {
			return middleware.NotImplemented("operation device.GetDeviceNameVlan has not yet been implemented")
		})
	}
	if api.VirtualserverGetVsHandler == nil {
		api.VirtualserverGetVsHandler = virtualserver.GetVsHandlerFunc(func(params virtualserver.GetVsParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.GetVs has not yet been implemented")
		})
	}
	if api.VirtualserverGetVsVipPortHandler == nil {
		api.VirtualserverGetVsVipPortHandler = virtualserver.GetVsVipPortHandlerFunc(func(params virtualserver.GetVsVipPortParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.GetVsVipPort has not yet been implemented")
		})
	}
	if api.VirtualserverGetVsVipPortLaddrHandler == nil {
		api.VirtualserverGetVsVipPortLaddrHandler = virtualserver.GetVsVipPortLaddrHandlerFunc(func(params virtualserver.GetVsVipPortLaddrParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.GetVsVipPortLaddr has not yet been implemented")
		})
	}
	if api.VirtualserverGetVsVipPortRsHandler == nil {
		api.VirtualserverGetVsVipPortRsHandler = virtualserver.GetVsVipPortRsHandlerFunc(func(params virtualserver.GetVsVipPortRsParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.GetVsVipPortRs has not yet been implemented")
		})
	}
	if api.DevicePutDeviceNameAddrHandler == nil {
		api.DevicePutDeviceNameAddrHandler = device.PutDeviceNameAddrHandlerFunc(func(params device.PutDeviceNameAddrParams) middleware.Responder {
			return middleware.NotImplemented("operation device.PutDeviceNameAddr has not yet been implemented")
		})
	}
	if api.DevicePutDeviceNameRouteHandler == nil {
		api.DevicePutDeviceNameRouteHandler = device.PutDeviceNameRouteHandlerFunc(func(params device.PutDeviceNameRouteParams) middleware.Responder {
			return middleware.NotImplemented("operation device.PutDeviceNameRoute has not yet been implemented")
		})
	}
	if api.DevicePutDeviceNameVlanHandler == nil {
		api.DevicePutDeviceNameVlanHandler = device.PutDeviceNameVlanHandlerFunc(func(params device.PutDeviceNameVlanParams) middleware.Responder {
			return middleware.NotImplemented("operation device.PutDeviceNameVlan has not yet been implemented")
		})
	}
	if api.VirtualserverPutVsVipPortHandler == nil {
		api.VirtualserverPutVsVipPortHandler = virtualserver.PutVsVipPortHandlerFunc(func(params virtualserver.PutVsVipPortParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.PutVsVipPort has not yet been implemented")
		})
	}
	if api.VirtualserverPutVsVipPortLaddrHandler == nil {
		api.VirtualserverPutVsVipPortLaddrHandler = virtualserver.PutVsVipPortLaddrHandlerFunc(func(params virtualserver.PutVsVipPortLaddrParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.PutVsVipPortLaddr has not yet been implemented")
		})
	}
	if api.VirtualserverPutVsVipPortRsHandler == nil {
		api.VirtualserverPutVsVipPortRsHandler = virtualserver.PutVsVipPortRsHandlerFunc(func(params virtualserver.PutVsVipPortRsParams) middleware.Responder {
			return middleware.NotImplemented("operation virtualserver.PutVsVipPortRs has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
