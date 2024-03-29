// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// DeleteDeviceNameNetlinkHandlerFunc turns a function with the right signature into a delete device name netlink handler
type DeleteDeviceNameNetlinkHandlerFunc func(DeleteDeviceNameNetlinkParams) middleware.Responder

// Handle executing the request and returning a response
func (fn DeleteDeviceNameNetlinkHandlerFunc) Handle(params DeleteDeviceNameNetlinkParams) middleware.Responder {
	return fn(params)
}

// DeleteDeviceNameNetlinkHandler interface for that can handle valid delete device name netlink params
type DeleteDeviceNameNetlinkHandler interface {
	Handle(DeleteDeviceNameNetlinkParams) middleware.Responder
}

// NewDeleteDeviceNameNetlink creates a new http.Handler for the delete device name netlink operation
func NewDeleteDeviceNameNetlink(ctx *middleware.Context, handler DeleteDeviceNameNetlinkHandler) *DeleteDeviceNameNetlink {
	return &DeleteDeviceNameNetlink{Context: ctx, Handler: handler}
}

/*
	DeleteDeviceNameNetlink swagger:route DELETE /device/{name}/netlink device deleteDeviceNameNetlink

ip link set ${name} down
*/
type DeleteDeviceNameNetlink struct {
	Context *middleware.Context
	Handler DeleteDeviceNameNetlinkHandler
}

func (o *DeleteDeviceNameNetlink) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewDeleteDeviceNameNetlinkParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
