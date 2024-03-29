// Code generated by go-swagger; DO NOT EDIT.

package virtualserver

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetVsVipPortHandlerFunc turns a function with the right signature into a get vs vip port handler
type GetVsVipPortHandlerFunc func(GetVsVipPortParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetVsVipPortHandlerFunc) Handle(params GetVsVipPortParams) middleware.Responder {
	return fn(params)
}

// GetVsVipPortHandler interface for that can handle valid get vs vip port params
type GetVsVipPortHandler interface {
	Handle(GetVsVipPortParams) middleware.Responder
}

// NewGetVsVipPort creates a new http.Handler for the get vs vip port operation
func NewGetVsVipPort(ctx *middleware.Context, handler GetVsVipPortHandler) *GetVsVipPort {
	return &GetVsVipPort{Context: ctx, Handler: handler}
}

/*
	GetVsVipPort swagger:route GET /vs/{VipPort} virtualserver getVsVipPort

get a specific virtual server
*/
type GetVsVipPort struct {
	Context *middleware.Context
	Handler GetVsVipPortHandler
}

func (o *GetVsVipPort) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewGetVsVipPortParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
