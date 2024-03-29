// Code generated by go-swagger; DO NOT EDIT.

package virtualserver

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// GetVsVipPortAllowOKCode is the HTTP code returned for type GetVsVipPortAllowOK
const GetVsVipPortAllowOKCode int = 200

/*
GetVsVipPortAllowOK Success

swagger:response getVsVipPortAllowOK
*/
type GetVsVipPortAllowOK struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewGetVsVipPortAllowOK creates GetVsVipPortAllowOK with default headers values
func NewGetVsVipPortAllowOK() *GetVsVipPortAllowOK {

	return &GetVsVipPortAllowOK{}
}

// WithPayload adds the payload to the get vs vip port allow o k response
func (o *GetVsVipPortAllowOK) WithPayload(payload string) *GetVsVipPortAllowOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get vs vip port allow o k response
func (o *GetVsVipPortAllowOK) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetVsVipPortAllowOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

// GetVsVipPortAllowNotFoundCode is the HTTP code returned for type GetVsVipPortAllowNotFound
const GetVsVipPortAllowNotFoundCode int = 404

/*
GetVsVipPortAllowNotFound Service not found

swagger:response getVsVipPortAllowNotFound
*/
type GetVsVipPortAllowNotFound struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewGetVsVipPortAllowNotFound creates GetVsVipPortAllowNotFound with default headers values
func NewGetVsVipPortAllowNotFound() *GetVsVipPortAllowNotFound {

	return &GetVsVipPortAllowNotFound{}
}

// WithPayload adds the payload to the get vs vip port allow not found response
func (o *GetVsVipPortAllowNotFound) WithPayload(payload string) *GetVsVipPortAllowNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get vs vip port allow not found response
func (o *GetVsVipPortAllowNotFound) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetVsVipPortAllowNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
