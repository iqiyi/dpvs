// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// DeleteDeviceNameAddrOKCode is the HTTP code returned for type DeleteDeviceNameAddrOK
const DeleteDeviceNameAddrOKCode int = 200

/*
DeleteDeviceNameAddrOK delete ip addr from device Success

swagger:response deleteDeviceNameAddrOK
*/
type DeleteDeviceNameAddrOK struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewDeleteDeviceNameAddrOK creates DeleteDeviceNameAddrOK with default headers values
func NewDeleteDeviceNameAddrOK() *DeleteDeviceNameAddrOK {

	return &DeleteDeviceNameAddrOK{}
}

// WithPayload adds the payload to the delete device name addr o k response
func (o *DeleteDeviceNameAddrOK) WithPayload(payload string) *DeleteDeviceNameAddrOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete device name addr o k response
func (o *DeleteDeviceNameAddrOK) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteDeviceNameAddrOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

// DeleteDeviceNameAddrInternalServerErrorCode is the HTTP code returned for type DeleteDeviceNameAddrInternalServerError
const DeleteDeviceNameAddrInternalServerErrorCode int = 500

/*
DeleteDeviceNameAddrInternalServerError Failed

swagger:response deleteDeviceNameAddrInternalServerError
*/
type DeleteDeviceNameAddrInternalServerError struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewDeleteDeviceNameAddrInternalServerError creates DeleteDeviceNameAddrInternalServerError with default headers values
func NewDeleteDeviceNameAddrInternalServerError() *DeleteDeviceNameAddrInternalServerError {

	return &DeleteDeviceNameAddrInternalServerError{}
}

// WithPayload adds the payload to the delete device name addr internal server error response
func (o *DeleteDeviceNameAddrInternalServerError) WithPayload(payload string) *DeleteDeviceNameAddrInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete device name addr internal server error response
func (o *DeleteDeviceNameAddrInternalServerError) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteDeviceNameAddrInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
