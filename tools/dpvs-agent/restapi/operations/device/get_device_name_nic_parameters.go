// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetDeviceNameNicParams creates a new GetDeviceNameNicParams object
// with the default values initialized.
func NewGetDeviceNameNicParams() GetDeviceNameNicParams {

	var (
		// initialize parameters with default values

		statsDefault   = bool(false)
		verboseDefault = bool(false)
	)

	return GetDeviceNameNicParams{
		Stats: &statsDefault,

		Verbose: &verboseDefault,
	}
}

// GetDeviceNameNicParams contains all the bound params for the get device name nic operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetDeviceNameNic
type GetDeviceNameNicParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  Required: true
	  In: path
	*/
	Name string
	/*
	  In: query
	  Default: false
	*/
	Stats *bool
	/*
	  In: query
	  Default: false
	*/
	Verbose *bool
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetDeviceNameNicParams() beforehand.
func (o *GetDeviceNameNicParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	rName, rhkName, _ := route.Params.GetOK("name")
	if err := o.bindName(rName, rhkName, route.Formats); err != nil {
		res = append(res, err)
	}

	qStats, qhkStats, _ := qs.GetOK("stats")
	if err := o.bindStats(qStats, qhkStats, route.Formats); err != nil {
		res = append(res, err)
	}

	qVerbose, qhkVerbose, _ := qs.GetOK("verbose")
	if err := o.bindVerbose(qVerbose, qhkVerbose, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindName binds and validates parameter Name from path.
func (o *GetDeviceNameNicParams) bindName(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.Name = raw

	return nil
}

// bindStats binds and validates parameter Stats from query.
func (o *GetDeviceNameNicParams) bindStats(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewGetDeviceNameNicParams()
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("stats", "query", "bool", raw)
	}
	o.Stats = &value

	return nil
}

// bindVerbose binds and validates parameter Verbose from query.
func (o *GetDeviceNameNicParams) bindVerbose(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewGetDeviceNameNicParams()
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("verbose", "query", "bool", raw)
	}
	o.Verbose = &value

	return nil
}
