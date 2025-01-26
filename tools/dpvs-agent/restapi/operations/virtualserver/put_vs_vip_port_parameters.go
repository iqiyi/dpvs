// Code generated by go-swagger; DO NOT EDIT.

package virtualserver

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"

	"github.com/dpvs-agent/models"
)

// NewPutVsVipPortParams creates a new PutVsVipPortParams object
// with the default values initialized.
func NewPutVsVipPortParams() PutVsVipPortParams {

	var (
		// initialize parameters with default values

		passiveUpdateDefault = bool(false)
		snapshotDefault      = bool(true)
	)

	return PutVsVipPortParams{
		PassiveUpdate: &passiveUpdateDefault,

		Snapshot: &snapshotDefault,
	}
}

// PutVsVipPortParams contains all the bound params for the put vs vip port operation
// typically these are obtained from a http.Request
//
// swagger:parameters PutVsVipPort
type PutVsVipPortParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  Required: true
	  In: path
	*/
	VipPort string
	/*
	  In: query
	  Default: false
	*/
	PassiveUpdate *bool
	/*
	  In: query
	  Default: true
	*/
	Snapshot *bool
	/*
	  In: body
	*/
	Spec *models.VirtualServerSpecTiny
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewPutVsVipPortParams() beforehand.
func (o *PutVsVipPortParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	rVipPort, rhkVipPort, _ := route.Params.GetOK("VipPort")
	if err := o.bindVipPort(rVipPort, rhkVipPort, route.Formats); err != nil {
		res = append(res, err)
	}

	qPassiveUpdate, qhkPassiveUpdate, _ := qs.GetOK("passiveUpdate")
	if err := o.bindPassiveUpdate(qPassiveUpdate, qhkPassiveUpdate, route.Formats); err != nil {
		res = append(res, err)
	}

	qSnapshot, qhkSnapshot, _ := qs.GetOK("snapshot")
	if err := o.bindSnapshot(qSnapshot, qhkSnapshot, route.Formats); err != nil {
		res = append(res, err)
	}

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.VirtualServerSpecTiny
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			res = append(res, errors.NewParseError("spec", "body", "", err))
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			ctx := validate.WithOperationRequest(r.Context())
			if err := body.ContextValidate(ctx, route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.Spec = &body
			}
		}
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindVipPort binds and validates parameter VipPort from path.
func (o *PutVsVipPortParams) bindVipPort(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.VipPort = raw

	return nil
}

// bindPassiveUpdate binds and validates parameter PassiveUpdate from query.
func (o *PutVsVipPortParams) bindPassiveUpdate(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewPutVsVipPortParams()
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("passiveUpdate", "query", "bool", raw)
	}
	o.PassiveUpdate = &value

	return nil
}

// bindSnapshot binds and validates parameter Snapshot from query.
func (o *PutVsVipPortParams) bindSnapshot(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewPutVsVipPortParams()
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("snapshot", "query", "bool", raw)
	}
	o.Snapshot = &value

	return nil
}
