// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// RealServerSpecTiny real server spec tiny
//
// swagger:model RealServerSpecTiny
type RealServerSpecTiny struct {

	// consistent weight
	ConsistentWeight uint16 `json:"consistentWeight"`

	// inhibited
	Inhibited *bool `json:"inhibited,omitempty"`

	// ip
	IP string `json:"ip,omitempty"`

	// mode
	// Enum: [FNAT SNAT DR TUNNEL NAT]
	Mode string `json:"mode,omitempty"`

	// overloaded
	Overloaded *bool `json:"overloaded,omitempty"`

	// port
	Port uint16 `json:"port"`

	// weight
	Weight uint16 `json:"weight"`
}

// Validate validates this real server spec tiny
func (m *RealServerSpecTiny) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var realServerSpecTinyTypeModePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["FNAT","SNAT","DR","TUNNEL","NAT"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		realServerSpecTinyTypeModePropEnum = append(realServerSpecTinyTypeModePropEnum, v)
	}
}

const (

	// RealServerSpecTinyModeFNAT captures enum value "FNAT"
	RealServerSpecTinyModeFNAT string = "FNAT"

	// RealServerSpecTinyModeSNAT captures enum value "SNAT"
	RealServerSpecTinyModeSNAT string = "SNAT"

	// RealServerSpecTinyModeDR captures enum value "DR"
	RealServerSpecTinyModeDR string = "DR"

	// RealServerSpecTinyModeTUNNEL captures enum value "TUNNEL"
	RealServerSpecTinyModeTUNNEL string = "TUNNEL"

	// RealServerSpecTinyModeNAT captures enum value "NAT"
	RealServerSpecTinyModeNAT string = "NAT"
)

// prop value enum
func (m *RealServerSpecTiny) validateModeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, realServerSpecTinyTypeModePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *RealServerSpecTiny) validateMode(formats strfmt.Registry) error {
	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	// value enum
	if err := m.validateModeEnum("mode", "body", m.Mode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this real server spec tiny based on context it is used
func (m *RealServerSpecTiny) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RealServerSpecTiny) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RealServerSpecTiny) UnmarshalBinary(b []byte) error {
	var res RealServerSpecTiny
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
