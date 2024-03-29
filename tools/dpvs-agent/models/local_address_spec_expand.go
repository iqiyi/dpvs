// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// LocalAddressSpecExpand local address spec expand
//
// swagger:model LocalAddressSpecExpand
type LocalAddressSpecExpand struct {

	// addr
	Addr string `json:"addr,omitempty"`

	// af
	Af uint32 `json:"af,omitempty"`

	// conns
	Conns uint32 `json:"conns,omitempty"`

	// device
	Device string `json:"device,omitempty"`

	// port conflict
	PortConflict uint64 `json:"portConflict,omitempty"`
}

// Validate validates this local address spec expand
func (m *LocalAddressSpecExpand) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this local address spec expand based on context it is used
func (m *LocalAddressSpecExpand) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LocalAddressSpecExpand) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LocalAddressSpecExpand) UnmarshalBinary(b []byte) error {
	var res LocalAddressSpecExpand
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
