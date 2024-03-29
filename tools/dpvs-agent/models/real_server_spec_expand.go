// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RealServerSpecExpand real server spec expand
//
// swagger:model RealServerSpecExpand
type RealServerSpecExpand struct {

	// spec
	Spec *RealServerSpecTiny `json:"Spec,omitempty"`

	// stats
	Stats *ServerStats `json:"Stats,omitempty"`
}

// Validate validates this real server spec expand
func (m *RealServerSpecExpand) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSpec(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStats(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RealServerSpecExpand) validateSpec(formats strfmt.Registry) error {
	if swag.IsZero(m.Spec) { // not required
		return nil
	}

	if m.Spec != nil {
		if err := m.Spec.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Spec")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Spec")
			}
			return err
		}
	}

	return nil
}

func (m *RealServerSpecExpand) validateStats(formats strfmt.Registry) error {
	if swag.IsZero(m.Stats) { // not required
		return nil
	}

	if m.Stats != nil {
		if err := m.Stats.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Stats")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this real server spec expand based on the context it is used
func (m *RealServerSpecExpand) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSpec(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStats(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RealServerSpecExpand) contextValidateSpec(ctx context.Context, formats strfmt.Registry) error {

	if m.Spec != nil {
		if err := m.Spec.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Spec")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Spec")
			}
			return err
		}
	}

	return nil
}

func (m *RealServerSpecExpand) contextValidateStats(ctx context.Context, formats strfmt.Registry) error {

	if m.Stats != nil {
		if err := m.Stats.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Stats")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RealServerSpecExpand) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RealServerSpecExpand) UnmarshalBinary(b []byte) error {
	var res RealServerSpecExpand
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
