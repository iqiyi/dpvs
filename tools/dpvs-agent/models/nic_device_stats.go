// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NicDeviceStats nic device stats
//
// swagger:model NicDeviceStats
type NicDeviceStats struct {

	// buf avail
	BufAvail uint32 `json:"bufAvail,omitempty"`

	// buf inuse
	BufInuse uint32 `json:"bufInuse,omitempty"`

	// error bytes q
	ErrorBytesQ []NicDeviceQueueData `json:"errorBytesQ"`

	// id
	ID uint16 `json:"id,omitempty"`

	// in bytes
	InBytes uint64 `json:"inBytes,omitempty"`

	// in bytes q
	InBytesQ []NicDeviceQueueData `json:"inBytesQ"`

	// in errors
	InErrors uint64 `json:"inErrors,omitempty"`

	// in missed
	InMissed uint64 `json:"inMissed,omitempty"`

	// in pkts
	InPkts uint64 `json:"inPkts,omitempty"`

	// in pkts q
	InPktsQ []NicDeviceQueueData `json:"inPktsQ"`

	// out bytes
	OutBytes uint64 `json:"outBytes,omitempty"`

	// out bytes q
	OutBytesQ []NicDeviceQueueData `json:"outBytesQ"`

	// out errors
	OutErrors uint64 `json:"outErrors,omitempty"`

	// out pkts
	OutPkts uint64 `json:"outPkts,omitempty"`

	// out pkts q
	OutPktsQ []NicDeviceQueueData `json:"outPktsQ"`

	// rx no mbuf
	RxNoMbuf uint64 `json:"rxNoMbuf,omitempty"`
}

// Validate validates this nic device stats
func (m *NicDeviceStats) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateErrorBytesQ(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInBytesQ(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInPktsQ(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOutBytesQ(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOutPktsQ(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NicDeviceStats) validateErrorBytesQ(formats strfmt.Registry) error {
	if swag.IsZero(m.ErrorBytesQ) { // not required
		return nil
	}

	for i := 0; i < len(m.ErrorBytesQ); i++ {

		if err := m.ErrorBytesQ[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("errorBytesQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("errorBytesQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) validateInBytesQ(formats strfmt.Registry) error {
	if swag.IsZero(m.InBytesQ) { // not required
		return nil
	}

	for i := 0; i < len(m.InBytesQ); i++ {

		if err := m.InBytesQ[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("inBytesQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("inBytesQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) validateInPktsQ(formats strfmt.Registry) error {
	if swag.IsZero(m.InPktsQ) { // not required
		return nil
	}

	for i := 0; i < len(m.InPktsQ); i++ {

		if err := m.InPktsQ[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("inPktsQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("inPktsQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) validateOutBytesQ(formats strfmt.Registry) error {
	if swag.IsZero(m.OutBytesQ) { // not required
		return nil
	}

	for i := 0; i < len(m.OutBytesQ); i++ {

		if err := m.OutBytesQ[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("outBytesQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("outBytesQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) validateOutPktsQ(formats strfmt.Registry) error {
	if swag.IsZero(m.OutPktsQ) { // not required
		return nil
	}

	for i := 0; i < len(m.OutPktsQ); i++ {

		if err := m.OutPktsQ[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("outPktsQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("outPktsQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// ContextValidate validate this nic device stats based on the context it is used
func (m *NicDeviceStats) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateErrorBytesQ(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInBytesQ(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInPktsQ(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOutBytesQ(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOutPktsQ(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NicDeviceStats) contextValidateErrorBytesQ(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ErrorBytesQ); i++ {

		if err := m.ErrorBytesQ[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("errorBytesQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("errorBytesQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) contextValidateInBytesQ(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.InBytesQ); i++ {

		if err := m.InBytesQ[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("inBytesQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("inBytesQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) contextValidateInPktsQ(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.InPktsQ); i++ {

		if err := m.InPktsQ[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("inPktsQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("inPktsQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) contextValidateOutBytesQ(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OutBytesQ); i++ {

		if err := m.OutBytesQ[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("outBytesQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("outBytesQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *NicDeviceStats) contextValidateOutPktsQ(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OutPktsQ); i++ {

		if err := m.OutPktsQ[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("outPktsQ" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("outPktsQ" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *NicDeviceStats) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NicDeviceStats) UnmarshalBinary(b []byte) error {
	var res NicDeviceStats
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
