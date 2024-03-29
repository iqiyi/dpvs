// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"
	"strings"

	"github.com/go-openapi/swag"
)

// GetDeviceNameVlanURL generates an URL for the get device name vlan operation
type GetDeviceNameVlanURL struct {
	Name string

	Stats *bool

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *GetDeviceNameVlanURL) WithBasePath(bp string) *GetDeviceNameVlanURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *GetDeviceNameVlanURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *GetDeviceNameVlanURL) Build() (*url.URL, error) {
	var _result url.URL

	var _path = "/device/{name}/vlan"

	name := o.Name
	if name != "" {
		_path = strings.Replace(_path, "{name}", name, -1)
	} else {
		return nil, errors.New("name is required on GetDeviceNameVlanURL")
	}

	_basePath := o._basePath
	if _basePath == "" {
		_basePath = "/v2"
	}
	_result.Path = golangswaggerpaths.Join(_basePath, _path)

	qs := make(url.Values)

	var statsQ string
	if o.Stats != nil {
		statsQ = swag.FormatBool(*o.Stats)
	}
	if statsQ != "" {
		qs.Set("stats", statsQ)
	}

	_result.RawQuery = qs.Encode()

	return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *GetDeviceNameVlanURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *GetDeviceNameVlanURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *GetDeviceNameVlanURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on GetDeviceNameVlanURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on GetDeviceNameVlanURL")
	}

	base, err := o.Build()
	if err != nil {
		return nil, err
	}

	base.Scheme = scheme
	base.Host = host
	return base, nil
}

// StringFull returns the string representation of a complete url
func (o *GetDeviceNameVlanURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
