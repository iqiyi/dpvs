// Code generated by go-swagger; DO NOT EDIT.

package virtualserver

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"
	"strings"

	"github.com/go-openapi/swag"
)

// PostVsVipPortRsURL generates an URL for the post vs vip port rs operation
type PostVsVipPortRsURL struct {
	VipPort string

	PassiveUpdate *bool
	Snapshot      *bool

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *PostVsVipPortRsURL) WithBasePath(bp string) *PostVsVipPortRsURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *PostVsVipPortRsURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *PostVsVipPortRsURL) Build() (*url.URL, error) {
	var _result url.URL

	var _path = "/vs/{VipPort}/rs"

	vipPort := o.VipPort
	if vipPort != "" {
		_path = strings.Replace(_path, "{VipPort}", vipPort, -1)
	} else {
		return nil, errors.New("vipPort is required on PostVsVipPortRsURL")
	}

	_basePath := o._basePath
	if _basePath == "" {
		_basePath = "/v2"
	}
	_result.Path = golangswaggerpaths.Join(_basePath, _path)

	qs := make(url.Values)

	var passiveUpdateQ string
	if o.PassiveUpdate != nil {
		passiveUpdateQ = swag.FormatBool(*o.PassiveUpdate)
	}
	if passiveUpdateQ != "" {
		qs.Set("passiveUpdate", passiveUpdateQ)
	}

	var snapshotQ string
	if o.Snapshot != nil {
		snapshotQ = swag.FormatBool(*o.Snapshot)
	}
	if snapshotQ != "" {
		qs.Set("snapshot", snapshotQ)
	}

	_result.RawQuery = qs.Encode()

	return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *PostVsVipPortRsURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *PostVsVipPortRsURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *PostVsVipPortRsURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on PostVsVipPortRsURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on PostVsVipPortRsURL")
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
func (o *PostVsVipPortRsURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
