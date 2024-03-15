// Copyright 2023 IQiYi Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// The healthcheck package refers to the framework of "github.com/google/
// seesaw/healthcheck" heavily, with only some adaption changes for DPVS.

package hc

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var _ CheckMethod = (*HttpChecker)(nil)

type HttpCodeRange struct {
	start int // inclusive
	end   int // inclusive
}

// HttpChecker contains configuration specific to a HTTP(S) healthcheck.
type HttpChecker struct {
	Config *CheckerConfig

	Method        string
	Host          string
	Uri           string
	ResponseCodes []HttpCodeRange
	Response      string

	Secure     bool
	TLSVerify  bool
	Proxy      bool
	ProxyProto int // proxy protocol: 0 - close, 1 - version 1, 2 - version 2
}

// NewHttpChecker returns an initialised HttpChecker.
func NewHttpChecker(method, host, uri string, proxyProto int) *HttpChecker {
	if len(method) == 0 {
		method = "GET"
	}
	if len(uri) == 0 {
		uri = "/"
	}
	return &HttpChecker{
		Method:        method,
		Host:          host,
		Uri:           uri,
		ResponseCodes: []HttpCodeRange{{200, 299}, {300, 399}, {400, 499}},
		Response:      "",
		Secure:        false,
		TLSVerify:     true,
		Proxy:         false,
		ProxyProto:    proxyProto,
	}
}

func (hc *HttpChecker) BindConfig(conf *CheckerConfig) {
	hc.Config = conf
	if len(hc.Host) == 0 {
		hc.Host = conf.Target.Addr()
	}
}

// String returns the string representation of a HTTP healthcheck.
func (hc *HttpChecker) String() string {
	attr := []string{hc.Method, hc.Host, hc.Uri}
	if hc.Secure {
		attr = append(attr, "secure")
		if hc.TLSVerify {
			attr = append(attr, "tls-verify")
		}
	}
	if hc.Proxy {
		attr = append(attr, "proxy")
	}

	return fmt.Sprintf("HTTP checker for %v [%s]", hc.Config.Id, strings.Join(attr, ", "))
}

// Check executes a HTTP healthcheck.
func (hc *HttpChecker) Check(target Target, timeout time.Duration) *Result {
	var msg string
	if hc.Secure {
		msg = fmt.Sprintf("HTTPS %s to %s", hc.Method, hc.Host)
	} else {
		msg = fmt.Sprintf("HTTP %s to %s", hc.Method, hc.Host)
	}

	start := time.Now()
	if timeout == time.Duration(0) {
		timeout = DefaultCheckConfig.Timeout
	}

	u, err := url.Parse(hc.Uri)
	if err != nil {
		return NewResult(start, fmt.Sprintf("%s; url parse failed", msg), false, err)
	}
	if hc.Secure {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	if len(u.Host) == 0 {
		u.Host = hc.Host
	}

	proxy := (func(*http.Request) (*url.URL, error))(nil)
	if hc.Proxy {
		proxy = http.ProxyURL(u)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !hc.TLSVerify,
	}

	tr := &http.Transport{
		Proxy:           proxy,
		TLSClientConfig: tlsConfig,
	}
	if hc.ProxyProto != 0 {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// Alternatively, use the go-proxyproto package:
			//   https://pkg.go.dev/github.com/pires/go-proxyproto
			if hc.ProxyProto == 2 {
				n, err := bytes.NewReader(proxyProtoV2LocalCmd).WriteTo(conn)
				if err != nil || n < int64(len(proxyProtoV2LocalCmd)) {
					return nil, err
				}
			} else if hc.ProxyProto == 1 {
				n, err := strings.NewReader(proxyProtoV1LocalCmd).WriteTo(conn)
				if err != nil || n < int64(len(proxyProtoV1LocalCmd)) {
					return nil, err
				}
			}
			return conn, nil
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirect not permitted")
		},
	}

	req, err := http.NewRequest(hc.Method, hc.Uri, nil)
	req.URL = u

	// If we received a response we want to process it, even in the
	// presence of an error - a redirect 3xx will result in both the
	// response and an error being returned.
	resp, err := client.Do(req)
	if resp == nil {
		return NewResult(start, fmt.Sprintf("%s; got no response", msg), false, err)
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	// Check response code.
	codeOk := false
	for _, cr := range hc.ResponseCodes {
		if resp.StatusCode >= cr.start && resp.StatusCode <= cr.end {
			codeOk = true
			break
		}
	}

	// Check response body.
	bodyOk := false
	msg = fmt.Sprintf("%s; got %s", msg, resp.Status)
	if len(hc.Response) == 0 {
		bodyOk = true
	} else if resp.Body != nil {
		buf := make([]byte, len(hc.Response))
		n, err := io.ReadFull(resp.Body, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			msg = fmt.Sprintf("%s; failed to read HTTP response", msg)
		} else if string(buf) != hc.Response {
			msg = fmt.Sprintf("%s; unexpected response - %q", msg, string(buf[0:n]))
		} else {
			bodyOk = true
		}
	}

	return NewResult(start, msg, codeOk && bodyOk, nil)
}
