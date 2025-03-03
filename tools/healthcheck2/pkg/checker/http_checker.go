package checker

/*
HTTP Checker Params:
-------------------------------------------------------------
name                value
-------------------------------------------------------------
method				GET | PUT | POST | HEAD
host                target host
uri                 target http URI
https               yes | no | true | false, case insensitive
tls-verify          yes | no | true | false, case insensitive
proxy               yes | no | true | false, case insensitive
prxoy-protocol      v1 | v2

request-header      KEY::VALUE
request             request data
response-codes      [CODE-CODE|CODE],[CODE-CODE|CODE], ...
response			expected response data
-------------------------------------------------------------

TODO:
  Add supports for QUIC/HTTP3.

*/

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
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*HTTPChecker)(nil)

var httpAllowddMethod = map[string]struct{}{
	"GET":  struct{}{},
	"PUT":  struct{}{},
	"POST": struct{}{},
	"HEAD": struct{}{},
}

type HttpCodeRange struct {
	Start int // inclusive
	End   int // inclusive
}

type HTTPChecker struct {
	method        string
	host          string
	uri           string
	https         bool
	tlsVerify     bool
	proxy         bool
	proxyProtocol string

	requestHeaders       map[string]string
	request              []byte
	responseCodesAllowed []HttpCodeRange
	response             []byte
}

func init() {
	registerMethod(CheckMethodHTTP, &HTTPChecker{})
}

func (c *HTTPChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	if timeout <= time.Duration(0) {
		return types.Unknown, fmt.Errorf("zero timeout on HTTP check")
	}
	addr := target.Addr()
	glog.V(9).Infof("Start HTTP check to %s ...", addr)

	if len(c.host) == 0 {
		c.host = addr
	}

	// 1. Create a http client.
	u, err := url.Parse(c.uri)
	if err != nil {
		return types.Unknown, fmt.Errorf("url parse failed -- url: %v, error: %v", c.uri, err)
	}
	if c.https || strings.HasPrefix(c.uri, "https://") {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	if len(u.Host) == 0 {
		u.Host = c.host
	}

	proxy := (func(*http.Request) (*url.URL, error))(nil)
	if c.proxy {
		proxy = http.ProxyURL(u)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !c.tlsVerify,
	}
	tr := &http.Transport{
		Proxy:               proxy,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: timeout,
	}
	if len(c.proxyProtocol) > 0 {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{
				Timeout: timeout,
			}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// Alternatively, use the go-proxyproto package:
			//   https://pkg.go.dev/github.com/pires/go-proxyproto
			if "v2" == c.proxyProtocol {
				if err = utils.WriteFull(conn, proxyProtoV2LocalCmd); err != nil {
					return nil, fmt.Errorf("failed to send proxy protocol v2 data: %v", err)
				}
			} else if "v1" == c.proxyProtocol {
				if err = utils.WriteFull(conn, []byte(proxyProtoV1LocalCmd)); err != nil {
					return nil, fmt.Errorf("failed to send proxy protocol v1 data: %v", err)
				}
			}
			return conn, nil
		}
	} else {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{
				Timeout: timeout,
			}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, viva []*http.Request) error {
			return errors.New("redirect not permitted")
		},
	}

	// 2. Send http request and check response.
	var reqBody io.Reader = nil
	if len(c.request) > 0 {
		reqBody = bytes.NewBuffer(c.request)
	}
	req, err := http.NewRequest(c.method, c.uri, reqBody)
	req.URL = u

	// If we received a response we want to process it, even in the
	// presence of an error - a redirect 3xx will result in both the
	// response and an error being returned.
	resp, err := client.Do(req)
	if resp == nil {
		glog.V(9).Infof("HTTP check %v %v: failed to send request, err: %v",
			addr, types.Unhealthy, err)
		return types.Unhealthy, nil
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	// check response code
	codeOk := false
	for _, cr := range c.responseCodesAllowed {
		if resp.StatusCode >= cr.Start && resp.StatusCode <= cr.End {
			codeOk = true
			break
		}
	}
	if !codeOk {
		glog.V(9).Infof("HTTP check %v %v: unexpected response code %d", addr,
			types.Unhealthy, resp.StatusCode)
		return types.Unhealthy, nil
	}

	// check response body
	if len(c.response) == 0 {
		glog.V(9).Infof("HTTP check %v %v: succeed", addr, types.Healthy)
		return types.Healthy, nil
	}

	if resp.Body != nil {
		buf := make([]byte, len(c.response))
		n, err := io.ReadFull(resp.Body, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			glog.V(9).Infof("HTTP check %v %v: failed to read response", addr, types.Unhealthy)
			return types.Unhealthy, nil
		}
		if !bytes.Equal(buf, c.response) {
			glog.V(9).Infof("HTTP check %v %v: unexpected response - %q", addr,
				types.Unhealthy, string(buf[:n]))
			return types.Unhealthy, nil
		}
	}

	glog.V(9).Infof("HTTP check %v %v: succeed", addr, types.Healthy)
	return types.Healthy, nil
}

func (c *HTTPChecker) create(params map[string]string) (CheckMethod, error) {
	// init and set default value
	checker := &HTTPChecker{
		method:               "GET",
		uri:                  "/",
		https:                false,
		tlsVerify:            true,
		proxy:                false,
		responseCodesAllowed: []HttpCodeRange{{200, 299}, {300, 399}, {400, 499}},
	}

	// parse params
	var err error
	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "method":
			if _, ok := httpAllowddMethod[val]; !ok {
				return nil, fmt.Errorf("unsupported http checker method: %s", val)
			}
			checker.method = val
		case "host":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty http checker param: %s", param)
			}
			checker.host = val
		case "uri":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty http checker param: %s", param)
			}
			checker.uri = val
		case "https":
			if checker.https, err = string2bool(val); err != nil {
				return nil, fmt.Errorf("invalid http checker param %s:%s", param, params[param])
			}
		case "tls-verify":
			if checker.tlsVerify, err = string2bool(val); err != nil {
				return nil, fmt.Errorf("invalid http checker param %s:%s", param, params[param])
			}
		case "proxy":
			if checker.proxy, err = string2bool(val); err != nil {
				return nil, fmt.Errorf("invalid http checker param %s:%s", param, params[param])
			}
		case ParamProxyProto:
			val = strings.ToLower(val)
			if val != "v1" && val != "v2" {
				return nil, fmt.Errorf("invalid http checker param %s:%s", param, params[param])
			}
			checker.proxyProtocol = val
		case "request-header":
			hdrName, hdrVal := parseHttpHeaderParam(val)
			if len(hdrName) == 0 || len(hdrVal) == 0 {
				return nil, fmt.Errorf("invalid http checker param %s:%s", param, val)
			}
			checker.requestHeaders[hdrName] = hdrVal
		case "request":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty http checker param: %s", param)
			}
			checker.request = []byte(val)
		case "response-codes":
			codes, err := parseHttpCodesParam(val)
			if err != nil {
				return nil, fmt.Errorf("invalid http checker response codes %s: %v", val, err)
			}
			checker.responseCodesAllowed = codes
		case "response":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty http checker param: %s", param)
			}
			checker.response = []byte(val)
		default:
			unsupported = append(unsupported, param)
		}
	}

	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported http checker params: %q", strings.Join(unsupported, ","))
	}

	return checker, nil
}

func string2bool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "yes", "true":
		return true, nil
	case "no", "false":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean string value: %s", s)
}

func parseHttpHeaderParam(header string) (name, val string) {
	segs := strings.Split(header, "::")
	if len(segs) != 2 {
		return
	}
	name, val = segs[0], segs[1]
	return
}

func parseHttpCodesParam(codes string) ([]HttpCodeRange, error) {
	parts := strings.Split(codes, ",")
	result := make([]HttpCodeRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, errors.New("invalid range format: " + part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, errors.New("invalid start value in range: " + bounds[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, errors.New("invalid end value in range: " + bounds[1])
			}
			if start > end {
				return nil, errors.New("start value is greater than end value in range: " + part)
			}
			result = append(result, HttpCodeRange{Start: start, End: end})
		} else {
			start, err := strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("invalid code: " + part)
			}
			result = append(result, HttpCodeRange{Start: start, End: start})
		}
	}
	return result, nil
}
