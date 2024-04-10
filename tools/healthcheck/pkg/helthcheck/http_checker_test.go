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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var http_targets = []Target{
	{net.ParseIP("192.168.88.30"), 80, utils.IPProtoTCP},
	{net.ParseIP("192.168.88.30"), 443, utils.IPProtoTCP},
	{net.ParseIP("2001::30"), 80, utils.IPProtoTCP},
	{net.ParseIP("2001::30"), 443, utils.IPProtoTCP},
	{net.ParseIP("192.168.88.30"), 8002, utils.IPProtoTCP}, // control group for proxy protocol
	{net.ParseIP("2001::30"), 8002, utils.IPProtoTCP},
}

var http_proxy_proto_targets = []Target{
	{net.ParseIP("192.168.88.30"), 8002, utils.IPProtoTCP},
	{net.ParseIP("2001::30"), 8002, utils.IPProtoTCP},
}

var http_url_targets = []string{
	"http://www.baidu.com",
	"https://www.baidu.com",
	"http://www.iqiyi.com",
	"https://www.iqiyi.com",
}

func TestHttpChecker(t *testing.T) {
	for _, target := range http_targets {
		checker := NewHttpChecker("", "", "", 0)
		checker.Host = target.Addr()
		/*
			if target.Port == 443 {
				checker.Secure = true
			}
		*/
		id := Id(target.String())
		config := NewCheckerConfig(&id, 0, checker, &target, StateUnknown,
			0, 3*time.Second, 2*time.Second, 3)
		result := checker.Check(target, config.Timeout)
		fmt.Printf("[ HTTP ] %s ==> %v\n", target, result)
	}

	for _, target := range http_proxy_proto_targets {
		checker := NewHttpChecker("", "", "", 1)
		checker.Host = target.Addr()
		id := Id(target.String())
		config := NewCheckerConfig(&id, 0, checker, &target, StateUnknown,
			0, 3*time.Second, 2*time.Second, 3)
		result := checker.Check(target, config.Timeout)
		fmt.Printf("[ HTTP(PPv1) ] %s ==> %v\n", target, result)
		checker2 := NewHttpChecker("", "", "", 2)
		checker2.Host = target.Addr()
		id2 := Id(target.String())
		config2 := NewCheckerConfig(&id2, 0, checker2, &target, StateUnknown,
			0, 3*time.Second, 2*time.Second, 3)
		result2 := checker2.Check(target, config2.Timeout)
		fmt.Printf("[ HTTP(PPv2) ] %s ==> %v\n", target, result2)
	}

	for _, target := range http_url_targets {
		host := target[strings.Index(target, "://")+3:]
		checker := NewHttpChecker("GET", target, "", 0)
		checker.Host = host
		checker.ResponseCodes = []HttpCodeRange{{200, 200}}
		if strings.HasPrefix(target, "https") {
			checker.Secure = true
		}
		id := Id(host)
		config := NewCheckerConfig(&id, 0, checker, &Target{}, StateUnknown,
			0, 3*time.Second, 2*time.Second, 3)
		result := checker.Check(Target{}, config.Timeout)
		if result.Success == false {
			t.Errorf("[ HTTP ] %s ==> %v\n", target, result)
		} else {
			fmt.Printf("[ HTTP ] %s ==> %v\n", target, result)
		}
	}
}
