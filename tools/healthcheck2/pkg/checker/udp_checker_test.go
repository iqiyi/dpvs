package checker

import (
	"net"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var udp_targets = []utils.L3L4Addr{
	{net.ParseIP("192.168.88.130"), 6000, utils.IPProtoUDP},
	{net.ParseIP("11.22.33.44"), 6000, utils.IPProtoUDP},
	{net.ParseIP("192.168.88.130"), 6602, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6000, utils.IPProtoUDP},
	{net.ParseIP("1234:5678::9"), 6000, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6002, utils.IPProtoUDP},
}

func TestUDPChecker(t *testing.T) {
	timeout := 2 * time.Second

	for _, target := range udp_targets {
		// TODO:
		//  Add tests for each supported params.

		checker, err := (&UDPChecker{}).create(nil)
		if err != nil {
			t.Fatalf("Failed to create UDP checker %v: %v", target, err)
		}

		state, err := checker.Check(&target, timeout)
		if err != nil {
			t.Errorf("Failed to execute UDP checker %v: %v", target, err)
		} else {
			t.Logf("[ UDP ] %v ==> %v", target, state)
		}
	}
}
