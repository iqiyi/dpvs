package checker

import (
	"net"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var udpping_targets = []utils.L3L4Addr{
	{net.ParseIP("192.168.88.130"), 6000, utils.IPProtoUDP},
	{net.ParseIP("11.22.33.44"), 6000, utils.IPProtoUDP},
	{net.ParseIP("192.168.88.130"), 6602, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6000, utils.IPProtoUDP},
	{net.ParseIP("1234:5678::9"), 6000, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6002, utils.IPProtoUDP},
}

func TestUDPPingChecker(t *testing.T) {
	timeout := 2 * time.Second

	for _, target := range udpping_targets {
		// TODO:
		//  Add tests for each supported params.

		checker, err := (&UDPPingChecker{}).create(nil)
		if err != nil {
			t.Fatalf("Failed to create udpping checker %v: %v", target, err)
		}

		state, err := checker.Check(&target, timeout)
		if err != nil {
			t.Errorf("Failed to execute  udpping checker %v: %v", target, err)
		} else {
			t.Logf("[ UDPPing ] %v ==> %v", target, state)
		}
	}
}
