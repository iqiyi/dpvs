package checker

import (
	"net"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var tcp_targets = []utils.L3L4Addr{
	{net.ParseIP("192.168.88.130"), 80, utils.IPProtoTCP},
	{net.ParseIP("11.22.33.44"), 80, utils.IPProtoTCP},
	{net.ParseIP("192.168.88.130"), 8383, utils.IPProtoTCP},
	{net.ParseIP("2001::30"), 80, utils.IPProtoTCP},
	{net.ParseIP("1234:5678::9"), 80, utils.IPProtoTCP},
	{net.ParseIP("2001::30"), 8383, utils.IPProtoTCP},
}

func TestTCPChecker(t *testing.T) {
	timeout := 2 * time.Second

	for _, target := range tcp_targets {
		// TODO:
		//  Add tests for each supported params.

		checker, err := (&TCPChecker{}).create(nil)
		if err != nil {
			t.Fatalf("Failed to create TCP checker %v: %v", target, err)
		}

		state, err := checker.Check(&target, timeout)
		if err != nil {
			t.Errorf("Failed to execute TCP checker %v: %v", target, err)
		} else {
			t.Logf("[ TCP ] %v ==> %v", target, state)
		}
	}
}
