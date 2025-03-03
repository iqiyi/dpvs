package checker

import (
	"net"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var ping_targets = []utils.L3L4Addr{
	{net.ParseIP("127.0.0.1"), 0, 0},
	{net.ParseIP("192.168.88.30"), 0, 0},
	{net.ParseIP("8.8.8.8"), 0, 0},
	{net.ParseIP("11.22.33.44"), 0, 0},
	{net.ParseIP("::1"), 0, 0},
	{net.ParseIP("2001::1"), 0, 0},
	{net.ParseIP("2001::68"), 0, 0},
}

func TestPingChecker(t *testing.T) {
	timeout := 2 * time.Second

	for _, target := range ping_targets {
		checker, err := (&PingChecker{}).create(nil)
		if err != nil {
			t.Fatalf("Failed to create ping checker %v: %v", target, err)
		}

		state, err := checker.Check(&target, timeout)
		if err != nil {
			t.Errorf("Failed to execute ping checker %v: %v", target, err)
		} else {
			t.Logf("[ Ping ]%v ==>%v", target.IP, state)
		}
	}
}
