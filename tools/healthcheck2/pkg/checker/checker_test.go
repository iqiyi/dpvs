package checker

import (
	"flag"
	"os"
	"testing"

	"github.com/golang/glog"
)

func TestMain(m *testing.M) {
	// To support test args, run test with params like:
	// `go test -v . -args -logtostderr=true -v=9`
	// or test a specific method ping like:
	// `go test -v -run TestPingChecker --args -logtostderr=true -v=9`
	flag.Parse()

	rc := m.Run()
	glog.Flush()
	os.Exit(rc)
}
