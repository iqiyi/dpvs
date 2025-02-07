package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var CheckerThreads ThreadStats

// CheckerID represents VS-scoped Checker ID.
// It has the format of L3L4Addr::String().
type CheckerID string

func (id *CheckerID) valid() bool {
	return len(*id) > 0
}

type Checker struct {
	// read-only members
	id     CheckerID
	target utils.L3L4Addr
	conf   CheckerConf

	// checker's status
	state types.State
	count uint64
	since time.Time
	stats Statistics

	method checker.CheckMethod
	vs     *VirtualService // only access to vs's notify chan & read-only members

	update chan CheckerConf
	metric chan Metric
	quit   chan bool
}

func NewChecker(rs *comm.RealServer, conf *CheckerConf) *Checker {
	// TODO
	return nil
}

// UUID returns a global unique ID for the checker.
func (c *Checker) UUID() string {
	return fmt.Sprintf("%s/%s", c.vs.id, c.id)
}

func (c *Checker) Run(ctx context.Context, wg *sync.WaitGroup) {
	// TODO
}
