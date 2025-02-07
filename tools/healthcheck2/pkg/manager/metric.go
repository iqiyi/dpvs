// +k8s:deepcopy-gen=package
package manager

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

/*
 Metric Indications:

|                    | up/down            | upNotified/downNotified          | upFailed/downFailed |
| ------------------ | ------------------ | -------------------------------- | ------------------- |
| Checker            | probe state counts | state change notices             | fail actions        |
| VirtualService(VS) | success actions    | received va state change notices | fail actions        |
| VirtualAddress(VA) | success actions    | received vs state change notices | fail actions        |
*/

type MetricType uint

const (
	MetricTypeVA MetricType = iota
	MetricTypeVS
	MetricTypeChecker
)

var metricDB *MetricDB

func init() {
	metricDB = NewMetricDB()
}

type State struct {
	state    types.State
	duration time.Duration
}

func (s *State) String() string {
	return fmt.Sprintf("%s %s", s.state, s.duration)
}

type Statistics struct {
	down        uint64
	up          uint64
	downNoticed uint64
	upNoticed   uint64
	downFailed  uint64
	upFailed    uint64
}

func (s *Statistics) String() string {
	return fmt.Sprintf("%d %d %d %d %d %d", s.up, s.down, s.upNoticed, s.downNoticed,
		s.upFailed, s.downFailed)
}

// Metric holds metric data sent from VA/VS/Checker to metric server.
// +k8s:deepcopy-gen=true
type Metric struct {
	kind      MetricType
	vaID      VAID
	vsID      VSID
	checkerID CheckerID

	state  State
	stats  Statistics
	extras []string
}

// +k8s:deepcopy-gen=true
type VSMetric struct {
	state    State
	stats    Statistics
	extras   []string
	checkers map[CheckerID]*Metric
}

// +k8s:deepcopy-gen=true
type VAMetric struct {
	state  State
	stats  Statistics
	extras []string
	vss    map[VSID]*VSMetric
}

// +k8s:deepcopy-gen=true
type MetricDB struct {
	data map[VAID]*VAMetric
	lock sync.RWMutex
}

func NewMetricDB() *MetricDB {
	db := new(MetricDB)
	db.data = make(map[VAID]*VAMetric)
	return db
}

func (db *MetricDB) Update(m *Metric) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	switch m.kind {
	case MetricTypeVA:
		if !m.vaID.valid() {
			return fmt.Errorf("invalid vaID(%v) in metric data", m.vaID)
		}
		va, exist := db.data[m.vaID]
		if !exist {
			va := new(VAMetric)
			va.vss = make(map[VSID]*VSMetric)
			db.data[m.vaID] = va
		}
		va.state = m.state
		va.stats = m.stats
		if len(m.extras) > 0 {
			va.extras = make([]string, len(m.extras))
			copy(va.extras[:], m.extras[:])
		}
	case MetricTypeVS:
		if !m.vaID.valid() || !m.vsID.valid() {
			return fmt.Errorf("invalid vaID(%v) or vsID(%v) in metric data", m.vaID, m.vsID)
		}
		va, exist := db.data[m.vaID]
		if !exist {
			va = new(VAMetric)
			va.vss = make(map[VSID]*VSMetric)
			db.data[m.vaID] = va
		}
		vs, exist := va.vss[m.vsID]
		if !exist {
			vs = new(VSMetric)
			vs.checkers = make(map[CheckerID]*Metric)
			va.vss[m.vsID] = vs
		}
		vs.state = m.state
		vs.stats = m.stats
		if len(m.extras) > 0 {
			vs.extras = make([]string, len(m.extras))
			copy(vs.extras[:], m.extras[:])
		}
	case MetricTypeChecker:
		if !m.vaID.valid() || !m.vsID.valid() || !m.checkerID.valid() {
			return fmt.Errorf("invalid vaID(%v) or vsID(%v) or metricID(%v) in metric data",
				m.vaID, m.vsID, m.checkerID)
		}
		va, exist := db.data[m.vaID]
		if !exist {
			va = new(VAMetric)
			va.vss = make(map[VSID]*VSMetric)
			db.data[m.vaID] = va
		}
		vs, exist := va.vss[m.vsID]
		if !exist {
			vs = new(VSMetric)
			vs.checkers = make(map[CheckerID]*Metric)
			va.vss[m.vsID] = vs
		}
		metric := new(Metric)
		m.DeepCopyInto(metric)
		vs.checkers[m.checkerID] = metric
	default:
		return fmt.Errorf("unknow metric data type %v", m.kind)
	}
	return nil
}

func (db *MetricDB) String() string {
	var dbCopied *MetricDB
	var builder strings.Builder

	db.lock.RLock()
	dbCopied = db.DeepCopy()
	db.lock.RUnlock()

	sep := "    "
	banner := fmt.Sprintf("%s%s%s%s%s%s%s%s%s", "object", sep, "state", sep,
		"statistics(up|down|up_notice|down_notice|up_fail|down_fail)", sep, "extra(optional)")
	builder.WriteString(fmt.Sprintf("%s\n", banner))
	builder.WriteString(fmt.Sprintf("%s\n", strings.Repeat("-", 80)))

	for vaID, va := range dbCopied.data {
		indent := ""
		vip := net.ParseIP(string(vaID))
		if vip == nil {
			glog.Warningf("VAID %v is not IP-formatted, skip VA metric %v.", vaID, va)
			continue
		}
		builder.WriteString(fmt.Sprintf("%s%s%s%s%s%s", indent, vip, sep, va.state, sep, va.stats))
		if len(va.extras) > 0 {
			builder.WriteString(fmt.Sprintf("%s%s", sep, strings.Join(va.extras, " ")))
		}
		builder.WriteString("\n")

		indent += sep
		for vsID, vs := range va.vss {
			vipport := utils.ParseL3L4Addr(string(vsID))
			if vipport == nil || !vip.Equal(vipport.IP) {
				glog.Warningf("VA %s VSID %v is not valid, skip VS metric %v.", vaID, vsID, vs)
				continue
			}
			vipportStr := ""
			if utils.IPAF(vipport.IP) == utils.IPv4 {
				vipportStr = fmt.Sprintf("%s %s:%d", vipport.Proto, vipport.IP, vipport.Port)
			} else {
				vipportStr = fmt.Sprintf("%s [%s]:%d", vipport.Proto, vipport.IP, vipport.Port)
			}
			builder.WriteString(fmt.Sprintf("%s%s%s%s%s%s", indent, vipportStr, sep, vs.state, sep, vs.stats))
			if len(vs.extras) > 0 {
				builder.WriteString(fmt.Sprintf("%s%s", sep, strings.Join(vs.extras, " ")))
			}
			builder.WriteString("\n")

			indent += "-> "
			for ckID, ck := range vs.checkers {
				backend := utils.ParseL3L4Addr(string(ckID))
				if backend == nil || backend.Proto != vipport.Proto {
					glog.Warningf("VS %s CheckerID %v is not valid, skip Checker metric %v.", vsID, ckID, ck)
					continue
				}
				backendStr := ""
				if utils.IPAF(backend.IP) == utils.IPv4 {
					backendStr = fmt.Sprintf("%s:%d", backend.IP, backend.Port)
				} else {
					backendStr = fmt.Sprintf("[%s]:%d", backend.IP, backend.Port)
				}
				builder.WriteString(fmt.Sprintf("%s%s%s%s%s%s", indent, backendStr, sep, ck.state, sep, ck.stats))
				if len(ck.extras) > 0 {
					builder.WriteString(fmt.Sprintf("%s%s", sep, strings.Join(ck.extras, " ")))
				}
				builder.WriteString("\n")
			} // backend ending
		} // VS ending
	} // VA ending

	return builder.String()
}

// TheadStats MUST access with atomic operations.
type ThreadStats struct {
	running  int32
	stopping int32
	finished uint64
}

func (t *ThreadStats) Running() int32 {
	return atomic.LoadInt32(&t.running)
}

func (t *ThreadStats) RunningInc() {
	atomic.AddInt32(&t.running, 1)
}

func (t *ThreadStats) RunningDec() {
	atomic.AddInt32(&t.running, -1)
}

func (t *ThreadStats) Stopping() int32 {
	return atomic.LoadInt32(&t.stopping)
}

func (t *ThreadStats) StoppingInc() {
	atomic.AddInt32(&t.stopping, 1)
}

func (t *ThreadStats) StoppingDec() {
	atomic.AddInt32(&t.stopping, -1)
}

func (t *ThreadStats) Finished() uint64 {
	return atomic.LoadUint64(&t.finished)
}

func (t *ThreadStats) FinishedInc() {
	atomic.AddUint64(&t.finished, 1)
}

func (t *ThreadStats) Dump(title bool) string {
	if title {
		return fmt.Sprintf("%-16s%-16s%-16s", "running", "stopping", "finished")
	}
	return fmt.Sprintf("%-16d%-16d%-16d", t.Running(), t.Stopping(), t.Finished())
}

func AppThreadStatsDump() string {
	str := VAThreads.Dump(true)
	res := fmt.Sprintf("%-20s%s\n", "", str)
	res += fmt.Sprintf("%s%-20s%s\n", res, "VirtualAddress", VAThreads.Dump(false))
	res += fmt.Sprintf("%s%-20s%s\n", res, "VirtualService", VSThreads.Dump(false))
	res += fmt.Sprintf("%s%-20s%s\n", res, "Checker", CheckerThreads.Dump(false))
	return res
}
