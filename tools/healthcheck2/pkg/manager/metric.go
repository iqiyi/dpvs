// +k8s:deepcopy-gen=package
package manager

import (
	"fmt"
	"net"
	"sort"
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
| Checker            | probe state counts | state change notices             | fail checks         |
| VirtualService(VS) | success actions    | received va state change notices | fail actions        |
| VirtualAddress(VA) | success actions    | received vs state change notices | fail actions        |
*/

type MetricType uint

const (
	MetricTypeVA MetricType = iota
	MetricTypeVS
	MetricTypeChecker
	MetricTypeDelVA
	MetricTypeDelVS
	MetricTypeDelChecker
)

var metricDB *MetricDB

func init() {
	metricDB = NewMetricDB()
}

type State struct {
	state types.State
	since time.Time
}

func (s State) String() string {
	duration := time.Duration(time.Since(s.since).Seconds()) * time.Second
	return fmt.Sprintf("%s %v", s.state, duration)
}

type Statistics struct {
	up          uint64 // act UP success, check UP
	down        uint64 // act DOWN success, check DOWN
	upNoticed   uint64 // UP state notified or received
	downNoticed uint64 // DOWN state notified or received
	upFailed    uint64 // act UP failed, check timeout
	downFailed  uint64 // act DOWN failed, check error
}

func (s Statistics) String() string {
	return fmt.Sprintf("%d,%d,%d,%d,%d,%d",
		s.up, s.down,
		s.upNoticed, s.downNoticed,
		s.upFailed, s.downFailed,
	)
}

func (s *Statistics) Title() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s",
		"up", "down",
		"up_notices", "down_notices",
		"fail(up,timeout)", "fail(down,error)",
	)
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
			va = new(VAMetric)
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
	case MetricTypeDelVA:
		if !m.vaID.valid() {
			return fmt.Errorf("invalid vaID(%v) in deleting metric data", m.vaID)
		}
		delete(db.data, m.vaID)
	case MetricTypeDelVS:
		if !m.vaID.valid() || !m.vsID.valid() {
			return fmt.Errorf("invalid vaID(%v) or vsID(%v) in deleting metric data", m.vaID, m.vsID)
		}
		va, exist := db.data[m.vaID]
		if !exist {
			return nil
		}
		delete(va.vss, m.vsID)
	case MetricTypeDelChecker:
		if !m.vaID.valid() || !m.vsID.valid() || !m.checkerID.valid() {
			return fmt.Errorf("invalid vaID(%v) or vsID(%v) or metricID(%v) in deleting metric data",
				m.vaID, m.vsID, m.checkerID)
		}
		va, exist := db.data[m.vaID]
		if !exist {
			return nil
		}
		vs, exist := va.vss[m.vsID]
		if !exist {
			return nil
		}
		delete(vs.checkers, m.checkerID)
	default:
		return fmt.Errorf("unknow metric data type %v", m.kind)
	}
	return nil
}

func (db *MetricDB) String() string {
	var dbCopied *MetricDB
	var builder strings.Builder
	stats := Statistics{}

	db.lock.RLock()
	dbCopied = db.DeepCopy()
	db.lock.RUnlock()

	sep := "    "
	banner := fmt.Sprintf("%s%s%s%sstatistics:%s%s%s", "object", sep, "state", sep,
		stats.Title(), sep, "extra(optional)")
	builder.WriteString(fmt.Sprintf("%s\n", banner))
	builder.WriteString(fmt.Sprintf("%s\n", strings.Repeat("-", 80)))

	vaIDSortList := make([]string, 0, len(dbCopied.data))
	for vaID, _ := range dbCopied.data {
		vaIDSortList = append(vaIDSortList, string(vaID))
	}
	sort.Strings(vaIDSortList)
	for _, vaIDStr := range vaIDSortList {
		vaID := VAID(vaIDStr)
		va := dbCopied.data[vaID]
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
		vsIDSortList := make([]string, 0, len(va.vss))
		for vsID, _ := range va.vss {
			vsIDSortList = append(vsIDSortList, string(vsID))
		}
		sort.Strings(vsIDSortList)
		for _, vsIDStr := range vsIDSortList {
			vsID := VSID(vsIDStr)
			vs := va.vss[vsID]
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
			ckIDSortList := make([]string, 0, len(vs.checkers))
			for ckID, _ := range vs.checkers {
				ckIDSortList = append(ckIDSortList, string(ckID))
			}
			sort.Strings(ckIDSortList)
			for _, ckIDStr := range ckIDSortList {
				ckID := CheckerID(ckIDStr)
				ck := vs.checkers[ckID]
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
			indent = strings.TrimSuffix(indent, "-> ")
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
	res := fmt.Sprintf("%-20s%s\n", "", VAThreads.Dump(true))
	res += fmt.Sprintf("%-20s%s\n", "VirtualAddress", VAThreads.Dump(false))
	res += fmt.Sprintf("%-20s%s\n", "VirtualService", VSThreads.Dump(false))
	res += fmt.Sprintf("%-20s%s\n", "Checker", CheckerThreads.Dump(false))
	res += fmt.Sprintf("%-20s%s\n", "HealthCheck", HealthCheckThreads.Dump(false))
	return res
}
