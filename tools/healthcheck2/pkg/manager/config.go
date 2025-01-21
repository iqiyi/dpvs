package manager

import "time"

type VAPolicy int

const (
	VAPolicyOneOf VAPolicy = 1
	VAPolicyAllOf VAPolicy = 2
)

type VAConf struct {
	downPolicy        VAPolicy
	ationer           string
	actionMinInterval time.Duration
	actionParams      map[string]interface{}
}

type VSConf struct {
	CheckerConf
	actioner          string
	actionMinInterval time.Duration
	actionParams      map[string]interface{}
}

type CheckerConf struct {
	method       string
	interval     time.Duration
	downRetry    uint
	upRetry      uint
	timeout      time.Duration
	syncTime     time.Duration
	methodParams map[string]interface{}
}

type Conf struct {
	vaGlobal VAConf
	vsGlobal VSConf
	vaConf   map[VAID]VAConf
	vsConf   map[VSID]VSConf
}

var (
	vaConfDefault VAConf = VAConf{
		downPolicy:        VAPolicyAllOf,
		ationer:           "kniAddrAddDel",
		actionMinInterval: 3 * time.Second,
	}

	vsConfDefault VSConf = VSConf{
		CheckerConf: CheckerConf{
			method:    "auto",
			interval:  2 * time.Second,
			downRetry: 1,
			upRetry:   1,
			timeout:   2 * time.Second,
			syncTime:  300 * time.Second,
		},
		actioner:          "updateWeightState",
		actionMinInterval: 3 * time.Second,
	}

	confDefault Conf = Conf{
		vaGlobal: vaConfDefault,
		vsGlobal: vsConfDefault,
	}
)

func LoadFileConf(filename string) *Conf {
	// TODO: load config from file

	return &confDefault
}
