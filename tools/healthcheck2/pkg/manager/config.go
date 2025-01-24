package manager

import "time"

type VAPolicy int

const (
	VAPolicyOneOf VAPolicy = 1
	VAPolicyAllOf VAPolicy = 2
)

type VAConf struct {
	disable        bool
	downPolicy     VAPolicy
	ationer        string
	actionSyncTime time.Duration
	actionParams   map[string]interface{}
}

type VSConf struct {
	CheckerConf
	actioner       string
	actionSyncTime time.Duration
	actionParams   map[string]interface{}
}

type CheckerConf struct {
	method       string
	interval     time.Duration
	downRetry    uint
	upRetry      uint
	timeout      time.Duration
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
		disable:        false,
		downPolicy:     VAPolicyAllOf,
		ationer:        "kniAddrAddDel",
		actionSyncTime: 60 * time.Second,
	}

	vsConfDefault VSConf = VSConf{
		CheckerConf: CheckerConf{
			method:    "auto",
			interval:  2 * time.Second,
			downRetry: 1,
			upRetry:   1,
			timeout:   2 * time.Second,
		},
		actioner:       "updateWeightState",
		actionSyncTime: 15 * time.Second,
	}

	confDefault Conf = Conf{
		vaGlobal: vaConfDefault,
		vsGlobal: vsConfDefault,
	}
)

func LoadFileConf(filename string) (*Conf, error) {
	// TODO: load config from file

	return &confDefault, nil
}
