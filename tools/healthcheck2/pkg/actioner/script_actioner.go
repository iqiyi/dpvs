package actioner

/*
Script Actioner Params:
-------------------------------------------------
name                value
-------------------------------------------------
script              script file path name
args                args to run the script

-------------------------------------------------

Notes:
The script is invoked as
  sh <script> [args] ACTION [IP] [PORT] [PROTOCOL]
where:
  ACTION := UP | DOWN
  IP, PORT, PROTOCOL is required only when counterparts
  in the target is non-zero.

*/

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*ScriptAction)(nil)

const scriptActionerName = "Script"

func init() {
	registerMethod(scriptActionerName, &ScriptAction{})
}

type ScriptAction struct {
	script string
	args   string
	target *utils.L3L4Addr
}

func (a *ScriptAction) commandline(signal types.State) string {
	act := "UP"
	if signal == types.Unhealthy {
		act = "DOWN"
	}
	cmdline := fmt.Sprintf("%s %s %s", a.script, a.args, act)

	if a.target == nil {
		return cmdline
	}

	if len(a.target.IP) == 0 {
		return cmdline
	}
	cmdline = fmt.Sprintf("%s %v", cmdline, a.target.IP)

	if a.target.Port == 0 {
		return cmdline
	}
	cmdline = fmt.Sprintf("%s %v", cmdline, a.target.Port)

	if a.target.Proto != utils.IPProto(0) {
		cmdline = fmt.Sprintf("%s %s", cmdline, a.target.Proto)
	}
	return cmdline
}

func (a *ScriptAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	cmdline := a.commandline(signal)

	if timeout < 0 {
		return nil, fmt.Errorf("zero timeout on %s actioner %q", scriptActionerName, cmdline)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	glog.V(7).Infof("starting %s actioner %q ...", scriptActionerName, cmdline)

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdline)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s actioner command %q timed out", scriptActionerName, cmdline)
	}
	if err != nil {
		return nil, fmt.Errorf("%s actioner command %q failed: %v, output: %s", scriptActionerName,
			cmdline, err, output)
	}

	if len(output) > 0 {
		glog.V(8).Infof("%s actioner command %q output: %s", scriptActionerName, cmdline, output)
	}
	glog.V(6).Infof("%s actioner command %q succeed", scriptActionerName, cmdline)

	return nil, nil
}

func (a *ScriptAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	actioner := &ScriptAction{}

	if target != nil {
		actioner.target = target.DeepCopy()
	}

	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "script":
			if len(val) > 0 {
				actioner.script = val
			}
		case "args":
			if len(val) > 0 {
				actioner.args = val
			}
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported %s actioner params: %s", scriptActionerName,
			strings.Join(unsupported, ","))
	}

	if len(actioner.script) == 0 || !utils.IsExecutableFile(actioner.script) {
		return nil, fmt.Errorf("invalid %s actioner script name %q", scriptActionerName, actioner.script)
	}
	return actioner, nil
}
