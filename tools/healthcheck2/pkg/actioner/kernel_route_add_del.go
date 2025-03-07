package actioner

/*
BackendAction Actioner Params:
-------------------------------------------------
name                value
-------------------------------------------------
ifname              network interface name

-------------------------------------------------
*/

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ ActionMethod = (*KernelRouteAction)(nil)

const kernelRouteActionerName = "KernelRouteAddDel"

func init() {
	registerMethod(kernelRouteActionerName, &KernelRouteAction{})
}

type KernelRouteAction struct {
	target *utils.L3L4Addr
	ifname string
}

func findLinkByAddr(addr net.IP) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list links: %w", err)
	}

	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(addr) {
				return link, nil
			}
		}
	}

	return nil, fmt.Errorf("address %v not found on any interface", addr)
}

func isExistError(err error) bool {
	return err == unix.EEXIST || err.Error() == "file exists"
}

func isNotExistError(err error) bool {
	return err == unix.ENOENT || err == unix.ESRCH || err.Error() == "cannot assign requested address"
}

func (a *KernelRouteAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	addr := a.target.IP
	var operation string

	if timeout < 0 {
		return nil, fmt.Errorf("zero timeout on %s actioner %v", kernelRouteActionerName, addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	glog.V(7).Infof("starting %s actioner %s ...", kernelRouteActionerName, addr)

	done := make(chan error, 1)

	go func() {
		var link netlink.Link
		var err error

		/*
			// Notes:
			//	 Find ifname by IP is not feasible to deletion operation.

			if len(a.ifname) == 0 {
				if link, err = findLinkByAddr(addr); err != nil {
					done <- fmt.Errorf("failed to find link for address: %w", err)
					return
				}
			}
		*/
		link, err = netlink.LinkByName(a.ifname)
		if err != nil {
			done <- fmt.Errorf("failed to get link by name: %w", err)
			return
		}

		var ipNet *net.IPNet
		if addr.To4() != nil {
			ipNet = &net.IPNet{IP: addr, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: addr, Mask: net.CIDRMask(128, 128)}
		}

		ipAddr := &netlink.Addr{IPNet: ipNet}

		if signal != types.Unhealthy { // ADD
			operation = "ADD"
			if err := netlink.AddrAdd(link, ipAddr); err != nil {
				if isExistError(err) {
					glog.V(8).Infof("Warning: adding address %v already exists: %v\n", addr, err)
				} else {
					done <- fmt.Errorf("failed to add address %v to %s: %w", addr, a.ifname, err)
					return
				}
			}

			route := netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       ipAddr.IPNet,
			}
			if err := netlink.RouteAdd(&route); err != nil {
				if !isExistError(err) {
					done <- fmt.Errorf("failed to add host route %v to %s: %w", addr, a.ifname, err)
					return
				}
			}
		} else { // DELETE
			operation = "DELETE"
			if err := netlink.AddrDel(link, ipAddr); err != nil {
				if isNotExistError(err) {
					glog.V(8).Infof("Warning: deleting address %v does not exist: %v\n", addr, err)
				} else {
					done <- fmt.Errorf("failed to delete address %v from %s: %w", addr, a.ifname, err)
					return
				}
			}

			route := netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       ipAddr.IPNet,
			}
			if err := netlink.RouteDel(&route); err != nil {
				if !isNotExistError(err) {
					done <- fmt.Errorf("failed to delete route %v from %s: %w", addr, a.ifname, err)
					return
				}
			}
		}

		done <- nil
	}()

	select {
	case <-ctx.Done():
		glog.Errorf("%s actioner %v %s timeout", kernelRouteActionerName, addr, operation)
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			glog.Errorf("%s actioner %v %s failed: %v", kernelRouteActionerName, addr, operation, err)
			return nil, err
		}
	}
	glog.V(6).Infof("%s actioner %v %s succeed", kernelRouteActionerName, addr, operation)
	return nil, nil
}

func (a *KernelRouteAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	if target == nil {
		return nil, fmt.Errorf("no target address for %s actioner", kernelRouteActionerName)
	}

	actioner := &KernelRouteAction{
		target: target.DeepCopy(),
	}

	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "ifname":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty %s actioner param: %s", kernelRouteActionerName, param)
			}
			actioner.ifname = val
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported %s actioner params: %s",
			kernelRouteActionerName, strings.Join(unsupported, ","))
	}

	if len(actioner.ifname) == 0 {
		return nil, fmt.Errorf("%s actioner misses param: ifname", kernelRouteActionerName)
	}
	return actioner, nil
}
