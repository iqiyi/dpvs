package utils

import (
	"context"
	"sync"
	"time"

	"github.com/golang/glog"
)

// Task represents a regularly scheduling Job with designated Interval.
type Task interface {
	Name() string
	Interval() time.Duration
	Job(ctx context.Context)
}

func RunTask(t Task, ctx context.Context, wg *sync.WaitGroup, start <-chan time.Time) {
	glog.Infof("Task %q started.", t.Name())
	if wg != nil {
		defer wg.Done()
	}

	if start != nil {
		<-start
	}

	// Run Job immediately on called (after the start delay).
	glog.V(7).Infof("Task %q scheduled.", t.Name())
	t.Job(ctx)

	ticker := time.NewTicker(t.Interval())
	for {
		select {
		case <-ctx.Done():
			glog.Infof("Task %q done.", t.Name())
			ticker.Stop()
			return
		case <-ticker.C:
			glog.V(7).Infof("Task %q scheduled.", t.Name())
			t.Job(ctx)
		default:
		}
	}
}
