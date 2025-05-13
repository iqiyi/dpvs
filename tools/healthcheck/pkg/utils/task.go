// /*
// Copyright 2025 IQiYi Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

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
		}
	}
}
