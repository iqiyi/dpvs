package settings

import (
	"sync"

	"github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/types"
)

var (
	shareSnapshot  *types.NodeSnapshot
	shareAppConfig *AppConfig
	initOnce       sync.Once
)

type AppConfig struct {
	CacheFile string
}

func setUp() {
	shareAppConfig = &AppConfig{}
	shareSnapshot = &types.NodeSnapshot{
		NodeSpec: &models.DpvsNodeSpec{
			AnnouncePort: &models.VsAnnouncePort{},
		},
		Snapshot: make(map[string]*types.ServiceSnapshot),
	}
}

func ShareAppConfig() *AppConfig {
	initOnce.Do(setUp)
	return shareAppConfig
}

func ShareSnapshot() *types.NodeSnapshot {
	initOnce.Do(setUp)
	return shareSnapshot
}

func LocalConfigFile() string {
	// return filepath.Join(shareAppConfig.ConfigDir, "cache")
	return shareAppConfig.CacheFile
}
