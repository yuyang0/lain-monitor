package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/consul/api"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/laincloud/lain-monitor/client/backend"
	"go.uber.org/zap"
)

const (
	TIMEOUT              = 2
	HEALTHCHECK_INTERVAL = 60
)

var (
	deploydMetric = "lain.deployd.health"
	deploydURL    = "http://deployd.lain:9003/api/status"

	consoleMetric = "lain.console.health"
	consoleURL    = "http://console.lain/"

	etcdMetric = "lain.etcd.health"
	etcdURL    = "http://etcd.lain:4001/health"

	swarmMetric = "lain.swarm.health"
	swarmURL    = "http://swarm.lain:2376/_ping"

	consulMetric = "lain.consul.health"
	consulAddr   = "consul.lain:8500"

	tinydnsMetric = "lain.tinydns.health"
	tinydnsURL    = fmt.Sprintf("http://%s/ping", serverAddr)

	lvaultURL    = "http://lvault.lain.local/v2/status"
	lvaultMetric = "lain.lvault.health"

	vaultURL    = "http://lvault.lain.local/v2/vaultstatus"
	vaultMetric = "lain.vault.health"
)

type HealthChecker interface {
	Check(logger *zap.Logger) []*backend.Metric
}

type urlHealthChecker struct {
	metricName string
	url        string
}

type etcdHealthChecker struct {
	metricName string
	url        string
}

type consulHealthChecker struct {
	metricName string
	addr       string
	client     *api.Client
}

type lvaultHealthChecker struct {
	metricName, url string
}

type vaultHealthChecker struct {
	metricName, url string
}

func _buildPacket(name string, aliveInstance int) *backend.Metric {
	return &backend.Metric{
		Path:      name,
		Value:     float64(aliveInstance),
		Tags:      map[string]string{"cluster": cfg.ClusterName},
		Timestamp: time.Now(),
		Step:      HEALTHCHECK_INTERVAL,
	}
}

func _getJSON(url string, v interface{}) (bool, error) {
	timeout := TIMEOUT * time.Second
	client := http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(url)
	isAlive := true
	if err != nil || resp.StatusCode != 200 {
		isAlive = false
		return isAlive, err
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		isAlive = false
		return isAlive, err
	}
	return true, nil
}

func newConsulHealthChecker(metric, addr string) (HealthChecker, error) {
	config := &api.Config{
		Address:   addr,
		Scheme:    "http",
		Transport: cleanhttp.DefaultPooledTransport(),
	}
	consulClient, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &consulHealthChecker{
		metricName: metric,
		addr:       addr,
		client:     consulClient,
	}, nil
}

func (ckr *urlHealthChecker) Check(logger *zap.Logger) []*backend.Metric {
	timeout := TIMEOUT * time.Second
	client := http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(ckr.url)
	aliveInstances := 1
	if err != nil || resp.StatusCode != 200 {
		aliveInstances = 0
	}
	m := _buildPacket(ckr.metricName, aliveInstances)
	return []*backend.Metric{m}
}

func (ckr *etcdHealthChecker) Check(logger *zap.Logger) []*backend.Metric {
	var data map[string]string
	aliveInstances := 1
	ok, err := _getJSON(ckr.url, &data)
	if !ok || err != nil {
		if err != nil {
			logger.Error("failed to get json from etcd", zap.Error(err))
		}
		aliveInstances = 0
	}

	if health, ok := data["health"]; !ok || health == "false" {
		aliveInstances = 0
	}

	m := _buildPacket(ckr.metricName, aliveInstances)
	return []*backend.Metric{m}
}

func (ckr *consulHealthChecker) Check(logger *zap.Logger) []*backend.Metric {
	leader, err := ckr.client.Status().Leader()
	aliveInstances := 1
	if err != nil || len(leader) == 0 {
		aliveInstances = 0
	}
	m := _buildPacket(ckr.metricName, aliveInstances)
	return []*backend.Metric{m}
}

func (ckr *lvaultHealthChecker) Check(logger *zap.Logger) []*backend.Metric {
	type LvaultStatus struct {
		Host   string
		IsMiss bool
	}
	var metrics []*backend.Metric
	var statusList []LvaultStatus
	isAlive, err := _getJSON(ckr.url, &statusList)
	if !isAlive || err != nil {
		if err != nil {
			logger.Error("failed to get json for lvaut", zap.Error(err))
		}
		metrics = append(metrics, _buildPacket(ckr.metricName, 0))
	}
	aliveInstances := 0
	for _, status := range statusList {
		if !status.IsMiss {
			aliveInstances++
		}
	}
	metrics = append(metrics, _buildPacket(ckr.metricName, aliveInstances))
	return metrics
}

func (ckr *vaultHealthChecker) Check(logger *zap.Logger) []*backend.Metric {
	sealedMetric := "lain.vault.sealed"

	type VaultInfo struct {
		ContainerIP   string `json:"container_ip"`
		ContainerPort int    `json:"container_port"`
	}
	type VaultStatus struct {
		Sealed         bool
		T, N, Progress int
	}
	type VaultTotalInfo struct {
		Info   VaultInfo
		Status VaultStatus
	}
	var metrics []*backend.Metric
	var statusMap map[string]VaultTotalInfo
	isAlive, err := _getJSON(ckr.url, &statusMap)
	if !isAlive || err != nil {
		if err != nil {
			logger.Error("failed to get json for vault", zap.Error(err))
		}
		metrics = append(metrics, _buildPacket(ckr.metricName, 0))
	}
	aliveInstances := 0
	sealedInstances := 0
	for _, status := range statusMap {
		sealed := status.Status.Sealed
		if !sealed {
			aliveInstances++
		} else {
			sealedInstances++
		}
	}
	metrics = append(metrics, _buildPacket(ckr.metricName, aliveInstances))
	metrics = append(metrics, _buildPacket(sealedMetric, sealedInstances))
	return metrics
}

func runHealthCheckers(ctx context.Context, bd backend.Backend, logger *zap.Logger) error {
	var checkers []HealthChecker
	urls := []string{
		deploydURL,
		consoleURL,
		swarmURL,
		tinydnsURL,
	}
	names := []string{
		deploydMetric,
		consoleMetric,
		swarmMetric,
		tinydnsMetric,
	}

	for i := 0; i < len(names); i++ {
		url := urls[i]
		name := names[i]
		checkers = append(checkers, &urlHealthChecker{name, url})
	}
	checkers = append(checkers, &etcdHealthChecker{etcdMetric, etcdURL})
	checkers = append(checkers, &lvaultHealthChecker{lvaultMetric, lvaultURL})
	checkers = append(checkers, &vaultHealthChecker{vaultMetric, vaultURL})

	consulCkr, err := newConsulHealthChecker(consulMetric, consulAddr)
	if err != nil {
		return err
	}
	checkers = append(checkers, consulCkr)
	go func() {
		ticker := time.NewTicker(HEALTHCHECK_INTERVAL)
		defer ticker.Stop()
		for {
			var packets []*backend.Metric

			select {
			case now := <-ticker.C:
				logger.Info("health check...", zap.Time("now", now))
				for _, ckr := range checkers {
					packets = append(packets, ckr.Check(logger)...)
				}
				bd.Send(packets, logger)
				logger.Info("health check done.", zap.Time("now", now))
			case <-ctx.Done():
				logger.Info("health checker has been cancelled.")
				return
			}
		}
	}()
	return nil
}
