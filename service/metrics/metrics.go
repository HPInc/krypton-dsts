// package github.com/HPInc/krypton-dsts/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// RegisterPrometheusMetrics - register prometheus metrics.
func RegisterPrometheusMetrics() {
	prometheus.MustRegister(MetricRPCLatency)
	prometheus.MustRegister(MetricRestLatency)
	prometheus.MustRegister(MetricCacheLatency)
	prometheus.MustRegister(MetricDatabaseLatency)
}

func ReportLatencyMetric(metric *prometheus.SummaryVec,
	startTime time.Time, label string) {
	duration := time.Since(startTime)
	metric.WithLabelValues(label).Observe(float64(duration.Milliseconds()))
}

func Chronograph(logger *zap.Logger, startTime time.Time, functionName string) {
	logger.Info("Execution completed in: ",
		zap.String("Function: ", functionName),
		zap.Duration("Duration (msec): ", time.Since(startTime)),
	)
}
