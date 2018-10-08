package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	connectionsStarted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ssh",
			Subsystem: "upstream",
			Name:      "connections_started_total",
			Help:      "Total number of started SSH connections",
		},
		[]string{"pubkey", "upstream"},
	)
	connectionsEnded = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ssh",
			Subsystem: "upstream",
			Name:      "connections_ended_total",
			Help:      "Total number of ended SSH connections",
		},
		[]string{"pubkey", "upstream"},
	)
)

func init() {
	prometheus.MustRegister(connectionsStarted, connectionsEnded)
}

// RegisterStartForward registers the start of an SSH forwarding connection.
func RegisterStartForward(pubKey, upstream string) {
	pubKey = strings.TrimPrefix(pubKey, "authorized_keys_")
	connectionsStarted.WithLabelValues(pubKey, upstream).Inc()
}

// RegisterEndForward registers the end of an SSH forwarding connection.
func RegisterEndForward(pubKey, upstream string) {
	pubKey = strings.TrimPrefix(pubKey, "authorized_keys_")
	connectionsEnded.WithLabelValues(pubKey, upstream).Inc()
}

// InitForward initializes the SSH forwarding metrics for a given pubKey and upstream.
func InitForward(pubKey, upstream string) {
	pubKey = strings.TrimPrefix(pubKey, "authorized_keys_")
	connectionsStarted.WithLabelValues(pubKey, upstream).Add(0)
	connectionsEnded.WithLabelValues(pubKey, upstream).Add(0)
}
