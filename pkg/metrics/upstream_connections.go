package metrics

import "github.com/prometheus/client_golang/prometheus"

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
	connectionsStarted.WithLabelValues(pubKey, upstream).Inc()
}

// RegisterEndForward registers the end of an SSH forwarding connection.
func RegisterEndForward(pubKey, upstream string) {
	connectionsEnded.WithLabelValues(pubKey, upstream).Inc()
}
