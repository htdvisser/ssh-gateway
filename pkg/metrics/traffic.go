package metrics

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	bytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ssh",
			Subsystem: "upstream",
			Name:      "sent_bytes_total",
			Help:      "Total number of sent bytes",
		},
		[]string{"upstream"},
	)
	bytesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ssh",
			Subsystem: "upstream",
			Name:      "received_bytes_total",
			Help:      "Total number of received bytes",
		},
		[]string{"upstream"},
	)
)

func init() {
	prometheus.MustRegister(bytesSent, bytesReceived)
}

type meteredConn struct {
	net.Conn
	upstream string
}

func (c *meteredConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	bytesReceived.WithLabelValues(c.upstream).Add(float64(n))
	return
}

func (c *meteredConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	bytesSent.WithLabelValues(c.upstream).Add(float64(n))
	return
}

// NewMeteredConn returns a new metered net.Conn that counts towards the given upstream.
func NewMeteredConn(conn net.Conn, upstream string) net.Conn {
	return &meteredConn{
		Conn:     conn,
		upstream: upstream,
	}
}

// InitUpstream initializes the SSH upstream metrics for a given upstream.
func InitUpstream(upstream string) {
	bytesReceived.WithLabelValues(upstream).Add(0)
	bytesSent.WithLabelValues(upstream).Add(0)
}
