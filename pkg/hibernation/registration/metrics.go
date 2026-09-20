// SPDX-License-Identifier: Apache-2.0
package registration

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

var metricsOnce sync.Once
var readyMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "kubevirt_hibernation_registration_ready", Help: "Whether the node can verify its approved enrollment with the provider."}, []string{"node", "registration"})
var renewalFailureMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "kubevirt_hibernation_registration_renewal_failed", Help: "Whether the latest enrollment or certificate renewal failed."}, []string{"node", "registration"})
var expiryMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "kubevirt_hibernation_registration_certificate_expiry_timestamp_seconds", Help: "Expiry of the latest issued client certificate, or zero while not enrolled."}, []string{"node", "registration"})

func registerMetrics() {
	metricsOnce.Do(func() { prometheus.MustRegister(readyMetric, renewalFailureMetric, expiryMetric) })
}
