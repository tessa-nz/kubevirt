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
	metricsOnce.Do(func() {
		prometheus.MustRegister(readyMetric, renewalFailureMetric, expiryMetric, providerScrapeMetric, providerLastSuccessMetric)
		for _, gauge := range providerMetrics {
			prometheus.MustRegister(gauge)
		}
	})
}

var providerScrapeMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "kubevirt_hibernation_provider_scrape_success", Help: "Whether the latest authenticated provider telemetry request succeeded."}, []string{"node", "registration", "provider"})
var providerLastSuccessMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "kubevirt_hibernation_provider_last_success_timestamp_seconds", Help: "Time of the latest authenticated provider telemetry response."}, []string{"node", "registration", "provider"})
var providerMetricNames = []string{"tpm_reachable", "tpm_persistent_slots_available", "active_attempts", "stuck_attempt_age_seconds", "server_certificate_expiry_timestamp_seconds", "ca_expiry_timestamp_seconds"}
var providerMetrics = func() map[string]*prometheus.GaugeVec {
	out := map[string]*prometheus.GaugeVec{}
	for _, name := range providerMetricNames {
		out[name] = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "kubevirt_hibernation_provider_" + name, Help: "Latest authenticated provider observation: " + name}, []string{"node", "registration", "provider"})
	}
	return out
}()

func clearProviderMetrics(node, registration, provider string) {
	for _, gauge := range providerMetrics {
		gauge.DeleteLabelValues(node, registration, provider)
	}
}
