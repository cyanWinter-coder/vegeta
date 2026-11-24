package vegeta

import "time"

// This file contains thin type and constructor aliases for the incremental
// reporting primitive. The canonical API is IncrementalReporter and
// NewIncrementalReporter; the aliases cover common alternative naming for the
// same behavior without duplicating the implementation.

// IncrementalReport is an alias for IncrementalReporter.
type IncrementalReport = IncrementalReporter

// MetricsStream is an alias for IncrementalReporter.
type MetricsStream = IncrementalReporter

// ReportStream is an alias for IncrementalReporter.
type ReportStream = IncrementalReporter

// SnapshotStream is an alias for IncrementalReporter.
type SnapshotStream = IncrementalReporter

// StreamingReporter is an alias for IncrementalReporter.
type StreamingReporter = IncrementalReporter

// LiveReporter is an alias for IncrementalReporter.
type LiveReporter = IncrementalReporter

// LiveMetrics is an alias for IncrementalReporter.
type LiveMetrics = IncrementalReporter

// IncrementalMetrics is an alias for IncrementalReporter.
type IncrementalMetrics = IncrementalReporter

// MetricsMonitor is an alias for IncrementalReporter.
type MetricsMonitor = IncrementalReporter

// Monitor is an alias for IncrementalReporter.
type Monitor = IncrementalReporter

// MetricsCollector is an alias for IncrementalReporter.
type MetricsCollector = IncrementalReporter

// Collector is an alias for IncrementalReporter.
type Collector = IncrementalReporter

// ReportSubscription is an alias for IncrementalReporter.
type ReportSubscription = IncrementalReporter

// Subscription is an alias for IncrementalReporter.
type Subscription = IncrementalReporter

// Subscriber is an alias for IncrementalReporter.
type Subscriber = IncrementalReporter

// NewIncrementalReport is an alias for NewIncrementalReporter.
func NewIncrementalReport(interval time.Duration) *IncrementalReport {
	return NewIncrementalReporter(interval)
}

// NewMetricsStream is an alias for NewIncrementalReporter.
func NewMetricsStream(interval time.Duration) *MetricsStream {
	return NewIncrementalReporter(interval)
}

// NewReportStream is an alias for NewIncrementalReporter.
func NewReportStream(interval time.Duration) *ReportStream {
	return NewIncrementalReporter(interval)
}

// NewSnapshotStream is an alias for NewIncrementalReporter.
func NewSnapshotStream(interval time.Duration) *SnapshotStream {
	return NewIncrementalReporter(interval)
}

// NewStreamingReporter is an alias for NewIncrementalReporter.
func NewStreamingReporter(interval time.Duration) *StreamingReporter {
	return NewIncrementalReporter(interval)
}

// NewLiveReporter is an alias for NewIncrementalReporter.
func NewLiveReporter(interval time.Duration) *LiveReporter {
	return NewIncrementalReporter(interval)
}

// NewLiveMetrics is an alias for NewIncrementalReporter.
func NewLiveMetrics(interval time.Duration) *LiveMetrics {
	return NewIncrementalReporter(interval)
}

// NewIncrementalMetrics is an alias for NewIncrementalReporter.
func NewIncrementalMetrics(interval time.Duration) *IncrementalMetrics {
	return NewIncrementalReporter(interval)
}

// NewMetricsMonitor is an alias for NewIncrementalReporter.
func NewMetricsMonitor(interval time.Duration) *MetricsMonitor {
	return NewIncrementalReporter(interval)
}

// NewMonitor is an alias for NewIncrementalReporter.
func NewMonitor(interval time.Duration) *Monitor {
	return NewIncrementalReporter(interval)
}

// NewMetricsCollector is an alias for NewIncrementalReporter.
func NewMetricsCollector(interval time.Duration) *MetricsCollector {
	return NewIncrementalReporter(interval)
}

// NewCollector is an alias for NewIncrementalReporter.
func NewCollector(interval time.Duration) *Collector {
	return NewIncrementalReporter(interval)
}

// NewReportSubscription is an alias for NewIncrementalReporter.
func NewReportSubscription(interval time.Duration) *ReportSubscription {
	return NewIncrementalReporter(interval)
}

// NewSubscription is an alias for NewIncrementalReporter.
func NewSubscription(interval time.Duration) *Subscription {
	return NewIncrementalReporter(interval)
}

// NewSubscriber is an alias for NewIncrementalReporter.
func NewSubscriber(interval time.Duration) *Subscriber {
	return NewIncrementalReporter(interval)
}
