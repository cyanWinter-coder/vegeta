package vegeta

import (
	"math"
	"sort"
	"strconv"
	"time"
)

// Metrics holds metrics computed out of a slice of Results which are used
// in some of the Reporters
type Metrics struct {
	// Latencies holds computed request latency metrics.
	Latencies LatencyMetrics `json:"latencies"`
	// Histogram, only if requested
	Histogram *Histogram `json:"buckets,omitempty"`
	// BytesIn holds computed incoming byte metrics.
	BytesIn ByteMetrics `json:"bytes_in"`
	// BytesOut holds computed outgoing byte metrics.
	BytesOut ByteMetrics `json:"bytes_out"`
	// Earliest is the earliest timestamp in a Result set.
	Earliest time.Time `json:"earliest"`
	// Latest is the latest timestamp in a Result set.
	Latest time.Time `json:"latest"`
	// End is the latest timestamp in a Result set plus its latency.
	End time.Time `json:"end"`
	// Duration is the duration of the attack.
	Duration time.Duration `json:"duration"`
	// Wait is the extra time waiting for responses from targets.
	Wait time.Duration `json:"wait"`
	// Requests is the total number of requests executed.
	Requests uint64 `json:"requests"`
	// Rate is the rate of sent requests per second.
	Rate float64 `json:"rate"`
	// Throughput is the rate of successful requests per second.
	Throughput float64 `json:"throughput"`
	// Success is the percentage of non-error responses.
	Success float64 `json:"success"`
	// StatusCodes is a histogram of the responses' status codes.
	StatusCodes map[string]int `json:"status_codes"`
	// Errors is a set of unique errors returned by the targets during the attack.
	Errors []string `json:"errors"`

	errors  map[string]struct{}
	success uint64
}

// Add implements the Add method of the Report interface by adding the given
// Result to Metrics.
func (m *Metrics) Add(r *Result) {
	m.init()

	m.Requests++
	m.StatusCodes[strconv.Itoa(int(r.Code))]++
	m.BytesOut.Total += r.BytesOut
	m.BytesIn.Total += r.BytesIn

	m.Latencies.Add(r.Latency)

	if m.Earliest.IsZero() || m.Earliest.After(r.Timestamp) {
		m.Earliest = r.Timestamp
	}

	if r.Timestamp.After(m.Latest) {
		m.Latest = r.Timestamp
	}

	if end := r.End(); end.After(m.End) {
		m.End = end
	}

	if r.Code >= 200 && r.Code < 400 {
		m.success++
	}

	if r.Error != "" {
		if _, ok := m.errors[r.Error]; !ok {
			m.errors[r.Error] = struct{}{}
			m.Errors = append(m.Errors, r.Error)
		}
	}

	if m.Histogram != nil {
		m.Histogram.Add(r)
	}
}

// Close implements the Close method of the Report interface by computing
// derived summary metrics which don't need to be run on every Add call.
// All derived metrics are computed from the complete sample set, so an
// empty Metrics stays at its zero values instead of producing NaNs.
func (m *Metrics) Close() {
	m.init()

	// With no samples there is nothing to aggregate; leave every derived
	// metric at its zero value rather than dividing by zero.
	if m.Requests == 0 {
		return
	}

	// The measurement window spans from the first request sent to the last
	// request sent. Responses still in flight after the last request was sent
	// (m.Wait) fall outside this window and must not inflate rate calculations.
	m.Duration = m.Latest.Sub(m.Earliest)
	m.Wait = m.End.Sub(m.Latest)

	m.BytesIn.Mean = float64(m.BytesIn.Total) / float64(m.Requests)
	m.BytesOut.Mean = float64(m.BytesOut.Total) / float64(m.Requests)

	// Success is the exact ratio of successful requests over the total. It is
	// bounded to [0, 1] by construction, so 100% successful runs report 1.0
	// exactly rather than an approximation.
	m.Success = float64(m.success) / float64(m.Requests)
	m.Latencies.Mean = time.Duration(float64(m.Latencies.Total) / float64(m.Requests))
	m.Latencies.P50 = m.Latencies.Quantile(0.50)
	m.Latencies.P90 = m.Latencies.Quantile(0.90)
	m.Latencies.P95 = m.Latencies.Quantile(0.95)
	m.Latencies.P99 = m.Latencies.Quantile(0.99)

	// Rate and throughput are both measured over the same request window. A
	// single request, or requests sharing a timestamp, has a zero-length
	// window: there is no measurable interval, so the rates stay zero instead
	// of dividing by zero or producing an infinite value.
	if secs := m.Duration.Seconds(); secs > 0 {
		m.Rate = float64(m.Requests) / secs
		m.Throughput = float64(m.success) / secs
	}
}

func (m *Metrics) init() {
	if m.StatusCodes == nil {
		m.StatusCodes = map[string]int{}
	}

	if m.errors == nil {
		m.errors = map[string]struct{}{}
	}

	if m.Errors == nil {
		m.Errors = make([]string, 0)
	}
}

// LatencyMetrics holds computed request latency metrics.
type LatencyMetrics struct {
	// Total is the total latency sum of all requests in an attack.
	Total time.Duration `json:"total"`
	// Mean is the mean request latency.
	Mean time.Duration `json:"mean"`
	// P50 is the 50th percentile request latency.
	P50 time.Duration `json:"50th"`
	// P90 is the 90th percentile request latency.
	P90 time.Duration `json:"90th"`
	// P95 is the 95th percentile request latency.
	P95 time.Duration `json:"95th"`
	// P99 is the 99th percentile request latency.
	P99 time.Duration `json:"99th"`
	// Max is the maximum observed request latency.
	Max time.Duration `json:"max"`
	// Min is the minimum observed request latency.
	Min time.Duration `json:"min"`

	estimator estimator
}

// Add adds the given latency to the latency metrics.
func (l *LatencyMetrics) Add(latency time.Duration) {
	l.init()
	l.Total += latency
	if l.estimator.Len() == 0 || latency < l.Min {
		l.Min = latency
	}
	if latency > l.Max {
		l.Max = latency
	}
	l.estimator.Add(float64(latency))
}

// Quantile returns the nth quantile from the latency summary. The returned
// value is computed from the sorted samples and always falls within the
// observed [Min, Max] range, so it can never exceed Max or drop below Min.
func (l LatencyMetrics) Quantile(nth float64) time.Duration {
	l.init()
	return time.Duration(l.estimator.Get(nth))
}

func (l *LatencyMetrics) init() {
	if l.estimator == nil {
		l.estimator = newSortedSamplesEstimator()
	}
}

// ByteMetrics holds computed byte flow metrics.
type ByteMetrics struct {
	// Total is the total number of flowing bytes in an attack.
	Total uint64 `json:"total"`
	// Mean is the mean number of flowing bytes per hit.
	Mean float64 `json:"mean"`
}

type estimator interface {
	Add(sample float64)
	Get(quantile float64) float64
	Len() int
}

// sortedSamplesEstimator keeps every observed sample and computes exact
// quantiles from the sorted sample set. Unlike streaming digest estimators,
// its results are actual observed values (or interpolations between adjacent
// ones) and are therefore always bounded by the minimum and maximum samples.
type sortedSamplesEstimator struct {
	samples []float64
	sorted  bool
}

func newSortedSamplesEstimator() *sortedSamplesEstimator {
	return &sortedSamplesEstimator{sorted: true}
}

func (e *sortedSamplesEstimator) Add(s float64) {
	// Samples are usually appended in arbitrary order, so the slice becomes
	// unsorted as soon as a new sample is smaller than the previous one.
	// After a sort, samples[len-1] is the maximum, so the same check remains
	// valid even if Adds are interleaved with Get calls.
	if e.sorted && len(e.samples) > 0 && s < e.samples[len(e.samples)-1] {
		e.sorted = false
	}
	e.samples = append(e.samples, s)
}

func (e *sortedSamplesEstimator) Len() int { return len(e.samples) }

// Get returns the quantile at q in [0, 1] using linear interpolation between
// the two closest ranks (the R-7 method, same definition used by NumPy and
// Go's external quantile libraries). The result is clamped to the observed
// sample range, so q=0 yields the minimum and q=1 the maximum.
func (e *sortedSamplesEstimator) Get(q float64) float64 {
	n := len(e.samples)
	if n == 0 {
		return 0
	}

	if !e.sorted {
		sort.Float64s(e.samples)
		e.sorted = true
	}

	q = math.Max(0, math.Min(1, q))
	if n == 1 {
		return e.samples[0]
	}

	// Continuous rank of the quantile over indices [0, n-1].
	pos := q * float64(n-1)
	lo := float64(int(pos))
	hi := math.Ceil(pos)
	if lo == hi {
		return e.samples[int(lo)]
	}

	frac := pos - lo
	return e.samples[int(lo)]*(1-frac) + e.samples[int(hi)]*frac
}
