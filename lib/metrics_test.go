package vegeta

import (
	"io"
	"math"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestMetrics_Add(t *testing.T) {
	t.Parallel()

	codes := []uint16{500, 200, 302}
	errors := []string{"Internal server error", ""}

	var got Metrics
	for i := 1; i <= 10000; i++ {
		got.Add(&Result{
			Code:      codes[i%len(codes)],
			Timestamp: time.Unix(int64(i-1), 0),
			Latency:   time.Duration(i) * time.Microsecond,
			BytesIn:   1024,
			BytesOut:  512,
			Error:     errors[i%len(errors)],
		})
	}
	got.Close()

	duration := func(s string) time.Duration {
		d, err := time.ParseDuration(s)
		if err != nil {
			panic(err)
		}
		return d
	}

	want := Metrics{
		Latencies: LatencyMetrics{
			Total:     duration("50.005s"),
			Mean:      duration("5.0005ms"),
			P50:       duration("5.0005ms"),
			P90:       duration("9.0001ms"),
			P95:       duration("9.50005ms"),
			P99:       duration("9.90001ms"),
			Max:       duration("10ms"),
			Min:       duration("1us"),
			estimator: got.Latencies.estimator,
		},
		BytesIn:     ByteMetrics{Total: 10240000, Mean: 1024},
		BytesOut:    ByteMetrics{Total: 5120000, Mean: 512},
		Earliest:    time.Unix(0, 0),
		Latest:      time.Unix(9999, 0),
		End:         time.Unix(9999, 0).Add(10000 * time.Microsecond),
		Duration:    duration("2h46m39s"),
		Wait:        duration("10ms"),
		Requests:    10000,
		Rate:        1.000100010001,
		Throughput:  0.6667666766676668,
		Success:     0.6667,
		StatusCodes: map[string]int{"500": 3333, "200": 3334, "302": 3333},
		Errors:      []string{"Internal server error"},

		errors:  got.errors,
		success: got.success,
	}

	opts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			Metrics{},
			LatencyMetrics{},
			ByteMetrics{},
		),
		equateApproxDuration(time.Nanosecond),
	}

	if diff := cmp.Diff(got, want, opts...); diff != "" {
		t.Errorf("mismatch: %s", diff)
	}
}

func equateApproxDuration(margin time.Duration) cmp.Option {
	if margin < 0 {
		panic("margin must be a non-negative number")
	}
	a := durationApproximator{margin}
	return cmp.FilterValues(areNonZeroDurations, cmp.Comparer(a.compare))
}

func areNonZeroDurations(x, y time.Duration) bool {
	return x != 0 && y != 0
}

type durationApproximator struct {
	margin time.Duration
}

func (a durationApproximator) compare(x, y time.Duration) bool {
	// Avoid subtracting times to avoid overflow when the
	// difference is larger than the largest representable duration.
	if x > y {
		// Ensure x is always before y
		x, y = y, x
	}
	// We're within the margin if x+margin >= y.
	return (x + a.margin) >= y
}

// https://github.com//tsenart/vegeta/issues/208
func TestMetrics_NoInfiniteRate(t *testing.T) {
	t.Parallel()

	// A single request defines a zero-length measurement window, so there is
	// no interval over which a rate can be computed. It must stay zero rather
	// than becoming +Inf or NaN through a division by zero.
	m := Metrics{Requests: 1, Duration: time.Microsecond}
	m.Close()

	if got, want := m.Rate, 0.0; got != want {
		t.Errorf("got rate %f, want %f", got, want)
	}
	if got, want := m.Throughput, 0.0; got != want {
		t.Errorf("got throughput %f, want %f", got, want)
	}
	if math.IsInf(m.Rate, 0) || math.IsNaN(m.Rate) {
		t.Errorf("rate must be finite, got %v", m.Rate)
	}
}

// TestMetrics_RateAndThroughputWindow verifies that rate and throughput are
// computed over the request window (Latest - Earliest) and that the wait for
// in-flight responses after the last request is not counted.
func TestMetrics_RateAndThroughputWindow(t *testing.T) {
	t.Parallel()

	var m Metrics
	// Two requests sent one second apart; the last one takes 500ms to answer.
	m.Add(&Result{Code: 200, Timestamp: time.Unix(0, 0), Latency: time.Millisecond})
	m.Add(&Result{Code: 200, Timestamp: time.Unix(1, 0), Latency: 500 * time.Millisecond})
	m.Close()

	if got, want := m.Duration, time.Second; got != want {
		t.Errorf("got duration %s, want %s", got, want)
	}
	if got, want := m.Wait, 500*time.Millisecond; got != want {
		t.Errorf("got wait %s, want %s", got, want)
	}
	// Both requests and both successes over a 1s window, excluding the wait.
	if got, want := m.Rate, 2.0; got != want {
		t.Errorf("got rate %f, want %f", got, want)
	}
	if got, want := m.Throughput, 2.0; got != want {
		t.Errorf("got throughput %f, want %f", got, want)
	}
}

// TestMetrics_SuccessBoundaries pins down the exact success ratio at the
// boundaries: all successful, all failed and partial mixes must match the
// integer count ratio without approximation errors.
func TestMetrics_SuccessBoundaries(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		codes   []uint16
		success float64
	}{
		{"all successful", []uint16{200, 201, 204, 301}, 1.0},
		{"all failed", []uint16{0, 500, 404, 503}, 0.0},
		{"one of three", []uint16{200, 500, 502}, 1.0 / 3.0},
		{"two of three", []uint16{200, 302, 500}, 2.0 / 3.0},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var m Metrics
			for i, code := range tc.codes {
				m.Add(&Result{
					Code:      code,
					Timestamp: time.Unix(int64(i), 0),
					Latency:   time.Millisecond,
				})
			}
			m.Close()

			if m.Success != tc.success {
				t.Errorf("got success %v, want %v", m.Success, tc.success)
			}
			// The exact ratio must survive percentage rendering: a fully
			// successful run reports 100.00%, never 99.9x%.
			if pct := m.Success * 100; pct < 0 || pct > 100 {
				t.Errorf("success percentage out of range: %v", pct)
			}
		})
	}
}

// TestMetrics_QuantilesWithinSampleRange verifies the original customer-facing
// defect: percentiles computed from the sorted samples can never escape the
// observed [Min, Max] range, even with a skewed latency distribution.
func TestMetrics_QuantilesWithinSampleRange(t *testing.T) {
	t.Parallel()

	var m Metrics
	// Mostly small latencies with a few multi-second outliers, unsorted.
	latencies := []time.Duration{
		2 * time.Second, 3 * time.Millisecond, 1 * time.Millisecond,
		7 * time.Millisecond, 5 * time.Millisecond, 2 * time.Millisecond,
		9 * time.Millisecond, 4 * time.Millisecond, 6 * time.Millisecond,
		8 * time.Millisecond, 5 * time.Second,
	}
	for i, latency := range latencies {
		m.Add(&Result{
			Code:      200,
			Timestamp: time.Unix(int64(i), 0),
			Latency:   latency,
		})
	}
	m.Close()

	min, max := time.Millisecond, 5*time.Second
	for _, tc := range []struct {
		name string
		got  time.Duration
	}{
		{"P50", m.Latencies.P50},
		{"P90", m.Latencies.P90},
		{"P95", m.Latencies.P95},
		{"P99", m.Latencies.P99},
	} {
		if tc.got < min || tc.got > max {
			t.Errorf("%s=%s outside sample range [%s, %s]", tc.name, tc.got, min, max)
		}
	}

	// The extremes of the quantile range collapse onto the observed extremes.
	if got := m.Latencies.Quantile(0); got != min {
		t.Errorf("quantile(0) = %s, want min %s", got, min)
	}
	if got := m.Latencies.Quantile(1); got != max {
		t.Errorf("quantile(1) = %s, want max %s", got, max)
	}
	// Out-of-range quantile arguments are clamped instead of extrapolating.
	if got := m.Latencies.Quantile(2); got != max {
		t.Errorf("quantile(2) = %s, want max %s", got, max)
	}
	if got := m.Latencies.Quantile(-1); got != min {
		t.Errorf("quantile(-1) = %s, want min %s", got, min)
	}
}

// TestMetrics_ZeroLatencySample ensures a zero latency is treated as a real
// minimum rather than an unset sentinel.
func TestMetrics_ZeroLatencySample(t *testing.T) {
	t.Parallel()

	var m Metrics
	m.Add(&Result{Code: 200, Timestamp: time.Unix(0, 0), Latency: 0})
	m.Add(&Result{Code: 200, Timestamp: time.Unix(1, 0), Latency: time.Millisecond})
	m.Close()

	if m.Latencies.Min != 0 {
		t.Errorf("got min %s, want 0", m.Latencies.Min)
	}
	if m.Latencies.Quantile(0) != 0 {
		t.Errorf("quantile(0) = %s, want 0", m.Latencies.Quantile(0))
	}
}

// https://github.com/tsenart/vegeta/pull/277
func TestMetrics_NonNilErrorsOnClose(t *testing.T) {
	t.Parallel()

	m := Metrics{Errors: nil}
	m.Close()

	got, want := m.Errors, []string{}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("\ngot:  %+v\nwant: %+v", got, want)
	}
}

// https://github.com/tsenart/vegeta/issues/461
func TestMetrics_EmptyMetricsCanBeReported(t *testing.T) {
	t.Parallel()

	var m Metrics
	m.Close()

	// An empty result set yields zero values, never NaN or Inf, so reports
	// remain numerically valid without any samples.
	if m.Requests != 0 || m.Rate != 0 || m.Throughput != 0 || m.Success != 0 {
		t.Errorf("empty Metrics has non-zero counters: %+v", m)
	}
	for _, f := range []float64{m.Rate, m.Throughput, m.Success, m.BytesIn.Mean, m.BytesOut.Mean} {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			t.Errorf("empty Metrics contains NaN/Inf value: %v", f)
		}
	}
	for _, q := range []float64{0, 0.5, 0.99, 1} {
		if got := m.Latencies.Quantile(q); got != 0 {
			t.Errorf("empty quantile(%v) = %s, want 0", q, got)
		}
	}

	reporter := NewJSONReporter(&m)
	if err := reporter(io.Discard); err != nil {
		t.Error(err)
	}
}
func BenchmarkMetrics(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #skipcq: GSC-G404

	latencies := make([]time.Duration, 1000000)
	for i := range latencies {
		latencies[i] = time.Duration(1e6 + rng.Int63n(1e10-1e6)) // 1ms to 10s
	}

	m := Metrics{Latencies: LatencyMetrics{estimator: newSortedSamplesEstimator()}}

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Add(&Result{
				Code:      200,
				Timestamp: time.Unix(int64(i), 0),
				Latency:   latencies[i%len(latencies)],
				BytesIn:   1024,
				BytesOut:  512,
			})
		}
	})

	b.Run("Close", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Close()
		}
	})

}
