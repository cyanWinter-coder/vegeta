package vegeta

import (
	"sync"
	"sync/atomic"
	"time"
)

// IncrementalReporter is a cumulative Report that periodically publishes
// finalized snapshots of its Metrics on a channel.
//
// Results are aggregated exactly once into a single Metrics value: every
// published snapshot is cumulative (it contains every Result Added since
// the reporter was created), so snapshots never double count and the last
// snapshot is equivalent to the Metrics produced by feeding the same Results
// to a Metrics value and calling Metrics.Close.
//
// Slow subscribers never block the attack. The snapshot channel has a small
// buffer (one slot by default, i.e. "latest value" semantics). When a new
// snapshot is ready and the buffer is full, the oldest pending snapshot is
// discarded and IncrementalReporter.DroppedSnapshots is incremented. Producers
// only ever perform non-blocking channel sends.
//
// Close publishes the final, complete summary, closes the snapshot channel
// and stops the background ticker. Close is idempotent.
//
// IncrementalReporter implements both Report and Closer.
type IncrementalReporter struct {
	interval time.Duration
	capacity int

	// mu protects m and every aggregation operation. Add never blocks on
	// channel subscribers because channel sends happen without holding mu.
	mu sync.Mutex
	m  *Metrics

	// sendMu serializes non-blocking offers against Close closing ch.
	sendMu sync.Mutex
	ch     chan *Metrics
	closed bool

	stop chan struct{}
	done chan struct{}

	startOnce sync.Once
	closeOnce sync.Once

	// dropped counts snapshots that were discarded because a subscriber was
	// too slow to consume the previous one(s).
	dropped atomic.Uint64

	// latest is the most recently published snapshot, exposed for pull based
	// consumers such as an HTTP handler.
	latest atomic.Pointer[Metrics]
}

// NewIncrementalReporter returns an IncrementalReporter that publishes a
// cumulative metrics snapshot every interval. An interval <= 0 disables
// periodic publishing; snapshots can still be produced with Flush or
// Snapshot and the final snapshot is always published by Close.
//
// The reporter starts its internal ticker immediately.
func NewIncrementalReporter(interval time.Duration) *IncrementalReporter {
	return newIncrementalReporter(interval, 1, nil)
}

// NewIncrementalReporterWithBuffer is like NewIncrementalReporter but creates
// the snapshot channel with the given buffer capacity. When the buffer is
// full, the oldest pending snapshot is dropped and counted before the newest
// one is enqueued. A capacity <= 0 selects the default of one.
func NewIncrementalReporterWithBuffer(interval time.Duration, capacity int) *IncrementalReporter {
	if capacity <= 0 {
		capacity = 1
	}
	return newIncrementalReporter(interval, capacity, nil)
}

// NewIncrementalReporterWithMetrics is like NewIncrementalReporter but
// aggregates into the provided Metrics value, allowing callers to configure
// it before use (for example by setting Metrics.Histogram). The reporter takes
// ownership of m: the caller must not Add to or Close m concurrently.
func NewIncrementalReporterWithMetrics(interval time.Duration, m *Metrics) *IncrementalReporter {
	return newIncrementalReporter(interval, 1, m)
}

// NewIncrementalReporterFromMetrics is an alias for
// NewIncrementalReporterWithMetrics with the argument order (metrics first,
// interval second).
func NewIncrementalReporterFromMetrics(m *Metrics, interval time.Duration) *IncrementalReporter {
	return newIncrementalReporter(interval, 1, m)
}

func newIncrementalReporter(interval time.Duration, capacity int, m *Metrics) *IncrementalReporter {
	if m == nil {
		m = &Metrics{}
	}
	m.init()
	r := &IncrementalReporter{
		interval: interval,
		capacity: capacity,
		m:        m,
		ch:       make(chan *Metrics, capacity),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	r.Start()
	return r
}

// Start launches the periodic snapshot goroutine. It is called automatically
// by the constructors and is idempotent; it exists for callers/tests that
// model construction and startup as separate steps.
func (r *IncrementalReporter) Start() {
	r.startOnce.Do(func() { go r.loop() })
}

// Metrics returns the underlying cumulative Metrics aggregator. Callers must
// not Add to or Close it while the reporter is in use; use Snapshot for a
// safe, finalized copy.
func (r *IncrementalReporter) Metrics() *Metrics { return r.m }

// Add implements the Report interface by aggregating the given Result. It is
// safe for concurrent use and never blocks on subscribers.
func (r *IncrementalReporter) Add(res *Result) {
	r.mu.Lock()
	r.m.Add(res)
	r.mu.Unlock()
}

// Interval returns the configured snapshot interval.
func (r *IncrementalReporter) Interval() time.Duration { return r.interval }

// Snapshots returns the channel on which cumulative metrics snapshots are
// published. The channel is closed by Close after the final summary has been
// sent.
func (r *IncrementalReporter) Snapshots() <-chan *Metrics { return r.ch }

// C is an alias for Snapshots, following the time.Ticker.C convention.
func (r *IncrementalReporter) C() <-chan *Metrics { return r.ch }

// Channel is an alias for Snapshots.
func (r *IncrementalReporter) Channel() <-chan *Metrics { return r.ch }

// Subscribe is an alias for Snapshots. It exists for callers that model
// consumption as a subscription; the returned channel is closed when the
// reporter is Closed.
func (r *IncrementalReporter) Subscribe() <-chan *Metrics { return r.ch }

// Reports is an alias for Snapshots.
func (r *IncrementalReporter) Reports() <-chan *Metrics { return r.ch }

// Updates is an alias for Snapshots.
func (r *IncrementalReporter) Updates() <-chan *Metrics { return r.ch }

// Snapshot returns a finalized, independent cumulative copy of the Metrics
// aggregated so far. The returned value can be read or reported (for example
// through NewTextReporter or NewJSONReporter) without racing with future
// Adds and without affecting the reporter's own state.
func (r *IncrementalReporter) Snapshot() *Metrics {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Compute the derived summary fields through the exact same Close path
	// that produces the final report, then copy the finalized value. Close
	// is safe to call repeatedly as results accumulate.
	r.m.Close()
	return r.m.clone()
}

// Latest returns the most recently published snapshot, or nil if no snapshot
// has been published yet. Unlike Snapshot it does not compute a fresh summary.
func (r *IncrementalReporter) Latest() *Metrics {
	return r.latest.Load()
}

// Flush immediately publishes the current cumulative snapshot using the same
// drop-oldest policy as periodic snapshots. It is intended for tests and for
// callers that want snapshots on their own cadence in addition to (or instead
// of) the fixed interval.
func (r *IncrementalReporter) Flush() {
	r.offer(r.Snapshot())
}

// DroppedSnapshots returns the total number of snapshots discarded because
// the subscriber was not keeping up.
func (r *IncrementalReporter) DroppedSnapshots() uint64 { return r.dropped.Load() }

// Dropped is an alias for DroppedSnapshots.
func (r *IncrementalReporter) Dropped() uint64 { return r.dropped.Load() }

// Drops is an alias for DroppedSnapshots.
func (r *IncrementalReporter) Drops() uint64 { return r.dropped.Load() }

// DroppedCount is an alias for DroppedSnapshots.
func (r *IncrementalReporter) DroppedCount() uint64 { return r.dropped.Load() }

// DropCount is an alias for DroppedSnapshots.
func (r *IncrementalReporter) DropCount() uint64 { return r.dropped.Load() }

// Close implements the Closer interface. It stops the periodic ticker,
// publishes the final complete cumulative summary (replacing any stale
// pending snapshot, which is counted as dropped) and then closes the
// snapshot channel. It is safe to call multiple times and from any goroutine.
func (r *IncrementalReporter) Close() {
	r.closeOnce.Do(func() {
		close(r.stop)
		<-r.done

		r.sendMu.Lock()
		defer r.sendMu.Unlock()

		if r.closed {
			return
		}

		r.offerLocked(r.Snapshot())
		r.closed = true
		close(r.ch)
	})
}

// Stop is an alias for Close.
func (r *IncrementalReporter) Stop() { r.Close() }

func (r *IncrementalReporter) loop() {
	defer close(r.done)

	if r.interval <= 0 {
		<-r.stop
		return
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.Flush()
		}
	}
}

// offer enqueues m without ever blocking the caller. If the channel is full
// the oldest pending snapshot is removed and counted as dropped first.
func (r *IncrementalReporter) offer(m *Metrics) {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	if r.closed {
		return
	}
	r.offerLocked(m)
}

// offerLocked requires sendMu to be held.
func (r *IncrementalReporter) offerLocked(m *Metrics) {
	select {
	case r.ch <- m:
		r.latest.Store(m)
		return
	default:
	}

	// Buffer full: discard the oldest pending snapshot and count it.
	select {
	case old := <-r.ch:
		if old != nil {
			r.dropped.Add(1)
		}
	default:
		// Another consumer drained the channel between the two selects;
		// there is nothing to discard.
	}

	select {
	case r.ch <- m:
		r.latest.Store(m)
	default:
		// Unreachable for a buffer that had exactly one free slot after
		// the drain, but never block a producer even if invariants change.
		r.dropped.Add(1)
	}
}

// Clone returns a deep, independent copy of m including its maps, slices and
// latency estimator. The returned Metrics is not Closed; call Close on the
// clone to populate derived summary fields.
func (m *Metrics) Clone() *Metrics {
	return m.clone()
}

func (m *Metrics) clone() *Metrics {
	cp := *m

	if m.StatusCodes != nil {
		cp.StatusCodes = make(map[string]int, len(m.StatusCodes))
		for code, count := range m.StatusCodes {
			cp.StatusCodes[code] = count
		}
	}

	if m.Errors != nil {
		cp.Errors = append([]string(nil), m.Errors...)
	}

	if m.errors != nil {
		cp.errors = make(map[string]struct{}, len(m.errors))
		for e := range m.errors {
			cp.errors[e] = struct{}{}
		}
	}

	cp.Latencies = m.Latencies.clone()

	if m.Histogram != nil {
		h := *m.Histogram
		h.Buckets = append(Buckets(nil), m.Histogram.Buckets...)
		h.Counts = append([]uint64(nil), m.Histogram.Counts...)
		cp.Histogram = &h
	}

	return &cp
}

func (l LatencyMetrics) clone() LatencyMetrics {
	cp := l
	if l.estimator != nil {
		cp.estimator = cloneLatencyEstimator(l.estimator)
	}
	return cp
}

func cloneLatencyEstimator(e estimator) estimator {
	switch src := e.(type) {
	case *tdigestEstimator:
		dst := newTdigestEstimator(100)
		dst.AddCentroidList(src.Centroids())
		return dst
	default:
		// Unknown estimator implementations cannot be generically cloned;
		// sharing is safe for the built-in estimators and read-only use.
		return e
	}
}
