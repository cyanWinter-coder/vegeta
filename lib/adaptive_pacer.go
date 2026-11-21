package vegeta

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

// AdjustReason explains the most recent decision an AdaptivePacer made
// when evaluating its feedback window. Reasons are queryable through
// AdaptivePacer.Snapshot and AdaptivePacer.History, which makes rate
// adjustments explainable after an attack.
type AdjustReason string

const (
	// ReasonNone is the zero value before any decision has been made.
	ReasonNone AdjustReason = ""
	// ReasonInvalidConfig means the pacer configuration was rejected and
	// the pacer is permanently held at its safe rate.
	ReasonInvalidConfig AdjustReason = "invalid config"
	// ReasonEmptyWindow means no samples fell inside the sliding window,
	// so the pacer holds its current rate instead of adjusting blind.
	ReasonEmptyWindow AdjustReason = "empty window"
	// ReasonCoolingDown means a signal asked for a change, but the cooldown
	// period since the previous change has not elapsed yet.
	ReasonCoolingDown AdjustReason = "cooldown"
	// ReasonLatencySLO means the windowed p95 latency breached the SLO.
	ReasonLatencySLO AdjustReason = "latency SLO breach"
	// ReasonErrorRate means the windowed error rate exceeded the limit.
	ReasonErrorRate AdjustReason = "error rate breach"
	// ReasonInFlight means the number of requests in flight reached the
	// configured limit.
	ReasonInFlight AdjustReason = "in-flight limit"
	// ReasonWorkersSaturated means the Attacker ran out of free workers
	// and the pacer is frozen from increasing the rate for a cooldown.
	ReasonWorkersSaturated AdjustReason = "workers saturated"
	// ReasonHealthy means all feedback signals were healthy, so the pacer
	// increased the rate within its configured step limit.
	ReasonHealthy AdjustReason = "healthy"
	// ReasonRateClamped means a requested change was fully absorbed by the
	// minimum or maximum rate bound.
	ReasonRateClamped AdjustReason = "rate limit"
	// ReasonHalted means an external halt condition (Stop, context
	// cancellation or worker starvation) is blocking rate increases.
	// Breach-driven decreases remain allowed while halted.
	ReasonHalted AdjustReason = "halted"
)

// HaltReason describes why an AdaptivePacer is currently forbidden from
// increasing its rate. The zero value HaltNone means no halt is active.
type HaltReason string

const (
	// HaltNone means no halt condition is active.
	HaltNone HaltReason = ""
	// HaltContext means the configured context has been canceled.
	HaltContext HaltReason = "context canceled"
	// HaltAttackerStopped means the Attacker's Stop method has been called.
	HaltAttackerStopped HaltReason = "attacker stopped"
)

// WindowStats is the aggregated feedback derived from the samples that
// fell inside the adaptive pacer's sliding window.
type WindowStats struct {
	// Samples is the number of results aggregated in the window.
	Samples uint64
	// P95 is the 95th percentile request latency in the window.
	P95 time.Duration
	// Mean is the mean request latency in the window.
	Mean time.Duration
	// Max is the maximum request latency in the window.
	Max time.Duration
	// ErrorRate is the fraction of windowed results whose Error is set,
	// in the [0, 1] interval.
	ErrorRate float64
	// InFlight is the number of accepted requests whose results have not
	// been observed yet.
	InFlight uint64
}

// Adjustment records a single rate change or halt transition made by an
// AdaptivePacer. A bounded history of adjustments is kept in memory and
// can be queried through AdaptivePacer.History.
type Adjustment struct {
	// Time is the attack-relative timestamp at which the adjustment was
	// applied, i.e. began + Elapsed.
	Time time.Time
	// Elapsed is the elapsed attack duration reported with the Pace call
	// that triggered the adjustment.
	Elapsed time.Duration
	// From is the rate in hits per second before the adjustment.
	From float64
	// To is the rate in hits per second after the adjustment.
	To float64
	// Reason is the feedback signal that caused the adjustment.
	Reason AdjustReason
	// HaltReason is set when the entry records a halt-state transition.
	HaltReason HaltReason
	// Window is the feedback snapshot the decision was taken on. It is the
	// zero value for halt transitions, which are triggered outside Pace.
	Window WindowStats
}

// AdaptivePacerConfig configures an AdaptivePacer. All rates are expressed
// in hits per second.
type AdaptivePacerConfig struct {
	// InitialRate is the rate the attack starts with. It is clamped into
	// [MinRate, MaxRate]; the zero value defaults to MinRate.
	InitialRate float64
	// MinRate is the lower rate bound and the default safe rate. It must
	// be strictly positive; the zero value defaults to 1 hit/s.
	MinRate float64
	// MaxRate is the upper rate bound. It must be >= MinRate.
	MaxRate float64
	// MaxStepUp caps any single positive rate change in hits/s. The zero
	// value defaults to a quarter of MaxRate.
	MaxStepUp float64
	// MaxStepDown caps any single negative rate change in hits/s. The
	// zero value defaults to half of MaxRate.
	MaxStepDown float64
	// Cooldown is the minimum duration between two rate changes. It also
	// doubles as the hold-off window after worker saturation. The zero
	// value defaults to 5 seconds.
	Cooldown time.Duration
	// Window is the sliding feedback window length. It must be strictly
	// positive; an invalid window puts the pacer in permanent safe-rate
	// fallback mode.
	Window time.Duration
	// MaxWindowSamples bounds the number of results retained for window
	// aggregation, independently of Metrics. The zero value defaults to
	// 1024.
	MaxWindowSamples int
	// LatencySLO is the maximum tolerated windowed p95 latency. It must be
	// strictly positive; a zero value makes the configuration invalid.
	LatencySLO time.Duration
	// MaxErrorRate is the maximum tolerated windowed error rate in [0, 1].
	// Zero means any error triggers a rate decrease.
	MaxErrorRate float64
	// MaxInFlight, when positive, caps the number of requests in flight;
	// reaching it triggers a rate decrease. Zero disables the check and
	// leaves worker saturation as the only in-flight signal.
	MaxInFlight uint64
	// SafeRate is the rate used when the configuration is invalid. The
	// zero value defaults to MinRate.
	SafeRate float64
	// Seed makes the pacer's bounded rate jitter deterministic: identical
	// configuration, seed and feedback sequence yield identical decisions.
	// A zero seed is itself a fixed, reproducible sequence.
	Seed int64
	// Context, when canceled, freezes rate increases for as long as it
	// stays canceled. It never stops the attack itself: accepted requests
	// are still allowed to complete and settle. A nil Context is replaced
	// with context.Background.
	Context context.Context
}

// AdaptivePacerSnapshot is a point-in-time, copy-on-read view of an
// AdaptivePacer's internal state.
type AdaptivePacerSnapshot struct {
	// Rate is the current rate in hits per second.
	Rate float64
	// MinRate is the configured lower rate bound.
	MinRate float64
	// MaxRate is the configured upper rate bound.
	MaxRate float64
	// Accepted is the total number of requests handed to workers.
	Accepted uint64
	// Completed is the total number of results observed.
	Completed uint64
	// InFlight is Accepted minus Completed.
	InFlight uint64
	// Halted is the active halt condition, if any.
	Halted HaltReason
	// LastReason is the reason produced by the most recent decision.
	LastReason AdjustReason
	// Window is the most recently computed window aggregation.
	Window WindowStats
	// HasWindow reports whether Window contains a valid aggregation.
	HasWindow bool
}

const (
	defaultAdaptiveMinRate          = 1.0
	defaultAdaptiveCooldown         = 5 * time.Second
	defaultAdaptiveWindow           = 10 * time.Second
	defaultAdaptiveWindowSamples    = 1024
	defaultAdaptiveStepUpFraction   = 0.25
	defaultAdaptiveStepDownFraction = 0.5
	adaptiveHistoryCap              = 256
	// adaptiveJitterLow keeps healthy step-ups in [0.75, 1.0] of
	// MaxStepUp, so the configured maximum step is a hard bound.
	adaptiveJitterLow = 0.75
)

// feedbackPacer is the in-package extension of Pacer through which an
// Attacker feeds runtime signals back to an adaptive pacer. Existing
// pacers that do not implement it keep their exact current behaviour.
type feedbackPacer interface {
	Pacer
	// onAccepted is called by the attack scheduler after a tick has been
	// handed to a worker.
	onAccepted()
	// onResult is called by a worker after the result of an accepted hit
	// has been delivered on the results channel.
	onResult(r *Result)
	// onHalt is called when the Attacker is asked to stop. It freezes
	// rate increases without aborting in-flight requests.
	onHalt(reason HaltReason)
	// onWorkersSaturated is called when every worker is blocked and the
	// Attacker has to spawn another one to keep up.
	onWorkersSaturated()
}

// AdaptivePacer is a closed-loop Pacer which adjusts its hit rate from the
// latency, error rate and in-flight request count observed in a sliding
// feedback window. Rate changes are bounded by MinRate/MaxRate, the maximum
// step sizes and the cooldown period. Stop signals, context cancellation
// and worker starvation freeze rate increases; they never stop accepted
// requests from settling.
//
// All internal timekeeping is relative to the elapsed durations Pace
// receives, so decisions depend only on inputs and the configured seed.
// The pacer's feedback bookkeeping is fully separate from Metrics,
// histograms and error sets, so adaptation never duplicates result
// accounting.
//
// An AdaptivePacer is safe for concurrent use.
type AdaptivePacer struct {
	cfg   AdaptivePacerConfig
	began time.Time

	mu          sync.Mutex
	rng         *rand.Rand
	samples     []pacerSample
	head        int
	count       int
	accepted    uint64
	completed   uint64
	rate        float64
	lastChange  time.Duration
	lastElapsed time.Duration
	lastReason  AdjustReason
	halted      HaltReason
	saturated   bool
	// saturateElapsed is the attack-relative time until which saturation
	// holds the rate. Signals arriving before the first Pace call anchor
	// at elapsed zero.
	saturateElapsed time.Duration
	invalid         bool
	history         []Adjustment
	lastWindow      WindowStats
	hasWindow       bool
}

// pacerSample is one feedback observation: the attack-relative time and
// latency of a completed request, plus whether it carried an error.
type pacerSample struct {
	at      time.Duration
	latency time.Duration
	err     bool
}

// NewAdaptivePacer constructs an AdaptivePacer from the given
// configuration. An invalid configuration (illegal window, missing latency
// SLO or inverted rate bounds) does not panic: the returned pacer stays on
// its SafeRate for the whole attack and reports ReasonInvalidConfig through
// Snapshot and History.
func NewAdaptivePacer(cfg AdaptivePacerConfig) *AdaptivePacer {
	p := &AdaptivePacer{
		cfg:        cfg,
		began:      time.Now(),
		lastReason: ReasonNone,
	}

	if p.cfg.Context == nil {
		p.cfg.Context = context.Background()
	}
	if p.cfg.MinRate <= 0 {
		p.cfg.MinRate = defaultAdaptiveMinRate
	}
	if p.cfg.MaxRate <= 0 || p.cfg.MaxRate < p.cfg.MinRate {
		p.invalid = true
		p.cfg.MaxRate = p.cfg.MinRate
	}
	if p.cfg.SafeRate <= 0 {
		p.cfg.SafeRate = p.cfg.MinRate
	}
	if p.cfg.MaxStepUp <= 0 {
		p.cfg.MaxStepUp = p.cfg.MaxRate * defaultAdaptiveStepUpFraction
	}
	if p.cfg.MaxStepDown <= 0 {
		p.cfg.MaxStepDown = p.cfg.MaxRate * defaultAdaptiveStepDownFraction
	}
	if p.cfg.Cooldown <= 0 {
		p.cfg.Cooldown = defaultAdaptiveCooldown
	}
	if p.cfg.MaxWindowSamples <= 0 {
		p.cfg.MaxWindowSamples = defaultAdaptiveWindowSamples
	}
	if p.cfg.Window <= 0 {
		p.cfg.Window = defaultAdaptiveWindow
		p.invalid = true
	}
	if p.cfg.LatencySLO <= 0 {
		p.invalid = true
	}
	if p.cfg.MaxErrorRate < 0 || p.cfg.MaxErrorRate > 1 {
		p.invalid = true
	}

	p.rng = rand.New(rand.NewSource(cfg.Seed))
	p.samples = make([]pacerSample, p.cfg.MaxWindowSamples)

	if p.invalid {
		p.rate = p.cfg.SafeRate
		p.recordLocked(Adjustment{
			Time:   p.began,
			From:   p.cfg.InitialRate,
			To:     p.cfg.SafeRate,
			Reason: ReasonInvalidConfig,
		})
		p.lastReason = ReasonInvalidConfig
		return p
	}

	p.rate = p.cfg.InitialRate
	switch {
	case p.rate <= 0:
		p.rate = p.cfg.MinRate
	case p.rate < p.cfg.MinRate:
		p.rate = p.cfg.MinRate
	case p.rate > p.cfg.MaxRate:
		p.rate = p.cfg.MaxRate
	}

	return p
}

// Compile-time interface checks.
var (
	_ Pacer         = (*AdaptivePacer)(nil)
	_ feedbackPacer = (*AdaptivePacer)(nil)
)

// Pace implements the Pacer interface. It returns the wait until the next
// hit at the pacer's currently selected rate, using the same catch-up
// semantics as ConstantPacer: a pacer that fell behind schedules the next
// hit immediately. The stop return is only ever true on integer overflow,
// mirroring ConstantPacer; halt conditions freeze rate increases rather
// than stopping the attack.
func (p *AdaptivePacer) Pace(elapsed time.Duration, hits uint64) (time.Duration, bool) {
	rate, _ := p.decide(elapsed)
	if !(rate > 0) || math.IsNaN(rate) || math.IsInf(rate, 0) {
		rate = p.cfg.SafeRate
	}

	nsPerHit := int64(math.Round(1e9 / rate))
	if nsPerHit > 0 && uint64(math.MaxInt64)/uint64(nsPerHit) < hits {
		// We would overflow the scheduled duration if we continued.
		return 0, true
	}

	expected := uint64(math.Floor(rate * elapsed.Seconds()))
	if hits < expected {
		// Running behind, send next hit immediately.
		return 0, false
	}

	wait := time.Duration(nsPerHit*int64(hits+1)) - elapsed
	if wait < 0 {
		wait = 0
	}
	return wait, false
}

// Rate implements the Pacer interface and returns the current instantaneous
// hit rate in hits per second.
func (p *AdaptivePacer) Rate(_ time.Duration) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate
}

// String returns a pretty-printed description of the pacer.
func (p *AdaptivePacer) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf(
		"Adaptive{rate: %g hits/s, range [%g, %g], window %s, latency SLO %s}",
		p.rate, p.cfg.MinRate, p.cfg.MaxRate, p.cfg.Window, p.cfg.LatencySLO,
	)
}

// Snapshot returns a copy-on-read view of the pacer's current state.
func (p *AdaptivePacer) Snapshot() AdaptivePacerSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return AdaptivePacerSnapshot{
		Rate:       p.rate,
		MinRate:    p.cfg.MinRate,
		MaxRate:    p.cfg.MaxRate,
		Accepted:   p.accepted,
		Completed:  p.completed,
		InFlight:   p.inFlightLocked(),
		Halted:     p.halted,
		LastReason: p.lastReason,
		Window:     p.lastWindow,
		HasWindow:  p.hasWindow,
	}
}

// History returns a copy of the recorded rate changes and halt transitions,
// oldest first. The returned slice can be retained and mutated freely.
func (p *AdaptivePacer) History() []Adjustment {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Adjustment, len(p.history))
	copy(out, p.history)
	return out
}

// onAccepted implements feedbackPacer. It runs on the attack scheduler
// goroutine, serialized with Pace.
func (p *AdaptivePacer) onAccepted() {
	p.mu.Lock()
	p.accepted++
	p.mu.Unlock()
}

// onResult implements feedbackPacer. It records the result in the bounded
// feedback ring only; it never touches Metrics, histograms or error sets.
func (p *AdaptivePacer) onResult(r *Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.completed++
	p.appendSampleLocked(pacerSample{
		at:      r.Timestamp.Sub(p.began),
		latency: r.Latency,
		err:     r.Error != "",
	})
}

// onHalt implements feedbackPacer. Repeated signals with the same reason
// are deduplicated so the history records transitions only.
func (p *AdaptivePacer) onHalt(reason HaltReason) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.markHaltedLocked(reason, p.lastElapsed)
}

// onWorkersSaturated implements feedbackPacer. The rate is held for one
// cooldown window; the signal re-arms automatically if workers remain
// saturated. It is anchored at the most recently observed Pace time so a
// signal arriving between Pace calls (or before the first one) is still
// measured on the same clock as the decisions.
func (p *AdaptivePacer) onWorkersSaturated() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saturated = true
	p.saturateElapsed = p.lastElapsed + p.cfg.Cooldown
}

// decide re-evaluates the feedback window and returns the rate the next
// Pace call must schedule at, together with the reason for the decision.
// All state mutation happens under the pacer's mutex, so identical elapsed
// inputs, feedback and seed produce identical decisions.
func (p *AdaptivePacer) decide(elapsed time.Duration) (float64, AdjustReason) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastElapsed = elapsed

	if p.invalid {
		p.lastReason = ReasonInvalidConfig
		return p.cfg.SafeRate, p.lastReason
	}

	if p.cfg.Context.Err() != nil {
		p.markHaltedLocked(HaltContext, elapsed)
	}
	if p.saturated && elapsed >= p.saturateElapsed {
		p.saturated = false
	}

	stats, ok := p.windowStatsLocked(elapsed)
	if !ok {
		// No evidence in the window: hold the current rate rather than
		// adjusting blindly, which is the empty-sample safe fallback.
		p.lastReason = ReasonEmptyWindow
		return p.rate, p.lastReason
	}
	p.lastWindow = stats
	p.hasWindow = true

	desired := p.rate
	var reason AdjustReason
	switch {
	case stats.P95 > p.cfg.LatencySLO:
		reason = ReasonLatencySLO
		desired = p.rate - p.cfg.MaxStepDown
	case stats.ErrorRate > p.cfg.MaxErrorRate:
		reason = ReasonErrorRate
		desired = p.rate - p.cfg.MaxStepDown
	case p.cfg.MaxInFlight > 0 && stats.InFlight >= p.cfg.MaxInFlight:
		reason = ReasonInFlight
		desired = p.rate - p.cfg.MaxStepDown
	default:
		// Healthy signal: increases are the only action that halt and
		// worker-saturation conditions forbid. Breach-driven decreases
		// above remain permitted while halted.
		if p.halted != HaltNone {
			p.lastReason = ReasonHalted
			return p.rate, p.lastReason
		}
		if p.saturated {
			p.lastReason = ReasonWorkersSaturated
			return p.rate, p.lastReason
		}
		reason = ReasonHealthy
		desired = p.rate + p.stepUpLocked()
	}

	// The cooldown constrains every actual rate change, in both directions.
	if elapsed-p.lastChange < p.cfg.Cooldown {
		p.lastReason = ReasonCoolingDown
		return p.rate, p.lastReason
	}

	next := clampAdaptiveRate(desired, p.cfg.MinRate, p.cfg.MaxRate)
	if next == p.rate {
		p.lastReason = ReasonRateClamped
		return p.rate, p.lastReason
	}

	from := p.rate
	p.rate = next
	p.lastChange = elapsed
	p.lastReason = reason
	p.recordLocked(Adjustment{
		Time:    p.began.Add(elapsed),
		Elapsed: elapsed,
		From:    from,
		To:      next,
		Reason:  reason,
		Window:  stats,
	})
	return next, reason
}

// stepUpLocked returns the next positive step, deterministically jittered
// into [0.75, 1.0] of MaxStepUp so the configured maximum stays a hard
// bound. The caller must hold p.mu.
func (p *AdaptivePacer) stepUpLocked() float64 {
	return p.cfg.MaxStepUp * (adaptiveJitterLow + p.rng.Float64()*(1-adaptiveJitterLow))
}

// markHaltedLocked records a halt-state transition. The caller must hold
// p.mu. Repeated signals for the same reason are deduplicated.
func (p *AdaptivePacer) markHaltedLocked(reason HaltReason, elapsed time.Duration) {
	if reason == HaltNone || p.halted == reason {
		return
	}
	p.halted = reason
	p.recordLocked(Adjustment{
		Time:       p.began.Add(elapsed),
		Elapsed:    elapsed,
		From:       p.rate,
		To:         p.rate,
		Reason:     ReasonHalted,
		HaltReason: reason,
	})
}

// recordLocked appends an adjustment to the bounded history ring, dropping
// the oldest entry when full. The caller must hold p.mu.
func (p *AdaptivePacer) recordLocked(a Adjustment) {
	if len(p.history) >= adaptiveHistoryCap {
		p.history = p.history[1:]
	}
	p.history = append(p.history, a)
}

// appendSampleLocked stores a feedback observation in the bounded ring,
// overwriting the oldest sample once the ring is full. The caller must
// hold p.mu.
func (p *AdaptivePacer) appendSampleLocked(s pacerSample) {
	if p.count < len(p.samples) {
		p.samples[p.count] = s
		p.count++
		return
	}
	p.samples[p.head] = s
	p.head = (p.head + 1) % len(p.samples)
}

// inFlightLocked returns the number of accepted requests whose results
// have not been observed yet. The caller must hold p.mu.
func (p *AdaptivePacer) inFlightLocked() uint64 {
	if p.completed >= p.accepted {
		return 0
	}
	return p.accepted - p.completed
}

// windowStatsLocked aggregates the samples currently inside the sliding
// window. The window is anchored at the current Pace time, so its
// boundaries track elapsed attack time exactly. The boolean result is
// false when no sample qualifies, which is the empty-sample fallback
// condition. The caller must hold p.mu.
func (p *AdaptivePacer) windowStatsLocked(now time.Duration) (WindowStats, bool) {
	cutoff := now - p.cfg.Window

	latencies := make([]time.Duration, 0, p.count)
	var (
		sum   time.Duration
		max   time.Duration
		errs  uint64
		total uint64
	)
	for i := 0; i < p.count; i++ {
		s := p.samples[i]
		if s.at < cutoff {
			continue
		}
		total++
		latencies = append(latencies, s.latency)
		sum += s.latency
		if s.latency > max {
			max = s.latency
		}
		if s.err {
			errs++
		}
	}
	if total == 0 {
		return WindowStats{}, false
	}

	rank := int(math.Ceil(0.95*float64(total))) - 1
	if rank < 0 {
		rank = 0
	} else if rank >= len(latencies) {
		rank = len(latencies) - 1
	}

	return WindowStats{
		Samples:   total,
		P95:       quickSelectDuration(latencies, rank),
		Mean:      sum / time.Duration(total),
		Max:       max,
		ErrorRate: float64(errs) / float64(total),
		InFlight:  p.inFlightLocked(),
	}, true
}

// clampAdaptiveRate clamps rate into [min, max].
func clampAdaptiveRate(rate, min, max float64) float64 {
	if rate < min {
		return min
	}
	if rate > max {
		return max
	}
	return rate
}

// quickSelectDuration returns the k-th smallest duration in data using an
// iterative, deterministic median-of-three quickselect. It rearranges
// data in place and runs in O(n) average time.
func quickSelectDuration(data []time.Duration, k int) time.Duration {
	lo, hi := 0, len(data)-1
	for lo < hi {
		mid := lo + (hi-lo)/2
		if data[mid] < data[lo] {
			data[lo], data[mid] = data[mid], data[lo]
		}
		if data[hi] < data[lo] {
			data[lo], data[hi] = data[hi], data[lo]
		}
		if data[hi] < data[mid] {
			data[mid], data[hi] = data[hi], data[mid]
		}
		pivot := data[mid]

		i, j := lo, hi
		for i <= j {
			for data[i] < pivot {
				i++
			}
			for data[j] > pivot {
				j--
			}
			if i <= j {
				data[i], data[j] = data[j], data[i]
				i++
				j--
			}
		}

		switch {
		case k <= j:
			hi = j
		case k >= i:
			lo = i
		default:
			return pivot
		}
	}
	return data[lo]
}
