package vegeta

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// validTestConfig returns a deterministic baseline configuration. Tests
// mutate individual fields on top of it.
func validTestConfig() AdaptivePacerConfig {
	return AdaptivePacerConfig{
		InitialRate:      10,
		MinRate:          1,
		MaxRate:          100,
		MaxStepUp:        5,
		MaxStepDown:      20,
		Cooldown:         time.Second,
		Window:           10 * time.Second,
		MaxWindowSamples: 128,
		LatencySLO:       100 * time.Millisecond,
		MaxErrorRate:     0.1,
		MaxInFlight:      0,
		SafeRate:         1,
		Seed:             42,
	}
}

// feedSample appends one synthetic feedback observation, simulating an
// accepted request whose result settled at the given attack-relative time.
func feedSample(p *AdaptivePacer, at time.Duration, latency time.Duration, err bool) {
	p.onResult(&Result{
		Timestamp: p.began.Add(at),
		Latency:   latency,
		Error:     boolError(err),
	})
}

func boolError(err bool) string {
	if err {
		return "boom"
	}
	return ""
}

// feedN appends n observations within the feedback window.
func feedN(p *AdaptivePacer, n int, latency time.Duration, errFraction float64) {
	for i := 0; i < n; i++ {
		feedSample(p, time.Duration(i+1)*time.Millisecond, latency,
			float64(i)/float64(n) < errFraction)
	}
}

func TestAdaptivePacer_ImplementsInterfaces(t *testing.T) {
	t.Parallel()
	var (
		_ Pacer         = (*AdaptivePacer)(nil)
		_ feedbackPacer = (*AdaptivePacer)(nil)
	)
}

func TestAdaptivePacer_InvalidConfigFallsBackToSafeRate(t *testing.T) {
	t.Parallel()

	for _, mutate := range []func(*AdaptivePacerConfig){
		func(c *AdaptivePacerConfig) { c.Window = 0 },
		func(c *AdaptivePacerConfig) { c.Window = -time.Second },
		func(c *AdaptivePacerConfig) { c.LatencySLO = 0 },
		func(c *AdaptivePacerConfig) { c.LatencySLO = -time.Millisecond },
		func(c *AdaptivePacerConfig) { c.MaxErrorRate = 1.5 },
		func(c *AdaptivePacerConfig) { c.MaxRate = c.MinRate / 2 },
	} {
		cfg := validTestConfig()
		mutate(&cfg)
		p := NewAdaptivePacer(cfg)
		snap := p.Snapshot()
		if snap.LastReason != ReasonInvalidConfig {
			t.Fatalf("last reason = %q, want %q", snap.LastReason, ReasonInvalidConfig)
		}
		if snap.Rate != cfg.SafeRate {
			t.Fatalf("rate = %v, want safe rate %v", snap.Rate, cfg.SafeRate)
		}
		// Healthy feedback must not move the pacer off its safe rate.
		feedN(p, 50, time.Millisecond, 0)
		for i := 1; i <= 10; i++ {
			if rate, _ := p.decide(time.Duration(i) * time.Second); rate != cfg.SafeRate {
				t.Fatalf("invalid-config pacer moved to %v at step %d", rate, i)
			}
		}
		if h := p.History(); len(h) != 1 || h[0].Reason != ReasonInvalidConfig {
			t.Fatalf("history = %+v, want single invalid-config entry", h)
		}
	}
}

func TestAdaptivePacer_EmptyWindowHoldsRate(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())

	rate, reason := p.decide(time.Second)
	if rate != 10 {
		t.Fatalf("rate = %v, want 10", rate)
	}
	if reason != ReasonEmptyWindow {
		t.Fatalf("reason = %q, want %q", reason, ReasonEmptyWindow)
	}

	// All samples older than the window are ignored: same hold behavior.
	feedSample(p, 0, time.Millisecond, false)
	rate, reason = p.decide(20 * time.Second)
	if rate != 10 || reason != ReasonEmptyWindow {
		t.Fatalf("stale-sample decision = (%v, %q), want (10, %q)", rate, reason, ReasonEmptyWindow)
	}
	if p.Snapshot().HasWindow {
		t.Fatal("snapshot should not report a window for empty windows")
	}
}

func TestAdaptivePacer_LatencySLOBreachDecreasesRate(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig()
	cfg.MaxStepDown = 5
	p := NewAdaptivePacer(cfg)
	feedN(p, 50, 150*time.Millisecond, 0) // p95 > 100ms SLO

	rate, reason := p.decide(time.Second)
	if reason != ReasonLatencySLO {
		t.Fatalf("reason = %q, want %q", reason, ReasonLatencySLO)
	}
	if want := 10.0 - cfg.MaxStepDown; rate != want {
		t.Fatalf("rate = %v, want %v", rate, want)
	}

	h := p.History()
	if len(h) != 1 || h[0].Reason != ReasonLatencySLO || h[0].From != 10 || h[0].To != rate {
		t.Fatalf("history = %+v", h)
	}
	if h[0].Window.Samples != 50 || h[0].Window.P95 != 150*time.Millisecond {
		t.Fatalf("history window = %+v", h[0].Window)
	}
}

func TestAdaptivePacer_ErrorRateBreachDecreasesRate(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())
	// Healthy latency so the latency branch does not fire, but a 50%
	// error rate against the 10% limit.
	feedN(p, 40, time.Millisecond, 0.5)

	rate, reason := p.decide(time.Second)
	if reason != ReasonErrorRate {
		t.Fatalf("reason = %q, want %q", reason, ReasonErrorRate)
	}
	if rate >= 10 {
		t.Fatalf("rate = %v, want a decrease from 10", rate)
	}
}

func TestAdaptivePacer_InFlightLimitDecreasesRate(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig()
	cfg.MaxInFlight = 5
	p := NewAdaptivePacer(cfg)

	// Healthy latency and zero errors, but 8 accepted hits with only 3
	// results observed leaves 5 in flight, at the limit.
	for i := 0; i < 8; i++ {
		p.onAccepted()
	}
	for i := 0; i < 3; i++ {
		feedSample(p, time.Duration(i+1)*time.Millisecond, time.Millisecond, false)
	}

	_, reason := p.decide(time.Second)
	if reason != ReasonInFlight {
		t.Fatalf("reason = %q, want %q", reason, ReasonInFlight)
	}
	snap := p.Snapshot()
	if snap.InFlight != 5 || snap.Accepted != 8 || snap.Completed != 3 {
		t.Fatalf("counters = %+v", snap)
	}
}

func TestAdaptivePacer_HealthyWindowIncreasesRateWithinStep(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())
	feedN(p, 50, time.Millisecond, 0)

	rate, reason := p.decide(time.Second)
	if reason != ReasonHealthy {
		t.Fatalf("reason = %q, want %q", reason, ReasonHealthy)
	}
	if delta := rate - 10; delta <= 0 || delta > p.cfg.MaxStepUp {
		t.Fatalf("rate = %v; increase must be in (0, %v]", rate, p.cfg.MaxStepUp)
	}
	if rate < p.cfg.MinRate || rate > p.cfg.MaxRate {
		t.Fatalf("rate %v outside bounds [%v, %v]", rate, p.cfg.MinRate, p.cfg.MaxRate)
	}
}

func TestAdaptivePacer_CooldownBlocksAllChanges(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())

	// First change at t=1s.
	feedN(p, 20, time.Millisecond, 0)
	if _, reason := p.decide(time.Second); reason != ReasonHealthy {
		t.Fatalf("first decision reason = %q", reason)
	}
	first := p.Snapshot().Rate

	// A breach at t=1.5s must be deferred by the cooldown, not applied.
	feedN(p, 20, 500*time.Millisecond, 1)
	rate, reason := p.decide(1500 * time.Millisecond)
	if reason != ReasonCoolingDown {
		t.Fatalf("reason = %q, want %q", reason, ReasonCoolingDown)
	}
	if rate != first {
		t.Fatalf("rate changed during cooldown: %v -> %v", first, rate)
	}
	if len(p.History()) != 1 {
		t.Fatalf("cooldown decision must not be recorded in history: %+v", p.History())
	}

	// After the cooldown elapses, the breach drives a decrease.
	rate, reason = p.decide(2500 * time.Millisecond)
	if reason != ReasonLatencySLO || rate >= first {
		t.Fatalf("post-cooldown decision = (%v, %q)", rate, reason)
	}
}

func TestAdaptivePacer_RateBoundsAreHard(t *testing.T) {
	t.Parallel()

	t.Run("floor", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.InitialRate = cfg.MinRate
		p := NewAdaptivePacer(cfg)
		for i := 1; i <= 12; i++ {
			// Refresh the window every iteration so breaches stay visible.
			feedSample(p, time.Duration(i)*900*time.Millisecond, time.Second, true)
			rate, _ := p.decide(time.Duration(i) * time.Second)
			if rate < cfg.MinRate {
				t.Fatalf("rate %v breached min %v at step %d", rate, cfg.MinRate, i)
			}
		}
		if p.Snapshot().LastReason != ReasonRateClamped {
			t.Fatalf("last reason = %q, want %q", p.Snapshot().LastReason, ReasonRateClamped)
		}
	})

	t.Run("ceiling", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.InitialRate = cfg.MaxRate - 1
		p := NewAdaptivePacer(cfg)
		for i := 1; i <= 40; i++ {
			feedSample(p, time.Duration(i)*1900*time.Millisecond, time.Millisecond, false)
			rate, _ := p.decide(time.Duration(i) * 2 * time.Second)
			if rate > cfg.MaxRate {
				t.Fatalf("rate %v breached max %v at step %d", rate, cfg.MaxRate, i)
			}
		}
	})
}

func TestAdaptivePacer_SeedDeterminism(t *testing.T) {
	t.Parallel()

	run := func(seed int64) []float64 {
		p := NewAdaptivePacer(func() AdaptivePacerConfig {
			cfg := validTestConfig()
			cfg.Seed = seed
			return cfg
		}())
		rates := make([]float64, 0, 5)
		for i := 1; i <= 5; i++ {
			feedN(p, 20, time.Millisecond, 0)
			rate, _ := p.decide(time.Duration(i) * 2 * time.Second)
			rates = append(rates, rate)
		}
		return rates
	}

	a, b := run(42), run(42)
	if len(a) != len(b) {
		t.Fatalf("length mismatch: %v vs %v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("seed determinism broken at step %d: %v vs %v", i, a, b)
		}
	}

	// Different seeds may still coincide by chance, but full-vector
	// equality is vanishingly unlikely with 5 jittered steps.
	if other := run(99); floatsEqual(other, a) {
		t.Fatalf("different seeds produced identical sequences: %v", a)
	}
}

func TestAdaptivePacer_HaltsFreezeIncreasesOnly(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())
	feedN(p, 30, time.Millisecond, 0)

	// Healthy decision would raise the rate.
	healthyRate, _ := p.decide(time.Second)
	if healthyRate <= 10 {
		t.Fatalf("setup: expected increase, got %v", healthyRate)
	}

	p.onHalt(HaltAttackerStopped)
	if p.Snapshot().Halted != HaltAttackerStopped {
		t.Fatal("halt reason not recorded")
	}
	if h := p.History(); len(h) != 2 || h[1].HaltReason != HaltAttackerStopped {
		t.Fatalf("history missing halt transition: %+v", h)
	}

	// Healthy signal while halted: rate frozen, explicit halted reason.
	rate, reason := p.decide(3 * time.Second)
	if reason != ReasonHalted || rate != healthyRate {
		t.Fatalf("halted healthy decision = (%v, %q)", rate, reason)
	}

	// A breach while halted still decreases: protection is not suppressed.
	feedN(p, 30, 500*time.Millisecond, 1)
	rate, reason = p.decide(4 * time.Second)
	if reason != ReasonLatencySLO || rate >= healthyRate {
		t.Fatalf("halted breach decision = (%v, %q)", rate, reason)
	}

	// Repeated identical halt signals do not flood the history.
	p.onHalt(HaltAttackerStopped)
	p.onHalt(HaltAttackerStopped)
	var halts int
	for _, h := range p.History() {
		if h.Reason == ReasonHalted {
			halts++
		}
	}
	if halts != 1 {
		t.Fatalf("want 1 halt entry, got %d", halts)
	}
}

func TestAdaptivePacer_ContextCancellationFreezesIncreases(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := validTestConfig()
	cfg.Context = ctx
	p := NewAdaptivePacer(cfg)
	feedN(p, 30, time.Millisecond, 0)

	cancel()
	rate, reason := p.decide(time.Second)
	if reason != ReasonHalted {
		t.Fatalf("reason = %q, want %q", reason, ReasonHalted)
	}
	if p.Snapshot().Halted != HaltContext {
		t.Fatalf("halted = %q, want %q", p.Snapshot().Halted, HaltContext)
	}
	if rate != 10 {
		t.Fatalf("rate = %v, want frozen 10", rate)
	}
}

func TestAdaptivePacer_WorkerSaturationHoldsForCooldown(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())
	feedN(p, 30, time.Millisecond, 0)

	// Prime the clock at t=1s, then saturation arms a hold until t=2s.
	if _, reason := p.decide(time.Second); reason != ReasonHealthy {
		t.Fatalf("priming decision reason = %q", reason)
	}
	p.onWorkersSaturated()
	if _, reason := p.decide(1500 * time.Millisecond); reason != ReasonWorkersSaturated {
		t.Fatalf("saturation decision reason = %q, want %q", reason, ReasonWorkersSaturated)
	}
	// Hold window elapses at 2s; the cooldown for rate changes also gates
	// the following increase, so the first healthy change lands at t>=2s
	// with the cooldown (1s) measured from the change at t=1s.
	rate, reason := p.decide(2500 * time.Millisecond)
	if reason != ReasonHealthy || rate <= 10 {
		t.Fatalf("post-saturation decision = (%v, %q)", rate, reason)
	}
}

func TestAdaptivePacer_WindowStats(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())

	latencies := []time.Duration{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	for i, lat := range latencies {
		feedSample(p, time.Duration(i+1)*time.Millisecond, lat, i >= 18) // 2 errors
	}

	stats, ok := p.windowStatsLocked(time.Second)
	if !ok {
		t.Fatal("window unexpectedly empty")
	}
	if stats.Samples != 20 {
		t.Fatalf("samples = %d, want 20", stats.Samples)
	}
	wantMean := time.Duration(210 / 20) // integer division, matches the implementation
	if stats.Mean != wantMean {
		t.Fatalf("mean = %v, want %v", stats.Mean, wantMean)
	}
	if stats.Max != 20*time.Nanosecond {
		t.Fatalf("max = %v, want 20ns", stats.Max)
	}
	// p95 rank = ceil(0.95*20)-1 = 18, the 19th ordered value = 19ns.
	if stats.P95 != 19*time.Nanosecond {
		t.Fatalf("p95 = %v, want 19ns", stats.P95)
	}
	if math.Abs(stats.ErrorRate-0.1) > 1e-9 {
		t.Fatalf("error rate = %v, want 0.1", stats.ErrorRate)
	}

	// Everything falls out of the window once enough time passes.
	if _, ok := p.windowStatsLocked(30 * time.Second); ok {
		t.Fatal("window should be empty after its horizon passes")
	}
}

func TestAdaptivePacer_RingEvictionAndInFlight(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig()
	cfg.MaxWindowSamples = 4
	p := NewAdaptivePacer(cfg)

	for i := 0; i < 10; i++ {
		feedSample(p, time.Duration(i+1)*time.Millisecond, time.Millisecond, false)
	}
	if p.count != 4 {
		t.Fatalf("ring count = %d, want 4", p.count)
	}
	stats, ok := p.windowStatsLocked(time.Second)
	if !ok || stats.Samples != 4 {
		t.Fatalf("evicted window = %+v ok=%v", stats, ok)
	}

	// In-flight accounting tolerates late observations without going
	// negative.
	for i := 0; i < 3; i++ {
		p.onAccepted()
	}
	for i := 0; i < 5; i++ {
		feedSample(p, time.Second+time.Duration(i)*time.Millisecond, time.Millisecond, false)
	}
	if inflight := p.Snapshot().InFlight; inflight != 0 {
		t.Fatalf("in-flight = %d, want clamped 0", inflight)
	}
}

func TestAdaptivePacer_PaceSchedule(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(validTestConfig())

	// Constant 10 hits/s at t=0: first hit scheduled at 100ms.
	if wait, stop := p.Pace(0, 0); stop || wait != 100*time.Millisecond {
		t.Fatalf("Pace(0,0) = (%v, %t), want (100ms, false)", wait, stop)
	}
	// Catch-up: behind schedule schedules immediately and never negative.
	if wait, stop := p.Pace(2*time.Second, 0); stop || wait != 0 {
		t.Fatalf("Pace(2s,0) = (%v, %t), want (0, false)", wait, stop)
	}
	// Overflow protection mirrors ConstantPacer.
	if _, stop := p.Pace(time.Duration(math.MaxInt64), math.MaxInt64); !stop {
		t.Fatal("expected stop on overflow")
	}
}

func TestAdaptivePacer_HistoryIsBoundedAndCopied(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig()
	cfg.Cooldown = time.Nanosecond
	p := NewAdaptivePacer(cfg)

	// Force many healthy increases up to the ceiling, exceeding the cap.
	for i := 1; i <= adaptiveHistoryCap*2; i++ {
		feedN(p, 10, time.Millisecond, 0)
		p.decide(time.Duration(i) * time.Millisecond)
	}
	h := p.History()
	if len(h) > adaptiveHistoryCap {
		t.Fatalf("history length = %d, cap = %d", len(h), adaptiveHistoryCap)
	}
	h[0].To = -1
	if p.History()[0].To == -1 {
		t.Fatal("History must return a copy, not internal storage")
	}
}

func TestAdaptivePacer_DefaultsAndString(t *testing.T) {
	t.Parallel()
	p := NewAdaptivePacer(AdaptivePacerConfig{LatencySLO: time.Second, Window: time.Second, MaxRate: 40})
	snap := p.Snapshot()
	if snap.MinRate != defaultAdaptiveMinRate || snap.Rate != defaultAdaptiveMinRate {
		t.Fatalf("defaults = %+v", snap)
	}
	if p.cfg.MaxStepUp != 10 || p.cfg.MaxStepDown != 20 || p.cfg.Cooldown != defaultAdaptiveCooldown {
		t.Fatalf("step/cooldown defaults wrong: %+v", p.cfg)
	}
	if p.cfg.Context == nil {
		t.Fatal("nil context should be replaced with Background")
	}
	if s := p.String(); s == "" {
		t.Fatal("String returned empty")
	}
}

func TestAdaptivePacer_AttackIntegration(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		failMode bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := failMode
		mu.Unlock()
		if fail {
			// A deterministic error signal: no sleep-dependent latency
			// jitter, so the decision does not depend on machine load.
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := validTestConfig()
	cfg.InitialRate = 50
	cfg.MinRate = 10
	cfg.MaxRate = 500
	cfg.MaxStepUp = 60
	cfg.MaxStepDown = 100
	// Generous latency SLO so scheduling noise never looks like a breach;
	// the failure phase below drives adaptation through the error rate.
	cfg.LatencySLO = 5 * time.Second
	cfg.MaxErrorRate = 0.0
	cfg.Cooldown = 50 * time.Millisecond
	cfg.Window = time.Second

	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})

	// Phase 1: healthy target, the pacer must climb from its initial rate.
	p := NewAdaptivePacer(cfg)
	atk := NewAttacker(Workers(20), MaxWorkers(40))
	var metrics Metrics
	for res := range atk.Attack(tr, p, 2*time.Second, "adaptive") {
		metrics.Add(res)
	}
	metrics.Close()
	if got := p.Snapshot().Rate; got <= cfg.InitialRate {
		t.Fatalf("rate did not climb against a healthy target: %v -> %v", cfg.InitialRate, got)
	}
	if len(p.History()) == 0 {
		t.Fatal("expected adjustment history during healthy phase")
	}

	// Phase 2: every request errors, which must drive the rate back down.
	mu.Lock()
	failMode = true
	mu.Unlock()

	p2 := NewAdaptivePacer(cfg)
	atk2 := NewAttacker(Workers(20), MaxWorkers(40))
	var metrics2 Metrics
	for res := range atk2.Attack(tr, p2, 2*time.Second, "adaptive-errors") {
		metrics2.Add(res)
	}
	metrics2.Close()
	snap := p2.Snapshot()
	if snap.Rate >= cfg.InitialRate {
		t.Fatalf("rate did not decrease under error pressure: %v", snap.Rate)
	}
	foundBreach := false
	for _, h := range p2.History() {
		if h.Reason == ReasonErrorRate {
			foundBreach = true
		}
	}
	if !foundBreach {
		t.Fatalf("no error-rate adjustment recorded: %+v", p2.History())
	}
	// Every delivered result was accounted exactly once by Metrics and
	// did not leak into the pacer's own counters.
	if metrics2.Requests != snap.Completed {
		t.Fatalf("metrics requests = %d, pacer observations = %d", metrics2.Requests, snap.Completed)
	}
}

func TestAdaptivePacer_StopDrainsInFlight(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Release blocked handlers before closing the server, otherwise
	// server.Close would wait forever on the in-flight handler goroutines.
	t.Cleanup(func() {
		close(block)
		server.Close()
	})

	cfg := validTestConfig()
	cfg.InitialRate = 100
	p := NewAdaptivePacer(cfg)
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	// A short timeout turns blocked handlers into settled error results
	// quickly; draining, not request success, is what this test checks.
	atk := NewAttacker(Workers(4), MaxWorkers(8), Timeout(200*time.Millisecond))

	resCh := atk.Attack(tr, p, 0, "drain")
	go func() {
		time.Sleep(150 * time.Millisecond)
		atk.Stop() // triggers onHalt through the stopch path
	}()

	var delivered uint64
	for range resCh {
		delivered++
	}
	// The channel only closes after every worker drains, so all accepted
	// requests settled. The pacer observed the same number of results.
	snap := p.Snapshot()
	if delivered != snap.Completed || snap.InFlight != 0 {
		t.Fatalf("delivered=%d accepted=%d completed=%d in-flight=%d",
			delivered, snap.Accepted, snap.Completed, snap.InFlight)
	}
	if snap.Halted != HaltAttackerStopped {
		t.Fatalf("halted = %q, want %q", snap.Halted, HaltAttackerStopped)
	}
}

func TestAdaptivePacer_MaxWorkersSaturationSignalled(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // every handler parks, so workers saturate immediately
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	cfg := validTestConfig()
	cfg.InitialRate = 100
	cfg.LatencySLO = time.Hour // isolate the worker signal from latency
	p := NewAdaptivePacer(cfg)
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	// A fixed, tiny worker ceiling: the pool hits its ceiling and the
	// saturation probe must fire instead of blocking the scheduler.
	atk := NewAttacker(Workers(2), MaxWorkers(2), Timeout(100*time.Millisecond))

	for range atk.Attack(tr, p, 600*time.Millisecond, "saturation") {
	}

	// Workers remain parked for the whole attack, so the scheduler's
	// ceiling probe must have armed the saturation hold and it must still
	// be active when the attack ends.
	snap := p.Snapshot()
	if snap.Accepted == 0 || snap.Completed != snap.Accepted {
		t.Fatalf("feedback wiring broken: accepted=%d completed=%d",
			snap.Accepted, snap.Completed)
	}
	if !p.saturated {
		t.Fatalf("saturation never engaged; last reason = %q, history: %+v",
			snap.LastReason, p.History())
	}
	if snap.Rate > cfg.InitialRate {
		t.Fatalf("rate climbed to %v despite worker saturation", snap.Rate)
	}
}

func TestAdaptivePacer_ExistingPacersUnaffected(t *testing.T) {
	t.Parallel()

	// Sanity: the classic pacers do not implement feedbackPacer, so the
	// Attacker's type assertion is a no-op for them.
	for _, p := range []Pacer{
		ConstantPacer{Freq: 10, Per: time.Second},
		Rate{Freq: 10, Per: time.Second},
		SinePacer{
			Period:  time.Minute,
			Mean:    Rate{Freq: 10, Per: time.Second},
			Amp:     Rate{Freq: 5, Per: time.Second},
			StartAt: MeanUp,
		},
		LinearPacer{StartAt: Rate{Freq: 10, Per: time.Second}, Slope: 1},
	} {
		if _, ok := p.(feedbackPacer); ok {
			t.Fatalf("%T unexpectedly implements feedbackPacer", p)
		}
		if _, ok := p.(*AdaptivePacer); ok {
			t.Fatalf("%T is an AdaptivePacer", p)
		}
	}
}

func floatsEqual(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
