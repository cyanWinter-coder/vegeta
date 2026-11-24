package vegeta

import (
	"net/http"
	"strconv"
)

// SnapshotHandler returns an http.Handler that serves a fresh, finalized
// cumulative metrics snapshot on every request. It is the pull-based
// counterpart of the Snapshots channel: a monitoring panel polling every
// couple of seconds can simply decode the JSON body as Metrics.
//
//	rep := vegeta.NewIncrementalReporter(2 * time.Second)
//	go http.ListenAndServe(":8080", rep.SnapshotHandler())
//
// Slow clients only occupy their own handler goroutine while the response is
// written; they never block Adds.
//
// The ?format=text query parameter renders the snapshot with the compatible
// plain text reporter instead of JSON.
func (r *IncrementalReporter) SnapshotHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		snap := r.Snapshot()

		switch req.URL.Query().Get("format") {
		case "text":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Dropped-Snapshots", strconv.FormatUint(r.DroppedSnapshots(), 10))
			_ = NewTextReporter(snap)(w)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Dropped-Snapshots", strconv.FormatUint(r.DroppedSnapshots(), 10))
			_ = NewJSONReporter(snap)(w)
		}
	})
}

// ServeHTTP makes IncrementalReporter itself usable as an http.Handler. It is
// equivalent to mounting SnapshotHandler at the mux root.
func (r *IncrementalReporter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.SnapshotHandler().ServeHTTP(w, req)
}
