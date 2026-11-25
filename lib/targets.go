package vegeta

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// Target is an HTTP request blueprint.
//
//go:generate go run ../internal/cmd/jsonschema/main.go -type=Target -output=target.schema.json
type Target struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Body   []byte      `json:"body,omitempty"`
	Header http.Header `json:"header,omitempty"`
}

// Request creates an *http.Request out of Target and returns it along with an
// error in case of failure.
func (t *Target) Request() (*http.Request, error) {
	var body io.Reader
	if len(t.Body) != 0 {
		body = bytes.NewReader(t.Body)
	}

	req, err := http.NewRequest(t.Method, t.URL, body)
	if err != nil {
		return nil, err
	}

	for k, vs := range t.Header {
		req.Header[k] = make([]string, len(vs))
		copy(req.Header[k], vs)
	}

	if host := req.Header.Get("Host"); host != "" {
		req.Host = host
	}

	return req, nil
}

// Equal returns true if the target is equal to the other given target.
func (t *Target) Equal(other *Target) bool {
	switch {
	case t == other:
		return true
	case t == nil || other == nil:
		return false
	default:
		equal := t.Method == other.Method &&
			t.URL == other.URL &&
			bytes.Equal(t.Body, other.Body) &&
			len(t.Header) == len(other.Header)

		if !equal {
			return false
		}

		for k := range t.Header {
			left, right := t.Header[k], other.Header[k]
			if len(left) != len(right) {
				return false
			}
			for i := range left {
				if left[i] != right[i] {
					return false
				}
			}
		}

		return true
	}
}

var (
	// ErrNoTargets is returned when not enough Targets are available.
	ErrNoTargets = errors.New("no targets to attack")
	// ErrNilTarget is returned when the passed Target pointer is nil.
	ErrNilTarget = errors.New("nil target")
	// ErrNoMethod is returned by JSONTargeter when a parsed Target has
	// no method.
	ErrNoMethod = errors.New("target: required method is missing")
	// ErrNoURL is returned by JSONTargeter when a parsed Target has no
	// URL.
	ErrNoURL = errors.New("target: required url is missing")
	// TargetFormats contains the canonical list of the valid target
	// format identifiers.
	TargetFormats = []string{HTTPTargetFormat, JSONTargetFormat}
)

const (
	// HTTPTargetFormat is the human readable identifier for the HTTP target format.
	HTTPTargetFormat = "http"
	// JSONTargetFormat is the human readable identifier for the JSON target format.
	JSONTargetFormat = "json"
)

// A Targeter decodes a Target or returns an error in case of failure.
// Implementations must be safe for concurrent use.
type Targeter func(*Target) error

// Decode is a convenience method that calls the underlying Targeter function.
func (tr Targeter) Decode(t *Target) error {
	return tr(t)
}

// NewJSONTargeter returns a new targeter that decodes one Target from the
// given io.Reader on every invocation. Each target is one JSON object in its own line.
//
// The method and url fields are required. If present, the body field must be base64 encoded.
// The generated [JSON Schema](lib/target.schema.json) defines the format in detail.
//
//	{"method":"POST", "url":"https://goku/1", "header":{"Content-Type":["text/plain"], "body": "Rk9P"}
//	{"method":"GET",  "url":"https://goku/2"}
//
// body will be set as the Target's body if no body is provided in each target definition.
// hdr will be merged with the each Target's headers.
func NewJSONTargeter(src io.Reader, body []byte, header http.Header) Targeter {
	return NewJSONTargeterWithBaseURL(src, body, header, "")
}

// NewJSONTargeterWithBaseURL is NewJSONTargeter with an explicit baseURL used
// to resolve relative target URLs, mirroring NewHTTPTargeterWithBaseURL.
func NewJSONTargeterWithBaseURL(src io.Reader, body []byte, header http.Header, baseURL string) Targeter {
	type reader struct {
		*bufio.Reader
		sync.Mutex
	}
	rd := reader{Reader: bufio.NewReader(src)}

	var base *url.URL
	var baseErr error
	if baseURL != "" {
		base, baseErr = parseBaseURL(baseURL)
	}

	return func(tgt *Target) (err error) {
		if tgt == nil {
			return ErrNilTarget
		}
		if baseErr != nil {
			return baseErr
		}

		var jl jlexer.Lexer

		rd.Lock()
		for len(jl.Data) == 0 {
			if jl.Data, err = rd.ReadBytes('\n'); err != nil {
				break
			}
			jl.Data = bytes.TrimSpace(jl.Data) // Skip empty lines
		}
		rd.Unlock()

		if err != nil {
			if err == io.EOF {
				err = ErrNoTargets
			}
			return err
		}

		var t jsonTarget
		t.decode(&jl)

		if err = jl.Error(); err != nil {
			return err
		} else if t.Method == "" {
			return ErrNoMethod
		} else if t.URL == "" {
			return ErrNoURL
		}

		tgt.Method = t.Method
		if tgt.URL, err = resolveTargetURL(t.URL, base); err != nil {
			return fmt.Errorf("bad URL: %s, %w", t.URL, err)
		}
		if tgt.Body = body; len(t.Body) > 0 {
			tgt.Body = t.Body
		}

		if tgt.Header == nil {
			tgt.Header = http.Header{}
		}

		for k, vs := range header {
			tgt.Header[k] = append(tgt.Header[k], vs...)
		}

		for k, vs := range t.Header {
			tgt.Header[k] = append(tgt.Header[k], vs...)
		}

		return nil
	}
}

// A TargetEncoder encodes a Target in a format that can be read by a Targeter.
type TargetEncoder func(*Target) error

// Encode is a convenience method that calls the underlying TargetEncoder function.
func (enc TargetEncoder) Encode(t *Target) error {
	return enc(t)
}

// NewJSONTargetEncoder returns a TargetEncoder that encodes Targets in the JSON format.
func NewJSONTargetEncoder(w io.Writer) TargetEncoder {
	var jw jwriter.Writer
	return func(t *Target) error {
		(*jsonTarget)(t).encode(&jw)
		if jw.Error != nil {
			return jw.Error
		}
		jw.RawByte('\n')
		_, err := jw.DumpTo(w)
		return err
	}
}

// NewStaticTargeter returns a Targeter which round-robins over the passed
// Targets.
func NewStaticTargeter(tgts ...Target) Targeter {
	i := int64(-1)
	return func(tgt *Target) error {
		if tgt == nil {
			return ErrNilTarget
		}
		*tgt = tgts[atomic.AddInt64(&i, 1)%int64(len(tgts))]
		return nil
	}
}

// ReadAllTargets eagerly reads all Targets out of the provided Targeter.
func ReadAllTargets(t Targeter) (tgts []Target, err error) {
	for {
		var tgt Target
		if err = t(&tgt); err == ErrNoTargets {
			break
		} else if err != nil {
			return nil, err
		}
		tgts = append(tgts, tgt)
	}

	if len(tgts) == 0 {
		return nil, ErrNoTargets
	}

	return tgts, nil
}

// NewHTTPTargeter returns a new Targeter that decodes one Target from the
// given io.Reader on every invocation. The format is as follows:
//
//	GET https://foo.bar/a/b/c
//	Header-X: 123
//	Header-Y: 321
//	@/path/to/body/file
//
//	POST https://foo.bar/b/c/a
//	Header-X: 123
//
// Empty lines and lines whose first non-space character is '#' are ignored.
// Trailing whitespace never affects parsing.
//
// If baseURL is not empty, target URLs without a scheme are resolved against
// it as relative references; otherwise every target URL must be an absolute
// http or https URL. Invalid URLs and an invalid baseURL produce errors rather
// than malformed requests.
//
// body will be set as the Target's body if no body is provided.
// hdr will be merged with the each Target's headers.
func NewHTTPTargeter(src io.Reader, body []byte, hdr http.Header) Targeter {
	return NewHTTPTargeterWithBaseURL(src, body, hdr, "")
}

// NewHTTPTargeterWithBaseURL is NewHTTPTargeter with an explicit baseURL used
// to resolve relative target URLs. An invalid baseURL makes every subsequent
// Decode call fail with an error instead of producing a request.
func NewHTTPTargeterWithBaseURL(src io.Reader, body []byte, hdr http.Header, baseURL string) Targeter {
	var mu sync.Mutex
	sc := newTargetScanner(bufio.NewScanner(src))

	var base *url.URL
	var baseErr error
	if baseURL != "" {
		base, baseErr = parseBaseURL(baseURL)
	}

	return func(tgt *Target) (err error) {
		if tgt == nil {
			return ErrNilTarget
		}
		if baseErr != nil {
			return baseErr
		}

		var bodyLinePath string
		var bodyLine int
		var scannerErr error

		func() {
			mu.Lock()
			defer mu.Unlock()

			var line scannedLine
			for {
				var ok bool
				if line, ok = sc.Scan(); !ok {
					err = ErrNoTargets
					return
				}
				if line.text != "" && line.text[0] != '#' {
					break
				}
			}
			requestLine := line.line

			tgt.Body = body
			tgt.Header = http.Header{}
			for k, vs := range hdr {
				tgt.Header[k] = vs
			}

			// Fields splits on any run of whitespace, so extra spaces or tabs
			// between the method and the URL can no longer leak into the URL or
			// into a header.
			tokens := strings.Fields(line.text)
			if len(tokens) == 1 {
				err = fmt.Errorf("bad target (line %d): %q, missing URL", requestLine, line.text)
				return
			}
			if len(tokens) > 2 {
				err = fmt.Errorf("bad target (line %d): %q, unexpected fields after URL", requestLine, line.text)
				return
			}
			if !startsWithHTTPMethod(line.text) {
				err = fmt.Errorf("bad method (line %d): %s", requestLine, tokens[0])
				return
			}
			tgt.Method = tokens[0]
			if tgt.URL, err = resolveTargetURL(tokens[1], base); err != nil {
				err = fmt.Errorf("bad URL (line %d): %s, %w", requestLine, tokens[1], err)
				return
			}

			// Eagerly pull the following line so a non-EOF scanner error is
			// reported by this decode (matching the historical streaming
			// contract) and so the first header/body line can be decided on
			// without an extra scanner round trip.
			next, ok := sc.Scan()
			if !ok {
				if sc.Err() != nil {
					err = ErrNoTargets
				}
				return
			}

			for {
				switch {
				case next.text == "":
					// A blank line ends this target.
				case next.text[0] == '#':
					// Comments between a request and its headers are ignored.
				case strings.HasPrefix(next.text, "@"):
					bodyLine = next.line
					bodyLinePath = next.text[1:]
					// The line can arrive while the scanner already carries a
					// non-EOF read error: remember it so a successfully read
					// body still ends the decode with ErrNoTargets, while a
					// body read failure below gets to take precedence.
					scannerErr = sc.Err()
					return
				case startsWithHTTPMethod(next.text):
					// A new request without a separating blank line. Push it
					// back so it is decoded as its own target instead of being
					// swallowed as an (invalid) header.
					sc.unread(next)
					return
				default:
					headerTokens := strings.SplitN(next.text, ":", 2)
					if len(headerTokens) < 2 {
						err = fmt.Errorf("bad header (line %d): %s", next.line, next.text)
						return
					}
					key := strings.TrimSpace(headerTokens[0])
					val := strings.TrimSpace(headerTokens[1])
					if key == "" || val == "" {
						err = fmt.Errorf("bad header (line %d): %s", next.line, next.text)
						return
					}
					// Add key/value directly to the http.Header
					// (map[string][]string). http.Header.Add() canonicalizes
					// keys but vegeta is used to test systems that require
					// case-sensitive headers.
					tgt.Header[key] = append(tgt.Header[key], val)
				}

				if next, ok = sc.Scan(); !ok {
					if sc.Err() != nil {
						err = ErrNoTargets
					}
					return
				}
			}
		}()

		if err != nil || bodyLinePath == "" {
			return err
		}

		// Body files can block independently of the target stream, so the read
		// happens after the scanner lock is released: a slow body file must not
		// stall other targets' decodes.
		if bodyLinePath != "" {
			var readErr error
			if tgt.Body, readErr = os.ReadFile(bodyLinePath); readErr != nil {
				// A failure to open the body file is more actionable than the
				// scanner state that followed its reference, so it takes
				// precedence (and stays unwrappable to os.ErrNotExist).
				return fmt.Errorf("bad body (line %d): %w", bodyLine, readErr)
			}
			if scannerErr != nil {
				return ErrNoTargets
			}
		}
		return err
	}
}

// parseBaseURL validates the base URL targets are resolved against. It must be
// an absolute http or https URL.
func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bad base URL: %s, %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("bad base URL: %s, must be an absolute http or https URL", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("bad base URL: %s, missing host", raw)
	}
	return u, nil
}

// resolveTargetURL validates raw and, when it is not an absolute URL, resolves
// it against base. Absolute targets must use the http or https scheme and
// carry a host.
func resolveTargetURL(raw string, base *url.URL) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.IsAbs() {
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
		if u.Host == "" {
			return "", errors.New("missing host")
		}
		return u.String(), nil
	}
	if base == nil {
		return "", errors.New("relative URL without a base URL")
	}
	return base.ResolveReference(u).String(), nil
}

var httpMethodChecker = regexp.MustCompile(`^[A-Z]+\s`)

// A line starts with an http method when the first word is uppercase ascii
// followed by whitespace.
func startsWithHTTPMethod(t string) bool {
	return httpMethodChecker.MatchString(t)
}

// scannedLine pairs a trimmed line with its 1-indexed line number in the
// source. Line numbers make parse errors actionable on files maintained by
// different teams.
type scannedLine struct {
	text string
	line int
}

// targetScanner wraps a bufio.Scanner with one line of pushback while tracking
// line numbers. Text is trimmed of leading and trailing whitespace so that
// indentation and trailing spaces never affect parsing.
type targetScanner struct {
	src     *bufio.Scanner
	peeked  scannedLine
	hasPeek bool
	line    int
	err     error
}

func newTargetScanner(src *bufio.Scanner) *targetScanner {
	return &targetScanner{src: src}
}

// Scan returns the next line and true, or false at EOF or on a scanner error.
// The returned line stays available for a subsequent unread.
func (s *targetScanner) Scan() (scannedLine, bool) {
	if s.hasPeek {
		next := s.peeked
		s.hasPeek = false
		return next, true
	}
	if s.src.Scan() {
		s.line++
		return scannedLine{text: strings.TrimSpace(s.src.Text()), line: s.line}, true
	}
	s.err = s.src.Err()
	return scannedLine{}, false
}

// unread returns the line most recently returned by Scan to the head of the
// stream, preserving its original line number.
func (s *targetScanner) unread(line scannedLine) {
	s.peeked = line
	s.hasPeek = true
}

func (s *targetScanner) Err() error {
	if s.err != nil {
		return s.err
	}
	return s.src.Err()
}
