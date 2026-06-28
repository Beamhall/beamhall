package s3

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/johannesboyne/gofakes3"
)

// sigv4.go is the security-critical front the broker owns. Every beam request is
// SigV4-authenticated here BEFORE it reaches the storage engine: we look up the
// access key → beam binding, verify the request's seed signature with the beam's
// plaintext secret, enforce that the beam can only touch its own bucket, apply
// the storage quota, normalize any aws-chunked body into a plain one, and emit an
// audit event for mutations and denials. The broker is one shared container on
// every beam bridge, so this signature check — not the network — is what isolates
// beams from each other.
//
// We verify the SEED (Authorization-header) signature over the canonical request,
// using whatever payload-hash placeholder the client put in x-amz-content-sha256
// (a real hash, UNSIGNED-PAYLOAD, or a STREAMING-* marker). Per-chunk signatures
// are not re-verified: the seed signature proves the requester holds the secret,
// and body confidentiality/integrity on the private in-host bridge is not the
// threat model (PLAN §5.13). S3's signer does not double-encode the path, so the
// canonical URI is the request's escaped path verbatim.

const unsignedPayload = "UNSIGNED-PAYLOAD"

// Handler returns the broker's S3 HTTP handler: verify → scope → quota →
// normalize → serve via the current engine → audit.
func (p *Provisioner) Handler() http.Handler {
	return http.HandlerFunc(p.serve)
}

func (p *Provisioner) serve(w http.ResponseWriter, r *http.Request) {
	reg, ok := p.verify(r)
	if !ok {
		op, _, _ := classify(r, secondSeg(r.URL.EscapedPath()))
		p.emit(Event{Op: op, Bucket: firstSeg(r.URL.EscapedPath()), Result: "denied", Err: "signature does not match"})
		s3Error(w, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature we calculated does not match")
		return
	}
	// ListBuckets (GET "/") must show only the caller's own bucket — gofakes3's
	// shared local backend would otherwise leak every beam's bucket name.
	if r.Method == http.MethodGet && cleanFirst(r.URL.EscapedPath()) == "" {
		p.writeOwnBucketList(w, reg.bucket)
		return
	}
	bucket := firstSeg(r.URL.EscapedPath())
	key := secondSeg(r.URL.EscapedPath())
	if bucket != "" && bucket != reg.bucket {
		p.emit(Event{BeamID: reg.beamID, Channel: reg.channel, Op: opOf(r, key), Bucket: bucket, Key: key, Result: "denied", Err: "cross-bucket access"})
		s3Error(w, http.StatusForbidden, "AccessDenied", "access to this bucket is not allowed")
		return
	}

	op, mutation, quotaWrite := classify(r, key)

	// Quota: reject a write that would exceed the beam's cap (coarse; counts
	// committed objects via a bucket listing, not multipart-in-progress parts).
	if quotaWrite && reg.maxBytes > 0 {
		incoming := incomingSize(r)
		if incoming > 0 && p.bucketUsage(reg.bucket)+incoming > reg.maxBytes {
			p.emit(Event{BeamID: reg.beamID, Channel: reg.channel, Op: op, Bucket: bucket, Key: key, Size: incoming, Result: "denied", Err: "quota exceeded"})
			s3Error(w, http.StatusInsufficientStorage, "QuotaExceeded", "object store quota exceeded for this beam")
			return
		}
	}

	if err := normalizeChunked(r); err != nil {
		p.emit(Event{BeamID: reg.beamID, Channel: reg.channel, Op: op, Bucket: bucket, Key: key, Result: "failed", Err: err.Error()})
		s3Error(w, http.StatusBadRequest, "InvalidRequest", "malformed chunked body")
		return
	}

	faker := p.currentFaker()
	if faker == nil {
		s3Error(w, http.StatusServiceUnavailable, "ServiceUnavailable", "object store backend not ready")
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	faker.Server().ServeHTTP(rec, r)

	// Audit mutations (and any failed request); reads are not per-object audited.
	if mutation || rec.status >= 400 {
		ev := Event{BeamID: reg.beamID, Channel: reg.channel, Op: op, Bucket: bucket, Key: key, Size: incomingSize(r), Result: "ok"}
		if rec.status >= 400 {
			ev.Result = "failed"
			ev.Err = fmt.Sprintf("status %d", rec.status)
		}
		if mutation || ev.Result != "ok" {
			p.emit(ev)
		}
	}
}

// verify parses + checks the SigV4 seed signature and returns the bound beam.
func (p *Provisioner) verify(r *http.Request) (*registration, bool) {
	const algo = "AWS4-HMAC-SHA256 "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algo) {
		return nil, false
	}
	var cred, signed, sig string
	for _, kv := range strings.Split(auth[len(algo):], ",") {
		kv = strings.TrimSpace(kv)
		switch {
		case strings.HasPrefix(kv, "Credential="):
			cred = strings.TrimPrefix(kv, "Credential=")
		case strings.HasPrefix(kv, "SignedHeaders="):
			signed = strings.TrimPrefix(kv, "SignedHeaders=")
		case strings.HasPrefix(kv, "Signature="):
			sig = strings.TrimPrefix(kv, "Signature=")
		}
	}
	cp := strings.SplitN(cred, "/", 5) // AK/date/region/service/aws4_request
	if len(cp) != 5 || signed == "" || sig == "" {
		return nil, false
	}
	reg, ok := p.lookup(cp[0])
	if !ok {
		return nil, false
	}
	date, region, service := cp[1], cp[2], cp[3]
	amzDate := r.Header.Get("X-Amz-Date")
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")

	var ch strings.Builder
	for _, h := range strings.Split(signed, ";") {
		var v string
		switch h {
		case "host":
			v = r.Host
		case "content-length":
			v = strconv.FormatInt(r.ContentLength, 10)
		default:
			v = r.Header.Get(h)
		}
		ch.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	canonReq := r.Method + "\n" + r.URL.EscapedPath() + "\n" + canonicalQuery(r.URL.Query()) + "\n" +
		ch.String() + "\n" + signed + "\n" + payloadHash
	hashedCR := hex.EncodeToString(sha256Sum([]byte(canonReq)))
	scope := date + "/" + region + "/" + service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hashedCR
	want := hex.EncodeToString(hmacSHA256(signingKey(reg.secret, date, region, service), sts))
	if hmac.Equal([]byte(want), []byte(sig)) {
		return reg, true
	}
	return nil, false
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func signingKey(secret, date, region, service string) []byte {
	return hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+secret), date), region), service), "aws4_request")
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// awsURIEncode is the SigV4 RFC3986 encoding used for canonical query strings.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(v url.Values) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), v[k]...)
		sort.Strings(vals)
		for _, val := range vals {
			parts = append(parts, awsURIEncode(k, true)+"="+awsURIEncode(val, true))
		}
	}
	return strings.Join(parts, "&")
}

// normalizeChunked replaces an aws-chunked streaming body (signed, unsigned, and
// the *-TRAILER variants modern SDKs default to) with a plain decoded stream the
// storage engine can read. It streams (no full-body buffering) and trusts the
// declared decoded length, which the SDK signs.
func normalizeChunked(r *http.Request) error {
	sha := r.Header.Get("X-Amz-Content-Sha256")
	if !strings.HasPrefix(sha, "STREAMING-") {
		return nil // already plain
	}
	decLen, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
	if err != nil {
		return fmt.Errorf("missing X-Amz-Decoded-Content-Length: %w", err)
	}
	r.Body = &chunkReader{br: bufio.NewReader(r.Body), orig: r.Body}
	r.ContentLength = decLen
	r.Header.Set("Content-Length", strconv.FormatInt(decLen, 10))
	r.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	r.Header.Del("Content-Encoding")
	r.Header.Del("X-Amz-Decoded-Content-Length")
	return nil
}

// chunkReader strips aws-chunked framing on the fly: "<hexsize>[;sig]\r\n<data>\r\n"
// repeated until a zero-size chunk, after which optional trailers are ignored.
type chunkReader struct {
	br      *bufio.Reader
	orig    io.Closer
	remain  int64
	started bool
	done    bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.remain == 0 {
		if c.started {
			if _, err := c.br.Discard(2); err != nil { // CRLF after previous chunk data
				return 0, err
			}
		}
		c.started = true
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		hdr := strings.TrimRight(line, "\r\n")
		if i := strings.IndexByte(hdr, ';'); i >= 0 {
			hdr = hdr[:i]
		}
		n, err := strconv.ParseInt(strings.TrimSpace(hdr), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("bad chunk size %q: %w", hdr, err)
		}
		if n == 0 {
			c.done = true
			return 0, io.EOF
		}
		c.remain = n
	}
	toRead := int64(len(p))
	if toRead > c.remain {
		toRead = c.remain
	}
	m, err := c.br.Read(p[:toRead])
	c.remain -= int64(m)
	return m, err
}

func (c *chunkReader) Close() error {
	if c.orig != nil {
		return c.orig.Close()
	}
	return nil
}

// bucketUsage sums committed object sizes in a bucket (coarse quota accounting).
func (p *Provisioner) bucketUsage(bucket string) int64 {
	be := p.currentBackend()
	if be == nil {
		return 0
	}
	list, err := be.ListBucket(bucket, nil, gofakes3.ListBucketPage{})
	if err != nil || list == nil {
		return 0
	}
	var total int64
	for _, c := range list.Contents {
		total += c.Size
	}
	return total
}

// incomingSize is the declared object size for a write (decoded length for a
// chunked body, else Content-Length).
func incomingSize(r *http.Request) int64 {
	if d := r.Header.Get("X-Amz-Decoded-Content-Length"); d != "" {
		if n, err := strconv.ParseInt(d, 10, 64); err == nil {
			return n
		}
	}
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	return 0
}

// classify maps a request to an operation name and whether it mutates / writes bytes.
func classify(r *http.Request, key string) (op string, mutation, quotaWrite bool) {
	q := r.URL.Query()
	switch r.Method {
	case http.MethodPut:
		if key == "" {
			return "CreateBucket", false, false
		}
		if q.Has("partNumber") {
			return "UploadPart", false, true
		}
		return "PutObject", true, true
	case http.MethodPost:
		switch {
		case q.Has("uploads"):
			return "CreateMultipartUpload", false, false
		case q.Has("uploadId"):
			return "CompleteMultipartUpload", true, false
		case q.Has("delete"):
			return "DeleteObjects", true, false
		}
		return "Post", false, false
	case http.MethodDelete:
		if key == "" {
			return "DeleteBucket", true, false
		}
		return "DeleteObject", true, false
	default:
		return r.Method, false, false // GET/HEAD reads
	}
}

func opOf(r *http.Request, key string) string { op, _, _ := classify(r, key); return op }

// --- small helpers ---

func cleanFirst(p string) string { return strings.Trim(p, "/") }

func firstSeg(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

func secondSeg(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return ""
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

func (p *Provisioner) writeOwnBucketList(w http.ResponseWriter, bucket string) {
	w.Header().Set("Content-Type", "application/xml")
	const tmpl = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Owner><ID>beamhall</ID><DisplayName>beamhall</DisplayName></Owner>` +
		`<Buckets><Bucket><Name>%s</Name><CreationDate>2009-02-03T16:45:09.000Z</CreationDate></Bucket></Buckets>` +
		`</ListAllMyBucketsResult>`
	fmt.Fprintf(w, tmpl, bucket)
}

func s3Error(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, msg)
}
