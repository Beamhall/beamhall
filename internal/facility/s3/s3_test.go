package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	minio "github.com/minio/minio-go/v7"
	miniocreds "github.com/minio/minio-go/v7/pkg/credentials"
)

func minioClient(t *testing.T, baseURL, ak, sk string) *minio.Client {
	t.Helper()
	mc, err := minio.New(strings.TrimPrefix(baseURL, "http://"), &minio.Options{
		Creds:        miniocreds.NewStaticV4(ak, sk, ""),
		Secure:       false,
		Region:       "us-east-1",
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return mc
}

// register a beam+channel with explicit creds and return them.
func register(t *testing.T, p *Provisioner, beamID, channel, ak, sk, bucket string, max int64) {
	t.Helper()
	if err := p.RegisterKey(Registration{
		BeamID: beamID, Channel: channel, AccessKey: ak, SecretKey: sk, Bucket: bucket,
		Limits: Limits{MaxBytes: max},
	}); err != nil {
		t.Fatalf("RegisterKey(%s): %v", beamID, err)
	}
}

func TestLocalRoundTripAndIsolation(t *testing.T) {
	p := New(WithStateDir(t.TempDir()))
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	ctx := context.Background()

	register(t, p, "beamA", "preview", "AKA", "secretA", "beam-a-preview", 0)
	register(t, p, "beamB", "preview", "AKB", "secretB", "beam-b-preview", 0)

	ca := minioClient(t, ts.URL, "AKA", "secretA")
	cb := minioClient(t, ts.URL, "AKB", "secretB")

	body := bytes.Repeat([]byte("isolation-spike\n"), 2000)
	if _, err := ca.PutObject(ctx, "beam-a-preview", "docs/a.txt", bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{}); err != nil {
		t.Fatalf("A PutObject: %v", err)
	}
	obj, err := ca.GetObject(ctx, "beam-a-preview", "docs/a.txt", minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("A GetObject: %v", err)
	}
	got, _ := io.ReadAll(obj)
	if !bytes.Equal(got, body) {
		t.Fatalf("A round-trip mismatch: %d vs %d", len(got), len(body))
	}

	// List shows only A's object.
	var keys []string
	for o := range ca.ListObjects(ctx, "beam-a-preview", minio.ListObjectsOptions{Recursive: true}) {
		if o.Err != nil {
			t.Fatalf("A list: %v", o.Err)
		}
		keys = append(keys, o.Key)
	}
	if len(keys) != 1 || keys[0] != "docs/a.txt" {
		t.Fatalf("A list wrong: %v", keys)
	}

	// B cannot touch A's bucket.
	if _, err := cb.GetObject(ctx, "beam-a-preview", "docs/a.txt", minio.GetObjectOptions{}); err == nil {
		// minio GetObject is lazy; force the request by reading.
		o2, _ := cb.GetObject(ctx, "beam-a-preview", "docs/a.txt", minio.GetObjectOptions{})
		if _, e := io.ReadAll(o2); e == nil {
			t.Fatal("B read A's object (cross-bucket isolation broken)")
		}
	}
	if _, err := cb.StatObject(ctx, "beam-a-preview", "docs/a.txt", minio.StatObjectOptions{}); err == nil {
		t.Fatal("B stat A's object succeeded (isolation broken)")
	}

	// Forged secret rejected.
	bad := minioClient(t, ts.URL, "AKA", "WRONG")
	if _, err := bad.StatObject(ctx, "beam-a-preview", "docs/a.txt", minio.StatObjectOptions{}); err == nil {
		t.Fatal("forged secret accepted")
	}

	// ListBuckets shows only the caller's own bucket.
	buckets, err := ca.ListBuckets(ctx)
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 1 || buckets[0].Name != "beam-a-preview" {
		t.Fatalf("ListBuckets leaked or wrong: %v", buckets)
	}
}

func TestQuotaEnforced(t *testing.T) {
	p := New(WithStateDir(t.TempDir()))
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	ctx := context.Background()
	register(t, p, "beamA", "preview", "AKA", "secretA", "beam-a-preview", 1024) // 1 KiB cap

	c := minioClient(t, ts.URL, "AKA", "secretA")
	small := bytes.Repeat([]byte("x"), 512)
	if _, err := c.PutObject(ctx, "beam-a-preview", "ok.bin", bytes.NewReader(small), int64(len(small)), minio.PutObjectOptions{}); err != nil {
		t.Fatalf("under-quota put failed: %v", err)
	}
	big := bytes.Repeat([]byte("y"), 2048)
	if _, err := c.PutObject(ctx, "beam-a-preview", "toobig.bin", bytes.NewReader(big), int64(len(big)), minio.PutObjectOptions{}); err == nil {
		t.Fatal("over-quota put was accepted")
	}
}

func TestDeregisterPurge(t *testing.T) {
	p := New(WithStateDir(t.TempDir()))
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	ctx := context.Background()
	register(t, p, "beamA", "preview", "AKA", "secretA", "beam-a-preview", 0)
	c := minioClient(t, ts.URL, "AKA", "secretA")
	if _, err := c.PutObject(ctx, "beam-a-preview", "a.txt", strings.NewReader("hi"), 2, minio.PutObjectOptions{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	p.Deregister("beamA", "preview", true)
	// Key no longer authenticates.
	if _, err := c.StatObject(ctx, "beam-a-preview", "a.txt", minio.StatObjectOptions{}); err == nil {
		t.Fatal("deregistered key still works")
	}
	// Re-register: the bucket was purged, so the object is gone.
	register(t, p, "beamA", "preview", "AKA", "secretA", "beam-a-preview", 0)
	if _, err := c.StatObject(ctx, "beam-a-preview", "a.txt", minio.StatObjectOptions{}); err == nil {
		t.Fatal("object survived purge")
	}
}

func TestProviderPersistenceLocalDefault(t *testing.T) {
	dir := t.TempDir()
	p := New(WithStateDir(dir))
	if !p.Enabled() {
		t.Fatal("object storage should be enabled by default (local backend)")
	}
	// Point at a second broker standing in for "external S3".
	extDir := t.TempDir()
	ext := New(WithStateDir(extDir))
	register(t, ext, "admin", "", "EXTAK", "EXTSK", "company-bucket", 0)
	extTS := httptest.NewServer(ext.Handler())
	defer extTS.Close()

	cfg := ProviderConfig{
		Endpoint: strings.TrimPrefix(extTS.URL, "http://"), Region: "us-east-1",
		Bucket: "company-bucket", AccessKey: "EXTAK", SecretKey: "EXTSK",
		ForcePathStyle: true, UseSSL: false,
	}
	if err := p.SetProvider(cfg); err != nil {
		t.Fatalf("SetProvider(forward): %v", err)
	}
	// A fresh broker loads the persisted forward provider.
	p2 := New(WithStateDir(dir))
	if err := p2.LoadProvider(); err != nil {
		t.Fatalf("LoadProvider: %v", err)
	}
	if !p2.Enabled() {
		t.Fatal("should be enabled after loading the persisted provider")
	}

	// Switching back to local clears the persisted provider.
	if err := p2.SetProvider(ProviderConfig{}); err != nil {
		t.Fatalf("SetProvider(local): %v", err)
	}
	p3 := New(WithStateDir(dir))
	if err := p3.LoadProvider(); err != nil {
		t.Fatalf("LoadProvider after clear: %v", err)
	}
	if !p3.Enabled() {
		t.Fatal("local default should be enabled")
	}
}

func TestForwardModeRoundTripAndPrefix(t *testing.T) {
	// "external S3" = a second broker.
	ext := New(WithStateDir(t.TempDir()))
	register(t, ext, "admin", "", "EXTAK", "EXTSK", "company-bucket", 0)
	extTS := httptest.NewServer(ext.Handler())
	defer extTS.Close()

	// Broker in FORWARD mode pointing at it.
	p := New(WithStateDir(t.TempDir()))
	if err := p.SetProvider(ProviderConfig{
		Endpoint: strings.TrimPrefix(extTS.URL, "http://"), Region: "us-east-1",
		Bucket: "company-bucket", AccessKey: "EXTAK", SecretKey: "EXTSK",
		ForcePathStyle: true, UseSSL: false,
	}); err != nil {
		t.Fatalf("SetProvider: %v", err)
	}
	register(t, p, "beamA", "preview", "AKA", "secretA", "beam-a-preview", 0)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	ctx := context.Background()

	c := minioClient(t, ts.URL, "AKA", "secretA")
	payload := []byte("forwarded-data-xyz")
	if _, err := c.PutObject(ctx, "beam-a-preview", "f/obj.txt", bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{}); err != nil {
		t.Fatalf("forward put: %v", err)
	}
	obj, err := c.GetObject(ctx, "beam-a-preview", "f/obj.txt", minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("forward get: %v", err)
	}
	got, _ := io.ReadAll(obj)
	if !bytes.Equal(got, payload) {
		t.Fatalf("forward round-trip mismatch: got %d bytes %q want %d %q", len(got), got, len(payload), payload)
	}

	// Confirm it landed under the per-beam prefix in the external bucket.
	extClient := minioClient(t, extTS.URL, "EXTAK", "EXTSK")
	if _, err := extClient.StatObject(ctx, "company-bucket", "beam-a-preview/f/obj.txt", minio.StatObjectOptions{}); err != nil {
		t.Fatalf("object not at expected prefix: %v", err)
	}
}

func TestControlChannelAndAudit(t *testing.T) {
	cs := NewControlServer("tok", 0)
	p := New(WithStateDir(t.TempDir()), WithAuditSink(cs.Record))
	cs.Attach(p)
	ctrlTS := httptest.NewServer(cs.Handler())
	defer ctrlTS.Close()
	s3TS := httptest.NewServer(p.Handler())
	defer s3TS.Close()
	ctx := context.Background()

	client := NewClient(ctrlTS.URL, "tok")
	enabled, next, err := client.Status(ctx)
	if err != nil || !enabled {
		t.Fatalf("status: enabled=%v next=%d err=%v", enabled, next, err)
	}
	creds, err := client.Provision(ctx, ProvisionRequest{BeamID: "beamA", Channel: "preview", Bucket: "beam-a-preview"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mc := minioClient(t, s3TS.URL, creds.AccessKey, creds.SecretKey)
	if _, err := mc.PutObject(ctx, "beam-a-preview", "x.txt", strings.NewReader("audit me"), 8, minio.PutObjectOptions{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	events, _, err := client.PullEvents(ctx, 0)
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	var sawPut bool
	for _, e := range events {
		if e.Op == "PutObject" && e.Bucket == "beam-a-preview" && e.Result == "ok" {
			sawPut = true
		}
	}
	if !sawPut {
		t.Fatalf("PutObject audit event missing: %+v", events)
	}

	// Bad token rejected.
	if _, _, err := NewClient(ctrlTS.URL, "wrong").Status(ctx); err == nil {
		t.Fatal("bad control token accepted")
	}
}

// --- chunked normalizer (the crux: handle every aws-chunked variant) ---

func buildChunked(data []byte, withSig, trailer bool) []byte {
	var b bytes.Buffer
	const sig = "0000000000000000000000000000000000000000000000000000000000000000"
	writeHdr := func(n int) {
		if withSig {
			fmt.Fprintf(&b, "%x;chunk-signature=%s\r\n", n, sig)
		} else {
			fmt.Fprintf(&b, "%x\r\n", n)
		}
	}
	// two data chunks to exercise multi-chunk framing
	half := len(data) / 2
	writeHdr(half)
	b.Write(data[:half])
	b.WriteString("\r\n")
	writeHdr(len(data) - half)
	b.Write(data[half:])
	b.WriteString("\r\n")
	writeHdr(0)
	if trailer {
		b.WriteString("x-amz-checksum-crc32:abcd1234\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

func TestNormalizeChunkedVariants(t *testing.T) {
	data := []byte("hello aws-chunked world, this is the decoded body")
	cases := []struct {
		name    string
		marker  string
		withSig bool
		trailer bool
	}{
		{"signed", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", true, false},
		{"unsigned-trailer", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", false, true},
		{"signed-trailer", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildChunked(data, tc.withSig, tc.trailer)
			r := httptest.NewRequest(http.MethodPut, "/beam-a-preview/k", bytes.NewReader(raw))
			r.Header.Set("X-Amz-Content-Sha256", tc.marker)
			r.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprintf("%d", len(data)))
			r.Header.Set("Content-Encoding", "aws-chunked")
			if err := normalizeChunked(r); err != nil {
				t.Fatalf("normalizeChunked: %v", err)
			}
			if r.Header.Get("X-Amz-Content-Sha256") != unsignedPayload {
				t.Fatalf("content-sha256 not normalized: %s", r.Header.Get("X-Amz-Content-Sha256"))
			}
			if r.ContentLength != int64(len(data)) {
				t.Fatalf("content length = %d want %d", r.ContentLength, len(data))
			}
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read normalized body: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("decoded body mismatch:\n got %q\nwant %q", got, data)
			}
		})
	}
}

func TestNormalizeChunkedPlainPassthrough(t *testing.T) {
	body := []byte("plain body, not chunked")
	r := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(body))
	r.Header.Set("X-Amz-Content-Sha256", "abc123") // a real hash placeholder
	if err := normalizeChunked(r); err != nil {
		t.Fatalf("normalizeChunked: %v", err)
	}
	got, _ := io.ReadAll(r.Body)
	if !bytes.Equal(got, body) {
		t.Fatalf("plain body altered")
	}
}
