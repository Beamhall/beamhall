package s3

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/johannesboyne/gofakes3"
	minio "github.com/minio/minio-go/v7"
	miniocreds "github.com/minio/minio-go/v7/pkg/credentials"
)

// forward.go implements the FORWARD backend: a gofakes3.Backend that stores
// through an admin-configured external S3 (AWS/MinIO/Wasabi) via minio-go. Every
// beam's bucket maps to a key PREFIX inside the single admin-supplied bucket, so
// the admin grants exactly one bucket + credential and beams stay isolated:
// bucket "beam-a-preview" object "k" → adminBucket/"beam-a-preview/k". The beam
// (and the builder) never see the external credential — it lives only here.
// Multipart is handled by gofakes3's in-memory fallback (we do not implement the
// optional MultipartBackend), so parts buffer in the broker then land as one
// PutObject to the external store.

type forwardBackend struct {
	cl     *minio.Client
	bucket string // the single real (admin-supplied) external bucket
}

func newForwardBackend(cfg ProviderConfig) (gofakes3.Backend, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("s3: forward provider needs a bucket")
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	cl, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:        miniocreds.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:       cfg.UseSSL,
		Region:       region,
		BucketLookup: bucketLookup(cfg.ForcePathStyle),
	})
	if err != nil {
		return nil, fmt.Errorf("s3: forward client: %w", err)
	}
	// Validate the provider eagerly: the admin bucket must be reachable now, so a
	// bad endpoint/credential/bucket fails admin_set_object_store_provider rather
	// than silently breaking beams later.
	exists, err := cl.BucketExists(context.Background(), cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("s3: reach external bucket %q: %w", cfg.Bucket, err)
	}
	if !exists {
		return nil, fmt.Errorf("s3: external bucket %q not found (create it or grant access)", cfg.Bucket)
	}
	return &forwardBackend{cl: cl, bucket: cfg.Bucket}, nil
}

func bucketLookup(forcePathStyle bool) minio.BucketLookupType {
	if forcePathStyle {
		return minio.BucketLookupPath
	}
	return minio.BucketLookupAuto
}

func (f *forwardBackend) prefixOf(beamBucket string) string { return beamBucket + "/" }
func (f *forwardBackend) realKey(beamBucket, key string) string {
	return f.prefixOf(beamBucket) + key
}

// ListBuckets is never reached for a beam request (the verifier answers GET "/"
// with the caller's single bucket); return empty for safety.
func (f *forwardBackend) ListBuckets() ([]gofakes3.BucketInfo, error) {
	return []gofakes3.BucketInfo{}, nil
}

func (f *forwardBackend) ListBucket(name string, prefix *gofakes3.Prefix, _ gofakes3.ListBucketPage) (*gofakes3.ObjectList, error) {
	if prefix == nil {
		prefix = &gofakes3.Prefix{}
	}
	bp := f.prefixOf(name)
	listPrefix := bp
	if prefix.HasPrefix {
		listPrefix += prefix.Prefix
	}
	resp := gofakes3.NewObjectList()
	var match gofakes3.PrefixMatch
	for o := range f.cl.ListObjects(context.Background(), f.bucket, minio.ListObjectsOptions{
		Prefix:    listPrefix,
		Recursive: true, // we apply delimiter rollup ourselves via prefix.Match
	}) {
		if o.Err != nil {
			return nil, o.Err
		}
		rel := strings.TrimPrefix(o.Key, bp)
		if rel == "" || !prefix.Match(rel, &match) {
			continue
		}
		if match.CommonPrefix {
			resp.AddPrefix(match.MatchedPart)
			continue
		}
		resp.Add(&gofakes3.Content{
			Key:          rel,
			LastModified: gofakes3.NewContentTime(o.LastModified),
			ETag:         o.ETag,
			Size:         o.Size,
		})
	}
	return resp, nil
}

// CreateBucket is a no-op: per-beam buckets are virtual prefixes inside the one
// real admin bucket, which already exists.
func (f *forwardBackend) CreateBucket(string) error { return nil }

// BucketExists reports true: the beam's virtual bucket exists because the admin
// bucket (validated at provider config) does.
func (f *forwardBackend) BucketExists(string) (bool, error) { return true, nil }

func (f *forwardBackend) DeleteBucket(name string) error {
	for o := range f.cl.ListObjects(context.Background(), f.bucket, minio.ListObjectsOptions{Prefix: f.prefixOf(name), Recursive: true}) {
		if o.Err != nil {
			return o.Err
		}
		return gofakes3.ResourceError(gofakes3.ErrBucketNotEmpty, name)
	}
	return nil
}

func (f *forwardBackend) ForceDeleteBucket(name string) error {
	ctx := context.Background()
	objs := make(chan minio.ObjectInfo)
	go func() {
		defer close(objs)
		for o := range f.cl.ListObjects(ctx, f.bucket, minio.ListObjectsOptions{Prefix: f.prefixOf(name), Recursive: true}) {
			if o.Err == nil {
				objs <- o
			}
		}
	}()
	for rerr := range f.cl.RemoveObjects(ctx, f.bucket, objs, minio.RemoveObjectsOptions{}) {
		if rerr.Err != nil {
			return rerr.Err
		}
	}
	return nil
}

func (f *forwardBackend) GetObject(bucket, key string, rng *gofakes3.ObjectRangeRequest) (*gofakes3.Object, error) {
	ctx := context.Background()
	realKey := f.realKey(bucket, key)
	info, err := f.cl.StatObject(ctx, f.bucket, realKey, minio.StatObjectOptions{})
	if err != nil {
		return nil, mapMinioErr(err, bucket, key)
	}
	opts := minio.GetObjectOptions{}
	var or *gofakes3.ObjectRange
	if rng != nil {
		r2, rerr := rng.Range(info.Size)
		if rerr != nil {
			return nil, rerr
		}
		if r2 != nil {
			or = r2
			if err := opts.SetRange(r2.Start, r2.Start+r2.Length-1); err != nil {
				return nil, err
			}
		}
	}
	obj, err := f.cl.GetObject(ctx, f.bucket, realKey, opts)
	if err != nil {
		return nil, mapMinioErr(err, bucket, key)
	}
	return &gofakes3.Object{
		Name:     key,
		Size:     info.Size,
		Metadata: objectMeta(info),
		Hash:     etagBytes(info.ETag),
		Range:    or,
		Contents: obj,
	}, nil
}

func (f *forwardBackend) HeadObject(bucket, key string) (*gofakes3.Object, error) {
	info, err := f.cl.StatObject(context.Background(), f.bucket, f.realKey(bucket, key), minio.StatObjectOptions{})
	if err != nil {
		return nil, mapMinioErr(err, bucket, key)
	}
	return &gofakes3.Object{
		Name:     key,
		Size:     info.Size,
		Metadata: objectMeta(info),
		Hash:     etagBytes(info.ETag),
		Contents: io.NopCloser(strings.NewReader("")),
	}, nil
}

func (f *forwardBackend) DeleteObject(bucket, key string) (gofakes3.ObjectDeleteResult, error) {
	err := f.cl.RemoveObject(context.Background(), f.bucket, f.realKey(bucket, key), minio.RemoveObjectOptions{})
	if err != nil && minio.ToErrorResponse(err).Code != "NoSuchKey" {
		return gofakes3.ObjectDeleteResult{}, err
	}
	return gofakes3.ObjectDeleteResult{}, nil
}

func (f *forwardBackend) PutObject(bucket, key string, meta map[string]string, input io.Reader, size int64, _ *gofakes3.PutConditions) (gofakes3.PutObjectResult, error) {
	opts := minio.PutObjectOptions{}
	if ct := metaGet(meta, "Content-Type"); ct != "" {
		opts.ContentType = ct
	}
	if _, err := f.cl.PutObject(context.Background(), f.bucket, f.realKey(bucket, key), input, size, opts); err != nil {
		return gofakes3.PutObjectResult{}, err
	}
	return gofakes3.PutObjectResult{}, nil
}

func (f *forwardBackend) DeleteMulti(bucket string, objects ...string) (gofakes3.MultiDeleteResult, error) {
	var res gofakes3.MultiDeleteResult
	for _, o := range objects {
		err := f.cl.RemoveObject(context.Background(), f.bucket, f.realKey(bucket, o), minio.RemoveObjectOptions{})
		if err != nil && minio.ToErrorResponse(err).Code != "NoSuchKey" {
			res.Error = append(res.Error, gofakes3.ErrorResult{Key: o, Code: gofakes3.ErrInternal, Message: err.Error()})
			continue
		}
		res.Deleted = append(res.Deleted, gofakes3.ObjectID{Key: o})
	}
	return res, nil
}

func (f *forwardBackend) CopyObject(srcBucket, srcKey, dstBucket, dstKey string, meta map[string]string) (gofakes3.CopyObjectResult, error) {
	ctx := context.Background()
	dst := minio.CopyDestOptions{Bucket: f.bucket, Object: f.realKey(dstBucket, dstKey)}
	src := minio.CopySrcOptions{Bucket: f.bucket, Object: f.realKey(srcBucket, srcKey)}
	ui, err := f.cl.CopyObject(ctx, dst, src)
	if err != nil {
		return gofakes3.CopyObjectResult{}, mapMinioErr(err, srcBucket, srcKey)
	}
	return gofakes3.CopyObjectResult{
		ETag:         ui.ETag,
		LastModified: gofakes3.NewContentTime(ui.LastModified),
	}, nil
}

// --- helpers ---

func mapMinioErr(err error, bucket, key string) error {
	switch minio.ToErrorResponse(err).Code {
	case "NoSuchKey":
		return gofakes3.KeyNotFound(key)
	case "NoSuchBucket":
		return gofakes3.BucketNotFound(bucket)
	default:
		return err
	}
}

func objectMeta(info minio.ObjectInfo) map[string]string {
	m := map[string]string{}
	if info.ContentType != "" {
		m["Content-Type"] = info.ContentType
	}
	// gofakes3 writes the GET/HEAD Last-Modified header from this; without it the
	// client fails to parse the response (the local backend sets it natively).
	if !info.LastModified.IsZero() {
		m["Last-Modified"] = info.LastModified.UTC().Format(http.TimeFormat)
	}
	for k, v := range info.UserMetadata {
		m[k] = v
	}
	return m
}

func metaGet(meta map[string]string, key string) string {
	for k, v := range meta {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// etagBytes hex-decodes a simple (non-multipart) ETag for gofakes3's ETag header;
// multipart ETags (with a "-N" suffix) decode to nil and the header is omitted.
func etagBytes(etag string) []byte {
	etag = strings.Trim(etag, `"`)
	b, err := hex.DecodeString(etag)
	if err != nil {
		return nil
	}
	return b
}
