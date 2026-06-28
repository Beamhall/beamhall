// Command s3probe is a conformance helper: a stock S3 client (minio-go, the same
// SDK a real beam would use) that PUTs and/or GETs an object through Beamhall's
// in-hall object-store endpoint, reading its credentials from /run/secrets/* just
// like a beam. It runs inside a throwaway container on a beam's bridge to prove
// the object-store facility end-to-end (round-trip, cross-beam isolation, forged
// key rejection). Env vars override the file-read defaults so the same binary can
// impersonate a wrong bucket/secret for the negative checks.
//
//	OP=putget|put|get  KEY=...  [S3_BUCKET=...] [S3_SECRET_KEY=...]
//
// Prints "OK ..." on success or "<STAGE>-ERR: ..." and exits non-zero on failure.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	minio "github.com/minio/minio-go/v7"
	miniocreds "github.com/minio/minio-go/v7/pkg/credentials"
)

func cred(env, file string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	b, _ := os.ReadFile(file)
	return strings.TrimSpace(string(b))
}

func main() {
	endpoint := cred("S3_ENDPOINT", "/run/secrets/S3_ENDPOINT")
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	region := cred("S3_REGION", "/run/secrets/S3_REGION")
	bucket := cred("S3_BUCKET", "/run/secrets/S3_BUCKET")
	ak := cred("S3_ACCESS_KEY", "/run/secrets/S3_ACCESS_KEY")
	sk := cred("S3_SECRET_KEY", "/run/secrets/S3_SECRET_KEY")
	key := os.Getenv("KEY")
	if key == "" {
		key = "probe.txt"
	}
	op := os.Getenv("OP")
	if op == "" {
		op = "putget"
	}
	fail := func(stage string, err error) {
		fmt.Printf("%s-ERR: %v\n", stage, err)
		os.Exit(1)
	}

	mc, err := minio.New(endpoint, &minio.Options{
		Creds:        miniocreds.NewStaticV4(ak, sk, ""),
		Secure:       false,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		fail("NEW", err)
	}
	ctx := context.Background()
	payload := []byte("beamhall-objstore-conformance")

	if op == "putget" || op == "put" {
		if _, err := mc.PutObject(ctx, bucket, key, bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{}); err != nil {
			fail("PUT", err)
		}
	}
	if op == "putget" || op == "get" {
		obj, err := mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
		if err != nil {
			fail("GET", err)
		}
		got, err := io.ReadAll(obj)
		if err != nil {
			fail("READ", err)
		}
		if op == "putget" && string(got) != string(payload) {
			fail("MISMATCH", fmt.Errorf("got %q", got))
		}
	}
	fmt.Printf("OK op=%s bucket=%s key=%s\n", op, bucket, key)
}
