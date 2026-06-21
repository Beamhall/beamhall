package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

func newLogger(t *testing.T) (*Logger, *store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st), st, path
}

// rawDB opens a second connection to the store's file so tests can tamper
// with rows the way an attacker with db access would. The modernc driver is
// registered by the store package import.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func appendN(t *testing.T, l *Logger, n int) []domain.AuditEvent {
	t.Helper()
	events := make([]domain.AuditEvent, 0, n)
	for i := 0; i < n; i++ {
		ev := domain.AuditEvent{
			ActorID:    "actor-1",
			BeamhallID: "bh-1",
			BeamID:     "beam-1",
			Action:     fmt.Sprintf("action-%d", i),
			Decision:   domain.DecisionAllow,
			Reason:     "test",
		}
		seq, err := l.Append(context.Background(), &ev)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if want := int64(len(events) + 1); seq != want {
			t.Fatalf("Append %d: seq = %d, want %d", i, seq, want)
		}
		events = append(events, ev)
	}
	return events
}

func mustVerify(t *testing.T, l *Logger) []Issue {
	t.Helper()
	issues, err := l.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return issues
}

func TestChainBuildsAndVerifies(t *testing.T) {
	l, _, _ := newLogger(t)
	events := appendN(t, l, 5)

	if events[0].PrevHash != "" {
		t.Fatalf("genesis PrevHash = %q, want empty", events[0].PrevHash)
	}
	for i, ev := range events {
		if ev.Hash == "" {
			t.Fatalf("event %d has empty hash", i)
		}
		if i > 0 && ev.PrevHash != events[i-1].Hash {
			t.Fatalf("event %d PrevHash does not link to event %d Hash", i, i-1)
		}
	}
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("clean log reported issues: %v", issues)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	l, _, _ := newLogger(t)
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("empty log reported issues: %v", issues)
	}
}

func TestVerifyDetectsContentMutation(t *testing.T) {
	l, _, path := newLogger(t)
	appendN(t, l, 5)

	db := rawDB(t, path)
	if _, err := db.Exec(`UPDATE audit_events SET reason = 'doctored' WHERE seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	issues := mustVerify(t, l)
	if len(issues) != 1 || issues[0].Seq != 3 || !strings.Contains(issues[0].Reason, "hash mismatch") {
		t.Fatalf("issues = %v, want exactly one hash mismatch at seq 3", issues)
	}
}

func TestVerifyDetectsRehashedMutation(t *testing.T) {
	// A smarter attacker rewrites the row AND recomputes its hash. The row
	// itself then verifies, but the successor's prev_hash no longer links.
	l, st, path := newLogger(t)
	appendN(t, l, 5)

	recs, err := st.ListAuditEvents(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	doctored := recs[2].Event // seq 3
	doctored.Reason = "doctored"
	doctored.Hash = ""
	rehashed := eventHash(&doctored)

	db := rawDB(t, path)
	if _, err := db.Exec(`UPDATE audit_events SET reason = 'doctored', hash = ? WHERE seq = 3`, rehashed); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	issues := mustVerify(t, l)
	if len(issues) != 1 || issues[0].Seq != 4 || !strings.Contains(issues[0].Reason, "chain break") {
		t.Fatalf("issues = %v, want exactly one chain break at seq 4", issues)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	l, _, path := newLogger(t)
	appendN(t, l, 5)

	db := rawDB(t, path)
	if _, err := db.Exec(`DELETE FROM audit_events WHERE seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	issues := mustVerify(t, l)
	var gap, brk bool
	for _, is := range issues {
		if is.Seq == 4 && strings.Contains(is.Reason, "seq gap") {
			gap = true
		}
		if is.Seq == 4 && strings.Contains(is.Reason, "chain break") {
			brk = true
		}
	}
	if !gap || !brk {
		t.Fatalf("issues = %v, want seq gap + chain break at seq 4", issues)
	}
}

func TestTailTruncationBlindSpotAndDetectionAfterAppend(t *testing.T) {
	l, _, path := newLogger(t)
	appendN(t, l, 5)

	db := rawDB(t, path)
	if _, err := db.Exec(`DELETE FROM audit_events WHERE seq > 3`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Documented blind spot: the surviving prefix is a valid chain.
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("truncated tail unexpectedly detected without append: %v", issues)
	}

	// The next append exposes it: AUTOINCREMENT's high-water mark leaves a
	// seq gap (6 follows 3), even though the hash linkage is consistent.
	appendOne := domain.AuditEvent{ActorID: "a", Action: "post-truncate", Decision: domain.DecisionAllow}
	if _, err := l.Append(context.Background(), &appendOne); err != nil {
		t.Fatalf("append after truncate: %v", err)
	}
	issues := mustVerify(t, l)
	if len(issues) != 1 || !strings.Contains(issues[0].Reason, "seq gap") {
		t.Fatalf("issues = %v, want exactly one seq gap after post-truncation append", issues)
	}
}

func TestConcurrentAppendsKeepChainIntact(t *testing.T) {
	l, st, _ := newLogger(t)

	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := domain.AuditEvent{ActorID: "a", Action: fmt.Sprintf("concurrent-%d", i), Decision: domain.DecisionDeny}
			if _, err := l.Append(context.Background(), &ev); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Append: %v", err)
	}

	recs, err := st.ListAuditEvents(context.Background(), 0, n+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != n {
		t.Fatalf("got %d records, want %d", len(recs), n)
	}
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("chain broken under concurrency: %v", issues)
	}
}

func TestExportJSONLinesAndResume(t *testing.T) {
	l, _, _ := newLogger(t)
	events := appendN(t, l, 4)

	var buf bytes.Buffer
	cursor, err := l.Export(context.Background(), &buf, 0)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if cursor != 4 {
		t.Fatalf("cursor = %d, want 4", cursor)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4", len(lines))
	}
	for i, line := range lines {
		var rec ExportRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		if rec.Seq != int64(i+1) || rec.Hash != events[i].Hash || rec.PrevHash != events[i].PrevHash {
			t.Fatalf("line %d = %+v, does not match event %d", i, rec, i)
		}
		if rec.Action != events[i].Action || rec.Decision != string(domain.DecisionAllow) {
			t.Fatalf("line %d content mismatch: %+v", i, rec)
		}
	}

	// Resume from the cursor: nothing new yields no output, same cursor.
	var empty bytes.Buffer
	cursor2, err := l.Export(context.Background(), &empty, cursor)
	if err != nil {
		t.Fatalf("Export resume: %v", err)
	}
	if cursor2 != cursor || empty.Len() != 0 {
		t.Fatalf("resume wrote %d bytes, cursor %d → %d; want no output, same cursor", empty.Len(), cursor, cursor2)
	}

	// New events after the cursor export incrementally.
	appendN2 := domain.AuditEvent{ActorID: "a", Action: "late", Decision: domain.DecisionAllow}
	if _, err := l.Append(context.Background(), &appendN2); err != nil {
		t.Fatal(err)
	}
	var inc bytes.Buffer
	cursor3, err := l.Export(context.Background(), &inc, cursor)
	if err != nil {
		t.Fatalf("Export incremental: %v", err)
	}
	if cursor3 != 5 || strings.Count(inc.String(), "\n") != 1 {
		t.Fatalf("incremental export: cursor %d, %q", cursor3, inc.String())
	}
}

func TestAppendOverwritesCallerHashFields(t *testing.T) {
	// Callers can never smuggle their own chain values in.
	l, _, _ := newLogger(t)
	ev := domain.AuditEvent{ActorID: "a", Action: "x", Decision: domain.DecisionAllow,
		PrevHash: "forged-prev", Hash: "forged-hash"}
	if _, err := l.Append(context.Background(), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.PrevHash != "" || ev.Hash == "forged-hash" {
		t.Fatalf("caller-supplied hash fields survived: prev=%q hash=%q", ev.PrevHash, ev.Hash)
	}
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("issues: %v", issues)
	}
}

func TestPruneKeepsChainVerifiableAndRecordsCheckpoint(t *testing.T) {
	l, st, _ := newLogger(t)
	ctx := context.Background()
	appendN(t, l, 10)

	// Keep the 4 newest; prune the older 6 (seq 1..6).
	pruned, err := l.Prune(ctx, RetentionPolicy{KeepLast: 4}, "operator-cli", time.Now())
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 6 {
		t.Fatalf("pruned = %d, want 6", pruned)
	}
	// The surviving chain still verifies (Verify resumes from the checkpoint).
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("chain not verifiable after prune: %v", issues)
	}
	// A checkpoint anchors the cut.
	cp, ok, err := st.LatestAuditCheckpoint(ctx)
	if err != nil || !ok {
		t.Fatalf("checkpoint missing after prune: ok=%v err=%v", ok, err)
	}
	if cp.ThroughSeq != 6 || cp.PrunedCount != 6 {
		t.Fatalf("checkpoint = through %d count %d, want 6/6", cp.ThroughSeq, cp.PrunedCount)
	}
	// Survivors are exactly the 4 newest originals (seq 7..10); the prune adds no
	// chain event, so KeepLast stays exact.
	recs, err := st.ListAuditEvents(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 || recs[0].Seq != 7 || recs[len(recs)-1].Seq != 10 {
		t.Fatalf("survivors = %d (seq %d..%d), want 4 from seq 7..10", len(recs), recs[0].Seq, recs[len(recs)-1].Seq)
	}

	// Re-pruning with the same policy is a true no-op (idempotent).
	again, err := l.Prune(ctx, RetentionPolicy{KeepLast: 4}, "operator-cli", time.Now())
	if err != nil || again != 0 {
		t.Fatalf("second prune = %d (err %v), want 0", again, err)
	}
}

func TestPruneThenUncheckpointedDeletionStillDetected(t *testing.T) {
	l, _, path := newLogger(t)
	ctx := context.Background()
	appendN(t, l, 10)
	if _, err := l.Prune(ctx, RetentionPolicy{KeepLast: 4}, "operator-cli", time.Now()); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("clean after legitimate prune, got %v", issues)
	}
	// An attacker deletes a surviving row WITHOUT recording a checkpoint.
	if _, err := rawDB(t, path).Exec("DELETE FROM audit_events WHERE seq = 8"); err != nil {
		t.Fatalf("raw delete: %v", err)
	}
	if issues := mustVerify(t, l); len(issues) == 0 {
		t.Fatal("un-checkpointed deletion after a prune went undetected")
	}
}

func TestPruneNoPolicyIsNoop(t *testing.T) {
	l, _, _ := newLogger(t)
	appendN(t, l, 3)
	n, err := l.Prune(context.Background(), RetentionPolicy{}, "x", time.Now())
	if err != nil || n != 0 {
		t.Fatalf("empty-policy prune = %d (err %v), want 0", n, err)
	}
}

func TestPruneByAge(t *testing.T) {
	l, _, path := newLogger(t)
	ctx := context.Background()
	appendN(t, l, 6)
	// Backdate the first 4 events well into the past via raw SQL.
	old := time.Now().Add(-72 * time.Hour).UnixNano()
	if _, err := rawDB(t, path).Exec("UPDATE audit_events SET at = ? WHERE seq <= 4", old); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	pruned, err := l.Prune(ctx, RetentionPolicy{MaxAge: 24 * time.Hour}, "operator-cli", time.Now())
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 4 {
		t.Fatalf("age-pruned = %d, want 4 (the backdated events)", pruned)
	}
	if issues := mustVerify(t, l); len(issues) != 0 {
		t.Fatalf("not verifiable after age prune: %v", issues)
	}
}
