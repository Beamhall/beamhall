package audit

import (
	"context"
	"encoding/json"
	"io"
)

// ExportRecord is the JSON-Lines shape of one exported audit event. Field
// names are stable — SIEM pipelines key on them.
type ExportRecord struct {
	Seq           int64  `json:"seq"`
	ID            string `json:"id"`
	At            int64  `json:"at_unix_nano"`
	ActorID       string `json:"actor_id"`
	ActorTokenJTI string `json:"actor_token_jti,omitempty"`
	BeamhallID    string `json:"beamhall_id,omitempty"`
	BeamID        string `json:"beam_id,omitempty"`
	Action        string `json:"action"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	RequestDigest string `json:"request_digest,omitempty"`
	ResultStatus  string `json:"result_status,omitempty"`
	SourceIP      string `json:"source_ip,omitempty"`
	PrevHash      string `json:"prev_hash"`
	Hash          string `json:"hash"`
}

// Export writes every record with seq > afterSeq to w as JSON Lines, in seq
// order, and returns the last seq written (afterSeq if nothing new). Feed the
// returned cursor back in to resume — this is the SIEM-shipping loop, and the
// off-box anchor that closes the chain's truncated-tail blind spot.
func (l *Logger) Export(ctx context.Context, w io.Writer, afterSeq int64) (int64, error) {
	enc := json.NewEncoder(w) // Encode appends the newline JSON Lines needs
	cursor := afterSeq
	for {
		recs, err := l.st.ListAuditEvents(ctx, cursor, verifyBatch)
		if err != nil {
			return cursor, err
		}
		if len(recs) == 0 {
			return cursor, nil
		}
		for _, rec := range recs {
			out := ExportRecord{
				Seq:           rec.Seq,
				ID:            string(rec.Event.ID),
				At:            rec.Event.At.UnixNano(),
				ActorID:       string(rec.Event.ActorID),
				ActorTokenJTI: rec.Event.ActorTokenJTI,
				BeamhallID:    string(rec.Event.BeamhallID),
				BeamID:        string(rec.Event.BeamID),
				Action:        rec.Event.Action,
				Decision:      string(rec.Event.Decision),
				Reason:        rec.Event.Reason,
				RequestDigest: rec.Event.RequestDigest,
				ResultStatus:  rec.Event.ResultStatus,
				SourceIP:      rec.Event.SourceIP,
				PrevHash:      rec.Event.PrevHash,
				Hash:          rec.Event.Hash,
			}
			if err := enc.Encode(out); err != nil {
				return cursor, err
			}
			cursor = rec.Seq
		}
	}
}
