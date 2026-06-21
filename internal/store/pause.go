package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/scheduler"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// PauseStore returns the scheduler.Store implementation backed by the
// armed_pauses table; wire it into scheduler.New so preview auto-pause
// deadlines survive a backplane restart.
func (s *Store) PauseStore() scheduler.Store { return pauseStore{s} }

type pauseStore struct{ s *Store }

func (p pauseStore) Load(ctx context.Context) ([]scheduler.ArmedPause, error) {
	rows, err := p.s.q.ListArmedPauses(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]scheduler.ArmedPause, 0, len(rows))
	for _, r := range rows {
		out = append(out, scheduler.ArmedPause{BeamID: r.BeamID, Deadline: fromNS(r.Deadline)})
	}
	return out, nil
}

func (p pauseStore) Save(ctx context.Context, ap scheduler.ArmedPause) error {
	return mapErr(p.s.q.UpsertArmedPause(ctx, db.UpsertArmedPauseParams{
		BeamID:   ap.BeamID,
		Deadline: ns(ap.Deadline),
	}))
}

func (p pauseStore) Delete(ctx context.Context, beamID string) error {
	return mapErr(p.s.q.DeleteArmedPause(ctx, beamID))
}
