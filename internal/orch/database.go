package orch

import (
	"context"
	"fmt"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/resource"
)

// DatabaseProvisioner is the managed-database seam
// (*resource.PostgresProvisioner satisfies it). Optional: a backplane without
// one refuses create_database cleanly.
type DatabaseProvisioner interface {
	Provision(ctx context.Context, req resource.Request) (resource.Provisioned, error)
	Drop(ctx context.Context, pr resource.Provisioned) error
}

// WithDatabaseProvisioner enables create_database.
func WithDatabaseProvisioner(p DatabaseProvisioner) Option {
	return func(o *Orchestrator) { o.dbProv = p }
}

// CreateDatabase provisions a scoped database for a beam and seals its DSN
// into the vault under the returned secret key — the agent learns the KEY
// (and reads the value as a file inside the workload after the next deploy),
// never the connection string itself (PLAN §6).
func (o *Orchestrator) CreateDatabase(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	name string) (secretKey string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionCreateDatabase, beamhallID, beamID); err != nil {
		return "", err
	}
	secretKey, err = o.createDatabase(ctx, actor, beamhallID, beamID, name)
	return secretKey, o.outcome(ctx, actor, policy.ActionCreateDatabase, beamhallID, beamID, err)
}

func (o *Orchestrator) createDatabase(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	name string) (string, error) {
	if o.dbProv == nil {
		return "", fmt.Errorf("no database provisioner configured on this backplane")
	}
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return "", err
	}
	// Idempotent: if this beam already has a preview database with this name,
	// return its existing secret key rather than failing on a duplicate
	// provision. A non-expert agent may call create_database more than once for
	// the same DB. create_database always provisions the PREVIEW channel's
	// database; promote reconciles a separate live database under the same key.
	existing, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelPreview)
	if err != nil {
		return "", err
	}
	for _, r := range existing {
		if r.Type == domain.ResourceDatabase && r.Spec["name"] == name {
			o.log.Info("database already provisioned; returning existing key", "beam", beamID, "name", name)
			return dbSecretKey(name), nil
		}
	}
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return "", err
	}
	if err := o.pep.CheckDatabaseQuota(ctx, bh); err != nil {
		return "", err
	}

	pr, err := o.dbProv.Provision(ctx, resource.Request{
		BeamhallSlug: bh.Slug,
		BeamSlug:     beam.Slug,
		Name:         name,
		Network:      networkName(beamhallID),
	})
	if err != nil {
		return "", err
	}

	key := dbSecretKey(name)
	ref := domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: key, Channel: domain.ChannelPreview}
	if _, err := o.vault.Set(ctx, ref, []byte(pr.DSN), actor.ID); err != nil {
		// Don't leave a credentialed database nobody can reach the DSN of.
		if derr := o.dbProv.Drop(ctx, pr); derr != nil {
			o.log.Error("rollback of provisioned database failed", "db", pr.Database, "err", derr)
		}
		return "", fmt.Errorf("seal connection secret: %w", err)
	}

	res := &domain.Resource{
		BeamhallID:          beamhallID,
		BeamID:              beamID,
		Channel:             domain.ChannelPreview,
		Type:                domain.ResourceDatabase,
		Status:              domain.ResourceReady,
		ConnectionSecretRef: ref,
		Spec:                map[string]string{"name": name, "database": pr.Database, "role": pr.Role},
		BackingHandle:       pr.Database,
	}
	if err := o.st.CreateResource(ctx, res); err != nil {
		return "", err
	}
	o.log.Info("database provisioned", "beam", beamID, "database", pr.Database, "secret_key", key)
	return key, nil
}

// dbSecretKey maps a database name to its injected secret key:
// "main" → MAIN_URL, surfacing at /run/secrets/MAIN_URL on the next deploy.
func dbSecretKey(name string) string {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return upper + "_URL"
}
