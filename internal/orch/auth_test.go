package orch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/identityadmin"
)

// authFakeIDP is an enabled identityadmin.Provider that records the OIDC-client
// calls provision_auth makes (the Keycloak REST shaping itself is unit-tested in
// internal/identityadmin; here we test the orchestrator's wiring).
type authFakeIDP struct {
	identityadmin.Disabled // user/group/federation no-ops; we override Enabled + the client surface
	created                []identityadmin.ClientSpec
	deleted                []string
	synced                 map[string][]string
	groups                 map[string][]string
	n                      int
}

func (f *authFakeIDP) Enabled() bool { return true }

func (f *authFakeIDP) CreateClient(_ context.Context, spec identityadmin.ClientSpec) (identityadmin.Client, error) {
	f.created = append(f.created, spec)
	f.n++
	return identityadmin.Client{UUID: fmt.Sprintf("uuid-%d", f.n), ClientID: spec.ClientID, Secret: "sealed-" + spec.ClientID}, nil
}

func (f *authFakeIDP) GetClientSecret(context.Context, string) (string, error) { return "sealed", nil }

func (f *authFakeIDP) SyncRedirectURIs(_ context.Context, uuid string, redirects, _ []string) error {
	if f.synced == nil {
		f.synced = map[string][]string{}
	}
	f.synced[uuid] = redirects
	return nil
}

func (f *authFakeIDP) SetClientGroupRoles(_ context.Context, uuid string, groups []string) error {
	if f.groups == nil {
		f.groups = map[string][]string{}
	}
	f.groups[uuid] = groups
	return nil
}

func (f *authFakeIDP) DeleteClient(_ context.Context, uuid string) error {
	f.deleted = append(f.deleted, uuid)
	return nil
}

func withAuth(w *world) *authFakeIDP {
	f := &authFakeIDP{}
	WithIdentityAdmin(f, false)(w.o)
	WithProvisionedAuth("https://idp.bh.example/realms/beamhall", "https://bh.example/mcp")(w.o)
	return f
}

func TestProvisionAuthBYODisabled(t *testing.T) {
	w := newWorld(t)
	beam := w.deployed(t, "app")
	// No WithIdentityAdmin → BYO-IdP → must degrade with ErrNotEnabled (the MCP
	// layer turns this into the set_secret fallback recipe).
	_, err := w.o.ProvisionAuth(context.Background(), w.build, w.bh.ID, beam.ID)
	if !errors.Is(err, identityadmin.ErrNotEnabled) {
		t.Fatalf("BYO-IdP ProvisionAuth must return ErrNotEnabled, got %v", err)
	}
}

func TestProvisionAuthSealsAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	f := withAuth(w)
	beam := w.deployed(t, "app")

	keys, err := w.o.ProvisionAuth(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("ProvisionAuth: %v", err)
	}
	if strings.Join(keys, ",") != "OIDC_ISSUER,OIDC_CLIENT_ID,OIDC_CLIENT_SECRET" {
		t.Fatalf("unexpected keys: %v", keys)
	}
	if len(f.created) != 1 {
		t.Fatalf("expected 1 client created, got %d", len(f.created))
	}
	spec := f.created[0]
	if !strings.HasPrefix(spec.ClientID, "beam-") || !strings.HasSuffix(spec.ClientID, "-app-preview") {
		t.Fatalf("unexpected client id %q", spec.ClientID)
	}
	// Audience isolation is asserted at this seam: the backplane resource URI is
	// passed as the forbidden audience.
	if spec.ForbiddenAudience != "https://bh.example/mcp" {
		t.Fatalf("ForbiddenAudience not wired: %q", spec.ForbiddenAudience)
	}
	if len(spec.RedirectURIs) == 0 {
		t.Fatal("redirect URIs should track the deployed preview host")
	}

	// A ResourceAuthClient row exists on the preview channel, pointing at the sealed secret.
	res, err := w.o.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelPreview)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	var ac *domain.Resource
	for i := range res {
		if res[i].Type == domain.ResourceAuthClient {
			ac = &res[i]
		}
	}
	if ac == nil || ac.ConnectionSecretRef.Key != "OIDC_CLIENT_SECRET" || ac.BackingHandle != "uuid-1" {
		t.Fatalf("auth_client resource missing/wrong: %+v", ac)
	}

	// Idempotent: a second call returns the same keys and does NOT create a second client.
	if _, err := w.o.ProvisionAuth(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("ProvisionAuth (2nd): %v", err)
	}
	if len(f.created) != 1 {
		t.Fatalf("idempotent ProvisionAuth must not create a 2nd client, got %d", len(f.created))
	}
}

func TestProvisionAuthRedirectSyncAcrossPauseResume(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	f := withAuth(w)
	beam := w.deployed(t, "app")
	if _, err := w.o.ProvisionAuth(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("ProvisionAuth: %v", err)
	}
	// Pause empties the allowlist; resume re-points it at the new rotated host.
	if err := w.o.PausePreview(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("PausePreview: %v", err)
	}
	if got := f.synced["uuid-1"]; len(got) != 0 {
		t.Fatalf("pause should empty the redirect allowlist, got %v", got)
	}
	if _, err := w.o.ResumePreview(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("ResumePreview: %v", err)
	}
	if got := f.synced["uuid-1"]; len(got) == 0 {
		t.Fatal("resume should re-sync the redirect allowlist to the new host")
	}
}

func TestProvisionAuthReclaimedOnArchive(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	f := withAuth(w)
	beam := w.deployed(t, "app")
	if _, err := w.o.ProvisionAuth(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("ProvisionAuth: %v", err)
	}
	// A builder may archive their own preview beam — cleanup must delete the client.
	if err := w.o.ArchiveBeam(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("ArchiveBeam: %v", err)
	}
	found := false
	for _, d := range f.deleted {
		if d == "uuid-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("archive must delete the beam's OIDC client; deleted=%v", f.deleted)
	}
}

func TestSetAuthGroupsRequiresIT(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	withAuth(w)
	beam := w.deployed(t, "app")
	if _, err := w.o.ProvisionAuth(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("ProvisionAuth: %v", err)
	}
	// A builder (non-IT) cannot curate the group allowlist.
	if err := w.o.SetAuthGroups(ctx, w.build, w.bh.ID, beam.ID, []string{"hr"}); err == nil {
		t.Fatal("SetAuthGroups must require it_admin")
	}
	// An IT operator can.
	if err := w.o.SetAuthGroups(ctx, itActor(w), w.bh.ID, beam.ID, []string{"hr"}); err != nil {
		t.Fatalf("SetAuthGroups (IT): %v", err)
	}
}
