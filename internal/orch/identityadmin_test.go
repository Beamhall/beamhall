package orch

import (
	"context"
	"testing"

	"github.com/Beamhall/beamhall/internal/identityadmin"
)

// fakeProvider records IdP-admin calls so the orchestrator's tiering/audit
// behavior is tested without a live Keycloak.
type fakeProvider struct {
	createdUser string
	federated   string
}

func (f *fakeProvider) Enabled() bool { return true }
func (f *fakeProvider) CreateUser(_ context.Context, u identityadmin.NewUser) (identityadmin.User, error) {
	f.createdUser = u.Username
	return identityadmin.User{ID: "u-1", Username: u.Username}, nil
}
func (f *fakeProvider) ListUsers(context.Context, string, int) ([]identityadmin.User, error) {
	return nil, nil
}
func (f *fakeProvider) SetTemporaryPassword(context.Context, string, string) error { return nil }
func (f *fakeProvider) CreateGroup(_ context.Context, name string) (identityadmin.Group, error) {
	return identityadmin.Group{ID: "g-1", Name: name}, nil
}
func (f *fakeProvider) ListGroups(context.Context) ([]identityadmin.Group, error) { return nil, nil }
func (f *fakeProvider) AddUserToGroup(context.Context, string, string) error      { return nil }
func (f *fakeProvider) FederateDirectory(_ context.Context, d identityadmin.DirectoryFederation) error {
	f.federated = d.Name
	return nil
}

func itActor(w *world) Actor { return Actor{ID: w.admin.ID, ITAdmin: true} }

func TestAdminCreateUserRequiresIT(t *testing.T) {
	w := newWorld(t)
	w.o.idp = &fakeProvider{}
	// A non-IT actor is refused (the structural-op gate), and the denial audits.
	_, err := w.o.AdminCreateUser(context.Background(), w.build, identityadmin.NewUser{Username: "x"})
	if err == nil {
		t.Fatal("non-IT actor must be refused")
	}
}

func TestAdminCreateUserRoutineTier(t *testing.T) {
	w := newWorld(t)
	fp := &fakeProvider{}
	w.o.idp = fp
	if _, err := w.o.AdminCreateUser(context.Background(), itActor(w), identityadmin.NewUser{Username: "alice"}); err != nil {
		t.Fatalf("AdminCreateUser: %v", err)
	}
	if fp.createdUser != "alice" {
		t.Fatalf("provider not called: %q", fp.createdUser)
	}
}

func TestFederateDirectoryFailsClosedWhenSensitiveDisabled(t *testing.T) {
	w := newWorld(t)
	fp := &fakeProvider{}
	w.o.idp = fp
	w.o.idpSensitive = false // the human-in-the-loop opt-in is OFF
	err := w.o.AdminFederateDirectory(context.Background(), itActor(w),
		identityadmin.DirectoryFederation{Name: "corp-ad", ConnectionURL: "ldaps://d:636", UsersDN: "DC=x"})
	if err == nil {
		t.Fatal("federation must fail closed when the sensitive tier is disabled")
	}
	if fp.federated != "" {
		t.Fatal("provider must NOT be invoked when failing closed")
	}
}

func TestFederateDirectoryRunsWhenSensitiveEnabled(t *testing.T) {
	w := newWorld(t)
	fp := &fakeProvider{}
	w.o.idp = fp
	w.o.idpSensitive = true // operator enabled the sensitive tier
	err := w.o.AdminFederateDirectory(context.Background(), itActor(w),
		identityadmin.DirectoryFederation{Name: "corp-ad", ConnectionURL: "ldaps://d:636", UsersDN: "DC=x"})
	if err != nil {
		t.Fatalf("AdminFederateDirectory: %v", err)
	}
	if fp.federated != "corp-ad" {
		t.Fatalf("provider not called: %q", fp.federated)
	}
}

func TestIdentityAdminDisabledByDefault(t *testing.T) {
	w := newWorld(t)
	if w.o.IdentityAdminEnabled() {
		t.Fatal("a world without WithIdentityAdmin must report IdP admin disabled")
	}
	if _, err := w.o.AdminCreateUser(context.Background(), itActor(w), identityadmin.NewUser{Username: "x"}); err != identityadmin.ErrNotEnabled {
		t.Fatalf("expected ErrNotEnabled from the Disabled provider, got %v", err)
	}
}
