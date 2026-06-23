package orch

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/identityadmin"
)

// fakeProvider records IdP-admin calls so the orchestrator's tiering/audit
// behavior is tested without a live Keycloak.
type fakeProvider struct {
	createdUser      string
	federated        string
	bindCredential   string
	userEnabled      bool
	userEnabledID    string
	removedFromGroup string
	unfederated      string
	deletedUser      string
	deletedGroup     string
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
func (f *fakeProvider) SetUserEnabled(_ context.Context, userID string, enabled bool) error {
	f.userEnabled = enabled
	f.userEnabledID = userID
	return nil
}
func (f *fakeProvider) CreateGroup(_ context.Context, name string) (identityadmin.Group, error) {
	return identityadmin.Group{ID: "g-1", Name: name}, nil
}
func (f *fakeProvider) ListGroups(context.Context) ([]identityadmin.Group, error) { return nil, nil }
func (f *fakeProvider) AddUserToGroup(context.Context, string, string) error      { return nil }
func (f *fakeProvider) RemoveUserFromGroup(_ context.Context, userID, groupID string) error {
	f.removedFromGroup = userID + ":" + groupID
	return nil
}
func (f *fakeProvider) DeleteUser(_ context.Context, userID string) error {
	f.deletedUser = userID
	return nil
}
func (f *fakeProvider) DeleteGroup(_ context.Context, groupID string) error {
	f.deletedGroup = groupID
	return nil
}
func (f *fakeProvider) UnfederateDirectory(_ context.Context, name string) error {
	f.unfederated = name
	return nil
}
func (f *fakeProvider) FederateDirectory(_ context.Context, d identityadmin.DirectoryFederation) error {
	f.federated = d.Name
	f.bindCredential = d.BindCredential
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

// secondIT is a distinct IT operator (different identity id) for four-eyes.
func secondIT(w *world) Actor { return Actor{ID: w.build.ID, ITAdmin: true} }

func TestRequestFederateFailsClosedWhenSensitiveDisabled(t *testing.T) {
	w := newWorld(t)
	fp := &fakeProvider{}
	w.o.idp = fp
	w.o.idpSensitive = false // master switch OFF — sensitive actions not requestable
	_, err := w.o.RequestFederateDirectory(context.Background(), itActor(w),
		identityadmin.DirectoryFederation{Name: "corp-ad", ConnectionURL: "ldaps://d:636", UsersDN: "DC=x"})
	if err == nil {
		t.Fatal("federation must fail closed when the sensitive tier is disabled")
	}
	pending, _ := w.o.ListPendingAdminActions(context.Background(), itActor(w))
	if len(pending) != 0 {
		t.Fatal("no request should be filed when the tier is disabled")
	}
	if fp.federated != "" {
		t.Fatal("provider must NOT be invoked")
	}
}

func TestFourEyesRequestThenApproveExecutes(t *testing.T) {
	w := newWorld(t)
	fp := &fakeProvider{}
	w.o.idp = fp
	w.o.idpSensitive = true
	ctx := context.Background()

	// Requesting files a pending request and does NOT execute.
	req, err := w.o.RequestFederateDirectory(ctx, itActor(w),
		identityadmin.DirectoryFederation{Name: "corp-ad", Vendor: "ad",
			ConnectionURL: "ldaps://d:636", UsersDN: "DC=x", BindCredential: "s3cret"})
	if err != nil {
		t.Fatalf("RequestFederateDirectory: %v", err)
	}
	if fp.federated != "" {
		t.Fatal("request must NOT execute the federation")
	}
	// The bind credential must NOT sit in cleartext: the summary is non-secret and
	// the payload is sealed (age ciphertext won't contain the plaintext secret).
	if strings.Contains(req.Summary, "s3cret") {
		t.Fatal("summary leaked the bind credential")
	}
	if bytes.Contains(req.PayloadCipher, []byte("s3cret")) {
		t.Fatal("payload is not sealed — bind credential in cleartext at rest")
	}

	// Four-eyes: the requester cannot approve their own request.
	if _, err := w.o.ApproveAdminAction(ctx, itActor(w), req.ID); err == nil {
		t.Fatal("the requester must not be able to approve their own sensitive action")
	}
	if fp.federated != "" {
		t.Fatal("a four-eyes-violating approval must not execute")
	}

	// A different IT operator approves → the federation executes with the sealed
	// payload (credential intact).
	out, err := w.o.ApproveAdminAction(ctx, secondIT(w), req.ID)
	if err != nil {
		t.Fatalf("ApproveAdminAction: %v", err)
	}
	if fp.federated != "corp-ad" {
		t.Fatalf("provider not called on approval: %q", fp.federated)
	}
	if fp.bindCredential != "s3cret" {
		t.Fatalf("sealed credential did not survive round-trip: %q", fp.bindCredential)
	}
	if out.Status != domain.AdminActionApproved {
		t.Fatalf("request not marked approved: %s", out.Status)
	}

	// No longer pending; a second approval is refused.
	pending, _ := w.o.ListPendingAdminActions(ctx, secondIT(w))
	if len(pending) != 0 {
		t.Fatalf("approved request should not remain pending (%d)", len(pending))
	}
	if _, err := w.o.ApproveAdminAction(ctx, secondIT(w), req.ID); err == nil {
		t.Fatal("an already-approved request must not approve again")
	}
}

func TestFourEyesReject(t *testing.T) {
	w := newWorld(t)
	fp := &fakeProvider{}
	w.o.idp = fp
	w.o.idpSensitive = true
	ctx := context.Background()
	req, err := w.o.RequestFederateDirectory(ctx, itActor(w),
		identityadmin.DirectoryFederation{Name: "corp-ad", ConnectionURL: "ldaps://d:636", UsersDN: "DC=x"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := w.o.RejectAdminAction(ctx, secondIT(w), req.ID, "wrong OU"); err != nil {
		t.Fatalf("RejectAdminAction: %v", err)
	}
	if fp.federated != "" {
		t.Fatal("a rejected action must not execute")
	}
	pending, _ := w.o.ListPendingAdminActions(ctx, itActor(w))
	if len(pending) != 0 {
		t.Fatal("rejected request should not remain pending")
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

func TestSetMembershipRoleChangesRole(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// w.build is a builder member of w.bh; change it to viewer in place.
	if err := w.o.SetMembershipRole(ctx, itActor(w), w.build.ID, w.bh.ID, domain.RoleViewer); err != nil {
		t.Fatalf("SetMembershipRole: %v", err)
	}
	m, err := w.st.GetMembership(ctx, w.build.ID, w.bh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != domain.RoleViewer {
		t.Fatalf("role = %s, want viewer", m.Role)
	}
	// Non-IT is refused.
	if err := w.o.SetMembershipRole(ctx, w.build, w.build.ID, w.bh.ID, domain.RoleBuilder); err == nil {
		t.Fatal("non-IT actor must be refused")
	}
}

func TestFourEyesSetSecurityContextApplies(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.o.idpSensitive = true
	// newWorld's beamhall starts on runsc; request a change to runc.
	req, err := w.o.RequestSetSecurityContext(ctx, itActor(w), "ops", domain.RuntimeRunc)
	if err != nil {
		t.Fatalf("RequestSetSecurityContext: %v", err)
	}
	// Not applied until approval, and the requester cannot approve their own.
	if _, err := w.o.ApproveAdminAction(ctx, itActor(w), req.ID); err == nil {
		t.Fatal("four-eyes: requester approved their own action")
	}
	if sc, _ := w.st.GetSecurityContext(ctx, w.bh.ID); sc.RuntimeClass != domain.RuntimeRunsc {
		t.Fatalf("runtime changed before approval: %s", sc.RuntimeClass)
	}
	if _, err := w.o.ApproveAdminAction(ctx, secondIT(w), req.ID); err != nil {
		t.Fatalf("ApproveAdminAction: %v", err)
	}
	sc, err := w.st.GetSecurityContext(ctx, w.bh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.RuntimeClass != domain.RuntimeRunc {
		t.Fatalf("runtime_class = %s after approval, want runc", sc.RuntimeClass)
	}
}

func TestFourEyesUnfederateExecutes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeProvider{}
	w.o.idp = fp
	w.o.idpSensitive = true
	req, err := w.o.RequestUnfederateDirectory(ctx, itActor(w), "corp-ad")
	if err != nil {
		t.Fatalf("RequestUnfederateDirectory: %v", err)
	}
	if _, err := w.o.ApproveAdminAction(ctx, secondIT(w), req.ID); err != nil {
		t.Fatalf("ApproveAdminAction: %v", err)
	}
	if fp.unfederated != "corp-ad" {
		t.Fatalf("unfederated = %q, want corp-ad", fp.unfederated)
	}
}

func TestRequestSensitiveRequiresTier(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.o.idpSensitive = false // master switch off
	if _, err := w.o.RequestSetSecurityContext(ctx, itActor(w), "ops", domain.RuntimeRunc); err == nil {
		t.Fatal("set_security_context must be refused when the sensitive tier is off")
	}
	if _, err := w.o.RequestPruneAudit(ctx, itActor(w), 1); err == nil {
		t.Fatal("prune_audit must be refused when the sensitive tier is off")
	}
}

func TestDeregisterIdentityGuardsMemberships(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// w.build has a membership in w.bh → deregister must refuse.
	if err := w.o.DeregisterIdentity(ctx, itActor(w), w.build.ID); err == nil {
		t.Fatal("deregister must refuse an identity that still has memberships")
	}
	// Register a fresh, membership-less identity → deregister succeeds and the
	// row is gone.
	ident := &domain.Identity{ExternalSubject: "throwaway", IdPIssuer: "idp",
		Email: "t@x", Status: domain.IdentityActive}
	if err := w.st.CreateIdentity(ctx, ident); err != nil {
		t.Fatal(err)
	}
	if err := w.o.DeregisterIdentity(ctx, itActor(w), ident.ID); err != nil {
		t.Fatalf("DeregisterIdentity: %v", err)
	}
	if _, err := w.st.GetIdentity(ctx, ident.ID); err == nil {
		t.Fatal("identity row should be gone after deregister")
	}
}
