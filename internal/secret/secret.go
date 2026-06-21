// Package secret is the backplane's write-only secret service. Values are
// age-encrypted to a single vault key (the "secret root") before they touch the
// store, and the only read paths are backplane-side: Inject decrypts material
// into driver file mounts at deploy time, and ScrubberFor decrypts to redact
// values from logs/metrics. There is deliberately no get-value API an agent can
// reach — agents set secrets and reference them by key; they never read back a
// value. See docs/PLAN.md §4 (secrets at rest) and §5.7.
package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/store"
)

// Store is the persistence the vault needs: secret metadata (write-only, keyed
// by scope+key) plus the at-rest ciphertext blobs that value_ref points at.
// *store.Store satisfies it.
type Store interface {
	PutSecret(ctx context.Context, sec *domain.Secret) error
	GetSecret(ctx context.Context, beamhallID, beamID domain.ID, key string, ch domain.Channel) (domain.Secret, error)
	ListSecretsByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Secret, error)
	DeleteSecret(ctx context.Context, beamhallID, beamID domain.ID, key string, ch domain.Channel) error

	PutSecretValue(ctx context.Context, ref string, ciphertext []byte) error
	GetSecretValue(ctx context.Context, ref string) ([]byte, error)
	DeleteSecretValue(ctx context.Context, ref string) error
}

// Vault encrypts/decrypts secret values with an age X25519 identity and
// persists them via a Store. It is safe for concurrent use (the identity and
// recipient are immutable; the Store serializes writes).
type Vault struct {
	id    *age.X25519Identity
	recip *age.X25519Recipient
	store Store
}

// NewVault builds a vault sealed by id over st.
func NewVault(id *age.X25519Identity, st Store) *Vault {
	return &Vault{id: id, recip: id.Recipient(), store: st}
}

// LoadOrCreateKey loads the age identity sealing the vault from path, or — when
// path does not exist — generates a fresh identity, persists it 0600, and
// returns generated=true so the caller can warn. Auto-generation is a dev/lab
// convenience; production supplies the key out-of-band (systemd LoadCredential
// / KMS / TPM) so path already exists. A present-but-unreadable or malformed
// key is a hard error (never silently overwritten).
func LoadOrCreateKey(path string) (id *age.X25519Identity, generated bool, err error) {
	b, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		id, perr := age.ParseX25519Identity(strings.TrimSpace(string(b)))
		if perr != nil {
			return nil, false, fmt.Errorf("parse secret key %s: %w", path, perr)
		}
		return id, false, nil
	case !errors.Is(rerr, fs.ErrNotExist):
		return nil, false, fmt.Errorf("read secret key %s: %w", path, rerr)
	}
	id, gerr := age.GenerateX25519Identity()
	if gerr != nil {
		return nil, false, fmt.Errorf("generate secret key: %w", gerr)
	}
	if werr := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); werr != nil {
		return nil, false, fmt.Errorf("write secret key %s: %w", path, werr)
	}
	return id, true, nil
}

// LoadKey reads an existing age root key, never generating one. This is the
// production path (systemd LoadCredential / KMS / TPM supply the key
// out-of-band): a missing or malformed key is a hard error, so the appliance
// refuses to start rather than silently sealing secrets to a throwaway key.
func LoadKey(path string) (*age.X25519Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secret key %s: %w", path, err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("parse secret key %s: %w", path, err)
	}
	return id, nil
}

// Set stores (or rewrites) the value for ref's (beamhall, beam, key). The value
// is encrypted before it reaches the store, so plaintext is never persisted and
// is never returned by any method. The resulting metadata (final id, version,
// timestamps) is returned. A rewrite stages new ciphertext under a fresh ref,
// flips the metadata pointer, then GCs the superseded blob.
func (v *Vault) Set(ctx context.Context, ref domain.SecretRef, value []byte, by domain.ID) (domain.Secret, error) {
	ct, err := v.encrypt(value)
	if err != nil {
		return domain.Secret{}, err
	}

	var oldRef string
	switch prev, gerr := v.store.GetSecret(ctx, ref.BeamhallID, ref.BeamID, ref.Key, ref.Channel); {
	case gerr == nil:
		oldRef = prev.ValueRef
	case !errors.Is(gerr, store.ErrNotFound):
		return domain.Secret{}, gerr
	}

	blobRef, err := newRef()
	if err != nil {
		return domain.Secret{}, err
	}
	if err := v.store.PutSecretValue(ctx, blobRef, ct); err != nil {
		return domain.Secret{}, err
	}

	sec := domain.Secret{
		BeamhallID: ref.BeamhallID,
		BeamID:     ref.BeamID,
		Channel:    ref.Channel,
		Key:        ref.Key,
		ValueRef:   blobRef,
		CreatedBy:  by,
	}
	if err := v.store.PutSecret(ctx, &sec); err != nil {
		_ = v.store.DeleteSecretValue(ctx, blobRef) // drop the orphaned blob
		return domain.Secret{}, err
	}
	if oldRef != "" && oldRef != blobRef {
		_ = v.store.DeleteSecretValue(ctx, oldRef) // GC superseded ciphertext
	}
	return sec, nil
}

// Delete removes a secret's metadata and its ciphertext. Idempotent.
func (v *Vault) Delete(ctx context.Context, ref domain.SecretRef) error {
	sec, err := v.store.GetSecret(ctx, ref.BeamhallID, ref.BeamID, ref.Key, ref.Channel)
	switch {
	case err == nil:
		if derr := v.store.DeleteSecret(ctx, ref.BeamhallID, ref.BeamID, ref.Key, ref.Channel); derr != nil {
			return derr
		}
		return v.store.DeleteSecretValue(ctx, sec.ValueRef)
	case errors.Is(err, store.ErrNotFound):
		return nil
	default:
		return err
	}
}

// Inject decrypts the referenced secrets for a deploy and returns the file
// mounts the driver stages at /run/secrets/<key> (tmpfs, never env). This is
// the deploy-time read path; it runs backplane-side and the agent never sees
// the plaintext. Refs resolve in order; a missing ref fails the whole inject.
func (v *Vault) Inject(ctx context.Context, refs []domain.SecretRef) ([]driver.SecretMount, error) {
	mounts := make([]driver.SecretMount, 0, len(refs))
	for _, ref := range refs {
		sec, err := v.store.GetSecret(ctx, ref.BeamhallID, ref.BeamID, ref.Key, ref.Channel)
		if err != nil {
			return nil, fmt.Errorf("inject secret %q: %w", ref.Key, err)
		}
		val, err := v.value(ctx, sec.ValueRef)
		if err != nil {
			return nil, fmt.Errorf("inject secret %q: %w", ref.Key, err)
		}
		mounts = append(mounts, driver.SecretMount{
			Key:       ref.Key,
			MountPath: MountPath(ref.Key),
			Value:     val,
		})
	}
	return mounts, nil
}

// MountPath is where a secret key is staged inside the workload.
func MountPath(key string) string { return "/run/secrets/" + key }

// value fetches and decrypts the ciphertext blob behind a value_ref.
func (v *Vault) value(ctx context.Context, ref string) ([]byte, error) {
	ct, err := v.store.GetSecretValue(ctx, ref)
	if err != nil {
		return nil, err
	}
	return v.decrypt(ct)
}

func (v *Vault) encrypt(plain []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, v.recip)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return nil, fmt.Errorf("age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age close: %w", err)
	}
	return buf.Bytes(), nil
}

func (v *Vault) decrypt(ct []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ct), v.id)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("age read: %w", err)
	}
	return out, nil
}

// newRef is an opaque 128-bit ciphertext pointer (distinct from the secret's
// ULID so each version's blob has its own ref and can be GC'd independently).
func newRef() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate secret ref: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
