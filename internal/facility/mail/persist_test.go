package mail

import "testing"

func TestProviderPersistence(t *testing.T) {
	dir := t.TempDir()

	p1 := New(WithProviderStore(dir))
	if p1.Enabled() {
		t.Fatal("should start disabled (no provider)")
	}
	p1.SetProvider(ProviderConfig{Smarthost: "smtp.example.com:587", Username: "u", Password: "p"})
	if !p1.Enabled() {
		t.Fatal("should be enabled after SetProvider with a smarthost")
	}

	// A fresh broker loads the persisted provider (survives restart).
	p2 := New(WithProviderStore(dir))
	if p2.Enabled() {
		t.Fatal("a fresh provisioner is disabled until LoadProvider")
	}
	if err := p2.LoadProvider(); err != nil {
		t.Fatalf("LoadProvider: %v", err)
	}
	if !p2.Enabled() {
		t.Fatal("should be enabled after loading the persisted provider")
	}

	// Clearing the smarthost disables and removes the persisted file.
	p2.SetProvider(ProviderConfig{Smarthost: ""})
	if p2.Enabled() {
		t.Fatal("should be disabled after clearing the smarthost")
	}
	p3 := New(WithProviderStore(dir))
	if err := p3.LoadProvider(); err != nil {
		t.Fatalf("LoadProvider after clear: %v", err)
	}
	if p3.Enabled() {
		t.Fatal("a cleared provider must not persist")
	}
}
