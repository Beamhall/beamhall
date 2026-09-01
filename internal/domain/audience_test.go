package domain

import "testing"

func TestAudienceAllows(t *testing.T) {
	cases := []struct {
		name     string
		aud      Audience
		identity ID
		groups   []string
		want     bool
	}{
		{"everyone", Audience{Everyone: true}, "x", nil, true},
		{"identity hit", Audience{Identities: []ID{"a", "b"}}, "b", nil, true},
		{"group hit", Audience{Groups: []string{"finance"}}, "x", []string{"hr", "finance"}, true},
		{"union: group side of a mixed audience", Audience{Identities: []ID{"a"}, Groups: []string{"hr"}}, "x", []string{"hr"}, true},
		{"no hit", Audience{Groups: []string{"finance"}, Identities: []ID{"a"}}, "x", []string{"hr"}, false},
		// An empty audience must deny everyone: the tool layer rejects it on
		// write, but a row that slips through must not become publish-to-all.
		{"empty audience denies", Audience{}, "x", []string{"hr"}, false},
		// Case-folding would let two distinct IdP groups collide into one
		// audience, so the match is exact.
		{"group match is case-sensitive", Audience{Groups: []string{"Finance"}}, "x", []string{"finance"}, false},
		{"nil token groups", Audience{Groups: []string{"finance"}}, "x", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.aud.Allows(c.identity, c.groups); got != c.want {
				t.Errorf("Allows(%q, %v) = %v, want %v", c.identity, c.groups, got, c.want)
			}
		})
	}
}

func TestAudienceIsEmpty(t *testing.T) {
	if !(Audience{}).IsEmpty() {
		t.Error("zero audience should be empty")
	}
	for _, a := range []Audience{{Everyone: true}, {Groups: []string{"g"}}, {Identities: []ID{"i"}}} {
		if a.IsEmpty() {
			t.Errorf("%+v should not be empty", a)
		}
	}
}
