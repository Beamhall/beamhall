package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
)
import "github.com/Beamhall/beamhall/internal/domain"

func TestBrandingRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	facility := domain.Branding{
		HeaderHTML:      "<div>ACME</div>",
		FooterHTML:      "<footer>legal</footer>",
		PrimaryColor:    "#0B5FFF",
		SecondaryColor:  "#222222",
		AccentColor:     "hotpink",
		BackgroundColor: "#ffffff",
		TextColor:       "#111111",
	}
	if err := s.PutBranding(ctx, domain.FacilityScope, facility); err != nil {
		t.Fatalf("PutBranding facility: %v", err)
	}
	hall := domain.Branding{PrimaryColor: "#00AA00"}
	if err := s.PutBranding(ctx, "wh1", hall); err != nil {
		t.Fatalf("PutBranding hall: %v", err)
	}

	gotF, err := s.GetBranding(ctx, domain.FacilityScope)
	if err != nil {
		t.Fatalf("GetBranding facility: %v", err)
	}
	if !reflect.DeepEqual(gotF, facility) {
		t.Errorf("facility branding mismatch:\n got %+v\nwant %+v", gotF, facility)
	}
	gotH, err := s.GetBranding(ctx, "wh1")
	if err != nil {
		t.Fatalf("GetBranding hall: %v", err)
	}
	if !reflect.DeepEqual(gotH, hall) {
		t.Errorf("hall branding mismatch:\n got %+v\nwant %+v", gotH, hall)
	}

	// Upsert replaces in place.
	facility.PrimaryColor = "#FF0000"
	if err := s.PutBranding(ctx, domain.FacilityScope, facility); err != nil {
		t.Fatalf("PutBranding replace: %v", err)
	}
	gotF, err = s.GetBranding(ctx, domain.FacilityScope)
	if err != nil {
		t.Fatalf("GetBranding after replace: %v", err)
	}
	if gotF.PrimaryColor != "#FF0000" {
		t.Errorf("replace did not stick: %+v", gotF)
	}
}

func TestGetBrandingNotFound(t *testing.T) {
	s, _ := openTestStore(t)
	if _, err := s.GetBranding(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetBranding on unset scope: got %v, want ErrNotFound", err)
	}
	if _, err := s.GetBrandingLogo(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetBrandingLogo on unset scope: got %v, want ErrNotFound", err)
	}
}

func TestBrandingLogoRoundTrip(t *testing.T) {
	s, clock := openTestStore(t)
	ctx := context.Background()

	logo := domain.BrandingLogo{Bytes: []byte{0x89, 'P', 'N', 'G', 0}, MIME: "image/png", ETag: "abcd1234"}
	if err := s.PutBrandingLogo(ctx, domain.FacilityScope, logo); err != nil {
		t.Fatalf("PutBrandingLogo: %v", err)
	}
	got, err := s.GetBrandingLogo(ctx, domain.FacilityScope)
	if err != nil {
		t.Fatalf("GetBrandingLogo: %v", err)
	}
	if !reflect.DeepEqual(got.Bytes, logo.Bytes) || got.MIME != logo.MIME || got.ETag != logo.ETag {
		t.Errorf("logo mismatch: %+v", got)
	}
	if !got.UpdatedAt.Equal(clock.Now()) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, clock.Now())
	}
}

func TestDeleteBrandingIsIdempotent(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if err := s.DeleteBranding(ctx, "never-set"); err != nil {
		t.Errorf("DeleteBranding on unset scope: %v", err)
	}
	if err := s.DeleteBrandingLogo(ctx, "never-set"); err != nil {
		t.Errorf("DeleteBrandingLogo on unset scope: %v", err)
	}
}

func TestClearBrandingScopeRemovesBoth(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if err := s.PutBranding(ctx, "wh1", domain.Branding{PrimaryColor: "#123456"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBrandingLogo(ctx, "wh1", domain.BrandingLogo{Bytes: []byte{1}, MIME: "image/png", ETag: "e"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearBrandingScope(ctx, "wh1"); err != nil {
		t.Fatalf("ClearBrandingScope: %v", err)
	}
	if _, err := s.GetBranding(ctx, "wh1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("branding survived clear: %v", err)
	}
	if _, err := s.GetBrandingLogo(ctx, "wh1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("logo survived clear: %v", err)
	}
}
