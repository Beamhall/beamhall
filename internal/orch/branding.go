package orch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/store"
)

// Company branding (PLAN §10 feature wave): IT defines the look the apps teams
// build should wear — header/footer HTML, a logo, a colour palette — as a
// facility-wide default plus per-beamhall field-wise overrides. Builders read
// it (show_branding) and cannot change it. Branding is deliberately NOT a
// secret: it must survive in build logs and show_logs unscrubbed, so it rides
// DeploySpec.Bindings, never the vault.

const (
	maxLogoBytes      = 1 << 20
	maxBrandHTMLBytes = 16 << 10
	brandMountPath    = "/run/beamhall/brand.json"
	brandAlias        = "brand.json"
	// facilityOwner is the facility scope's segment in public /brand/ URLs.
	// slugRe forbids '_', so it can never collide with a beamhall slug.
	facilityOwner = "_"
)

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// colorRe bounds palette values to plausible CSS color syntax. The values are
// interpolated into the brand.css :root block, so the charset must exclude
// anything that could close the block or start a new declaration.
var colorRe = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|[a-zA-Z]{3,32}|(rgb|rgba|hsl|hsla)\([0-9a-zA-Z.,%/+\s-]{1,48}\))$`)

// BrandingSpec is the IT input for admin_set_branding, for one scope.
// Text/colours are set-and-replace; the logo is kept unless replaced
// (LogoPNG) or removed (ClearLogo). Clear drops the whole scope.
type BrandingSpec struct {
	Branding  domain.Branding
	LogoPNG   []byte
	ClearLogo bool
	Clear     bool
}

// BrandingInfo is the resolved, agent- and runtime-facing view of a
// beamhall's branding: the per-beamhall override layered field-wise over the
// facility default. It is also the schema of /run/beamhall/brand.json.
type BrandingInfo struct {
	Configured      bool   `json:"configured"`
	Scope           string `json:"scope,omitempty"` // "facility" | "beamhall"
	HeaderHTML      string `json:"header_html,omitempty"`
	FooterHTML      string `json:"footer_html,omitempty"`
	PrimaryColor    string `json:"primary_color,omitempty"`
	SecondaryColor  string `json:"secondary_color,omitempty"`
	AccentColor     string `json:"accent_color,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
	LogoURL         string `json:"logo_url,omitempty"`
	LogoMIME        string `json:"logo_mime,omitempty"`
	CSSURL          string `json:"css_url,omitempty"`
}

// SetBranding replaces one scope's branding (beamhallID "" = the facility-wide
// default). IT-only (admin:it), audited.
func (o *Orchestrator) SetBranding(ctx context.Context, actor Actor, beamhallID domain.ID, spec BrandingSpec) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_branding", beamhallID, err)
	}
	return o.itAudit(ctx, actor, "admin_set_branding", beamhallID, o.setBranding(ctx, beamhallID, spec))
}

func (o *Orchestrator) setBranding(ctx context.Context, beamhallID domain.ID, spec BrandingSpec) error {
	if spec.Clear {
		return o.st.ClearBrandingScope(ctx, beamhallID)
	}
	if err := validateBranding(spec.Branding); err != nil {
		return err
	}
	if spec.LogoPNG != nil {
		if len(spec.LogoPNG) > maxLogoBytes {
			return fmt.Errorf("logo exceeds %d KB — use a smaller PNG", maxLogoBytes/1024)
		}
		if !bytes.HasPrefix(spec.LogoPNG, pngMagic) {
			return errors.New("logo must be a PNG image (SVG and other formats are not accepted)")
		}
	}
	if err := o.st.PutBranding(ctx, beamhallID, spec.Branding); err != nil {
		return err
	}
	if spec.LogoPNG != nil {
		sum := sha256.Sum256(spec.LogoPNG)
		return o.st.PutBrandingLogo(ctx, beamhallID, domain.BrandingLogo{
			Bytes: spec.LogoPNG,
			MIME:  "image/png",
			ETag:  hex.EncodeToString(sum[:])[:16],
		})
	}
	if spec.ClearLogo {
		return o.st.DeleteBrandingLogo(ctx, beamhallID)
	}
	return nil
}

func validateBranding(b domain.Branding) error {
	if len(b.HeaderHTML) > maxBrandHTMLBytes || len(b.FooterHTML) > maxBrandHTMLBytes {
		return fmt.Errorf("header/footer HTML exceeds %d KB", maxBrandHTMLBytes/1024)
	}
	for name, v := range map[string]string{
		"primary_color":    b.PrimaryColor,
		"secondary_color":  b.SecondaryColor,
		"accent_color":     b.AccentColor,
		"background_color": b.BackgroundColor,
		"text_color":       b.TextColor,
	} {
		if v != "" && !colorRe.MatchString(v) {
			return fmt.Errorf("%s %q is not a valid CSS colour (use #hex, a colour name, or rgb()/hsl())", name, v)
		}
	}
	return nil
}

// ShowBranding returns the resolved branding a beamhall's apps should wear.
// Builder-readable (PEP-gated per membership).
func (o *Orchestrator) ShowBranding(ctx context.Context, actor Actor, beamhallID domain.ID) (BrandingInfo, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowBranding, beamhallID, ""); err != nil {
		return BrandingInfo{}, err
	}
	info, err := o.showBranding(ctx, beamhallID)
	return info, o.outcome(ctx, actor, policy.ActionShowBranding, beamhallID, "", err)
}

func (o *Orchestrator) showBranding(ctx context.Context, beamhallID domain.ID) (BrandingInfo, error) {
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return BrandingInfo{}, err
	}
	return o.resolvedBranding(ctx, bh.ID, bh.Slug)
}

// ResolveBrandingByOwner resolves branding for a public /brand/ URL owner
// segment: a beamhall slug, or the facility sentinel.
func (o *Orchestrator) ResolveBrandingByOwner(ctx context.Context, owner string) (BrandingInfo, error) {
	if owner == facilityOwner {
		return o.resolvedBranding(ctx, domain.FacilityScope, facilityOwner)
	}
	bh, err := o.st.GetBeamhallBySlug(ctx, owner)
	if err != nil {
		return BrandingInfo{}, err
	}
	return o.resolvedBranding(ctx, bh.ID, bh.Slug)
}

// BrandingLogoByOwner returns the logo a /brand/ URL owner resolves to (the
// beamhall's own, else the facility default).
func (o *Orchestrator) BrandingLogoByOwner(ctx context.Context, owner string) (domain.BrandingLogo, error) {
	if owner == facilityOwner {
		return o.st.GetBrandingLogo(ctx, domain.FacilityScope)
	}
	bh, err := o.st.GetBeamhallBySlug(ctx, owner)
	if err != nil {
		return domain.BrandingLogo{}, err
	}
	logo, err := o.st.GetBrandingLogo(ctx, bh.ID)
	if errors.Is(err, store.ErrNotFound) {
		return o.st.GetBrandingLogo(ctx, domain.FacilityScope)
	}
	return logo, err
}

// resolvedBranding merges a beamhall's override field-wise over the facility
// default. owner is the URL segment public brand URLs use for this scope.
func (o *Orchestrator) resolvedBranding(ctx context.Context, beamhallID domain.ID, owner string) (BrandingInfo, error) {
	facility, err := o.st.GetBranding(ctx, domain.FacilityScope)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return BrandingInfo{}, err
	}
	merged := facility
	scope := "facility"
	if beamhallID != domain.FacilityScope {
		override, err := o.st.GetBranding(ctx, beamhallID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return BrandingInfo{}, err
		}
		if !override.IsZero() {
			scope = "beamhall"
		}
		merged = mergeBranding(facility, override)
	}

	logo, err := o.resolveLogo(ctx, beamhallID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return BrandingInfo{}, err
	}

	info := BrandingInfo{
		Configured:      !merged.IsZero() || logo.ETag != "",
		HeaderHTML:      merged.HeaderHTML,
		FooterHTML:      merged.FooterHTML,
		PrimaryColor:    merged.PrimaryColor,
		SecondaryColor:  merged.SecondaryColor,
		AccentColor:     merged.AccentColor,
		BackgroundColor: merged.BackgroundColor,
		TextColor:       merged.TextColor,
	}
	if !info.Configured {
		return info, nil
	}
	info.Scope = scope
	info.CSSURL = fmt.Sprintf("https://%s/brand/%s/brand.css", o.baseDomain, owner)
	if logo.ETag != "" {
		info.LogoURL = fmt.Sprintf("https://%s/brand/%s/logo-%s.png", o.baseDomain, owner, logo.ETag)
		info.LogoMIME = logo.MIME
	}
	return info, nil
}

// resolveLogo returns the scope's own logo metadata, else the facility
// default's — never the bytes (those load only when the logo URL is served).
func (o *Orchestrator) resolveLogo(ctx context.Context, beamhallID domain.ID) (domain.BrandingLogo, error) {
	if beamhallID != domain.FacilityScope {
		logo, err := o.st.GetBrandingLogoMeta(ctx, beamhallID)
		if err == nil || !errors.Is(err, store.ErrNotFound) {
			return logo, err
		}
	}
	return o.st.GetBrandingLogoMeta(ctx, domain.FacilityScope)
}

// mergeBranding layers an override on a base field-wise: empty override
// fields fall back to the base value.
func mergeBranding(base, override domain.Branding) domain.Branding {
	pick := func(o, b string) string {
		if o != "" {
			return o
		}
		return b
	}
	return domain.Branding{
		HeaderHTML:      pick(override.HeaderHTML, base.HeaderHTML),
		FooterHTML:      pick(override.FooterHTML, base.FooterHTML),
		PrimaryColor:    pick(override.PrimaryColor, base.PrimaryColor),
		SecondaryColor:  pick(override.SecondaryColor, base.SecondaryColor),
		AccentColor:     pick(override.AccentColor, base.AccentColor),
		BackgroundColor: pick(override.BackgroundColor, base.BackgroundColor),
		TextColor:       pick(override.TextColor, base.TextColor),
	}
}

// brandingBinding materializes the resolved branding as the workload's
// /run/beamhall/brand.json mount. Branding is cosmetic: any failure here must
// never block a deploy, so errors degrade to "no branding" with a warning.
func (o *Orchestrator) brandingBinding(ctx context.Context, bh domain.Beamhall) []driver.ResourceBinding {
	info, err := o.resolvedBranding(ctx, bh.ID, bh.Slug)
	if err != nil {
		o.log.Warn("branding lookup failed; deploying without brand.json", "beamhall", bh.ID, "err", err)
		return nil
	}
	if !info.Configured {
		return nil
	}
	data, err := json.Marshal(info)
	if err != nil {
		o.log.Warn("branding encode failed; deploying without brand.json", "beamhall", bh.ID, "err", err)
		return nil
	}
	return []driver.ResourceBinding{{Alias: brandAlias, MountPath: brandMountPath, Value: data}}
}
