package identityadmin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// baselineStub is a stateful Keycloak Admin REST stub for the realm-baseline
// surface: it holds scopes/clients/attachments in memory so a second
// EnsureRealmBaseline run can prove idempotency (no creates, no re-attaches).
type baselineStub struct {
	scopes    map[string]string   // name -> id
	clients   map[string]kcClient // clientId -> rep (ID filled)
	attached  map[string]map[string][]string
	mappers   map[string][]kcProtocolMapper
	creates   int // POSTs that created something
	attachPut int
}

func newBaselineStub() *baselineStub {
	return &baselineStub{
		scopes:   map[string]string{"beamhall-audience": "sid-aud", "offline_access": "sid-off"},
		clients:  map[string]kcClient{},
		attached: map[string]map[string][]string{},
		mappers:  map[string][]kcProtocolMapper{},
	}
}

func (s *baselineStub) addClient(clientID string, defaults, optionals []string) {
	uuid := "uuid-" + clientID
	s.clients[clientID] = kcClient{ID: uuid, ClientID: clientID}
	s.attached[uuid] = map[string][]string{
		"default-client-scopes":  defaults,
		"optional-client-scopes": optionals,
	}
}

func (s *baselineStub) uuidOf(clientID string) string { return "uuid-" + clientID }

func (s *baselineStub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/beamhall/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 60})
	})
	mux.HandleFunc("/admin/realms/beamhall/client-scopes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			var out []map[string]string
			for name, id := range s.scopes {
				out = append(out, map[string]string{"id": id, "name": name})
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.scopes[body.Name] = "sid-" + body.Name
			s.creates++
			w.WriteHeader(http.StatusCreated)
		}
	})
	mux.HandleFunc("/admin/realms/beamhall/clients", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			id := r.URL.Query().Get("clientId")
			var out []kcClient
			if c, ok := s.clients[id]; ok {
				out = append(out, c)
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var body kcClient
			_ = json.NewDecoder(r.Body).Decode(&body)
			uuid := "uuid-" + body.ClientID
			body.ID = uuid
			s.clients[body.ClientID] = body
			// Keycloak honors the scope-name lists on create.
			s.attached[uuid] = map[string][]string{
				"default-client-scopes":  body.DefaultClientScopes,
				"optional-client-scopes": body.OptionalClientScopes,
			}
			s.creates++
			w.Header().Set("Location", "/admin/realms/beamhall/clients/"+uuid)
			w.WriteHeader(http.StatusCreated)
		}
	})
	mux.HandleFunc("/admin/realms/beamhall/clients/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/admin/realms/beamhall/clients/")
		parts := strings.Split(rest, "/")
		uuid := parts[0]
		switch {
		case len(parts) == 2 && strings.HasSuffix(parts[1], "-client-scopes") && r.Method == http.MethodGet:
			var out []map[string]string
			for _, name := range s.attached[uuid][parts[1]] {
				out = append(out, map[string]string{"id": s.scopes[name], "name": name})
			}
			_ = json.NewEncoder(w).Encode(out)
		case len(parts) == 3 && strings.HasSuffix(parts[1], "-client-scopes") && r.Method == http.MethodPut:
			for name, id := range s.scopes {
				if id == parts[2] {
					s.attached[uuid][parts[1]] = append(s.attached[uuid][parts[1]], name)
				}
			}
			s.attachPut++
			w.WriteHeader(http.StatusNoContent)
		case len(parts) == 3 && parts[1] == "protocol-mappers" && parts[2] == "models" && r.Method == http.MethodGet:
			out := s.mappers[uuid]
			if out == nil {
				out = []kcProtocolMapper{}
			}
			_ = json.NewEncoder(w).Encode(out)
		case len(parts) == 3 && parts[1] == "protocol-mappers" && parts[2] == "models" && r.Method == http.MethodPost:
			var m kcProtocolMapper
			_ = json.NewDecoder(r.Body).Decode(&m)
			s.mappers[uuid] = append(s.mappers[uuid], m)
			s.creates++
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return mux
}

func baselineKeycloak(t *testing.T, s *baselineStub) *Keycloak {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	k, err := NewKeycloak(KeycloakConfig{BaseURL: srv.URL, Realm: "beamhall",
		ClientID: "beamhall-idp-admin", ClientSecret: "s", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEnsureRealmBaselineCreatesAndIsIdempotent(t *testing.T) {
	stub := newBaselineStub()
	// The realm shape after a pre-user-tier install: beamhall-agent exists
	// with the nine builder capability scopes, no beams:use anywhere.
	stub.addClient("beamhall-agent", []string{"beamhall-audience"},
		[]string{"beamhalls:read", "beams:write", "offline_access"})
	k := baselineKeycloak(t, stub)

	res, err := k.EnsureRealmBaseline(context.Background(), BeamhallRealmBaseline())
	if err != nil {
		t.Fatalf("EnsureRealmBaseline: %v", err)
	}
	if len(res.CreatedScopes) != 1 || res.CreatedScopes[0] != "beams:use" {
		t.Errorf("CreatedScopes = %v", res.CreatedScopes)
	}
	if len(res.CreatedClients) != 1 || res.CreatedClients[0] != "beamhall-user-agent" {
		t.Errorf("CreatedClients = %v", res.CreatedClients)
	}
	// beamhall-agent gained beams:use (its optional list); the freshly created
	// user client already carries its scopes from the create body.
	var gotAttach bool
	for _, a := range res.AttachedScopes {
		if a == "beamhall-agent:beams:use" {
			gotAttach = true
		}
	}
	if !gotAttach {
		t.Errorf("AttachedScopes = %v, want beamhall-agent:beams:use", res.AttachedScopes)
	}

	// The created user client must be public PKCE+ROPC with ONLY the user
	// scopes and the groups membership mapper.
	created := stub.clients["beamhall-user-agent"]
	if !created.PublicClient || !created.StandardFlowEnabled || !created.DirectAccessGrants || !created.Enabled {
		t.Errorf("user client shape: %+v", created)
	}
	if created.ServiceAccountsEnabled || created.FullScopeAllowed || created.ImplicitFlowEnabled {
		t.Errorf("user client must not have service accounts / full scope / implicit: %+v", created)
	}
	if created.Attributes["pkce.code.challenge.method"] != "S256" {
		t.Errorf("user client attributes: %+v", created.Attributes)
	}
	mappers := stub.mappers[stub.uuidOf("beamhall-user-agent")]
	if len(mappers) != 1 || mappers[0].ProtocolMapper != "oidc-group-membership-mapper" ||
		mappers[0].Config["full.path"] != "false" || mappers[0].Config["claim.name"] != "groups" {
		t.Errorf("groups mapper = %+v", mappers)
	}

	// Second run: nothing to do — no creates, no attaches.
	stub.creates, stub.attachPut = 0, 0
	res2, err := k.EnsureRealmBaseline(context.Background(), BeamhallRealmBaseline())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if res2.Changed() || stub.creates != 0 || stub.attachPut != 0 {
		t.Errorf("second run changed the realm: %+v (creates=%d attaches=%d)", res2, stub.creates, stub.attachPut)
	}
}

// A baseline that would give the user-tier client a capability scope must be
// refused before anything touches the realm.
func TestEnsureRealmBaselineRefusesWideUserClient(t *testing.T) {
	stub := newBaselineStub()
	k := baselineKeycloak(t, stub)
	bad := BeamhallRealmBaseline()
	for i := range bad.Clients {
		if bad.Clients[i].ClientID == userAgentClientID {
			bad.Clients[i].OptionalScopes = append(bad.Clients[i].OptionalScopes, "beams:write")
		}
	}
	if _, err := k.EnsureRealmBaseline(context.Background(), bad); err == nil {
		t.Fatal("a builder scope on the user client was accepted")
	}
	if stub.creates != 0 {
		t.Fatalf("the realm was touched before the guard fired (%d creates)", stub.creates)
	}
}

func TestEnsureRealmBaselineAttachOnlyRefusesToCreate(t *testing.T) {
	stub := newBaselineStub() // no beamhall-agent at all
	k := baselineKeycloak(t, stub)
	if _, err := k.EnsureRealmBaseline(context.Background(), BeamhallRealmBaseline()); err == nil {
		t.Fatal("a missing attach-only client should be an error, not a create")
	}
	if _, ok := stub.clients["beamhall-agent"]; ok {
		t.Fatal("attach-only client was created")
	}
}

// TestRealmTemplateMatchesBaseline is the anti-drift guard between the two
// provisioning paths: the install-time realm import (realm-template.json) and
// the boot-time EnsureRealmBaseline must describe the same scopes and clients,
// or a fresh install and an upgraded appliance diverge.
func TestRealmTemplateMatchesBaseline(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/keycloak/realm-template.json")
	if err != nil {
		t.Fatalf("read realm template: %v", err)
	}
	var tmpl struct {
		ClientScopes []struct {
			Name string `json:"name"`
		} `json:"clientScopes"`
		Clients []struct {
			ClientID             string             `json:"clientId"`
			PublicClient         bool               `json:"publicClient"`
			StandardFlow         bool               `json:"standardFlowEnabled"`
			DirectAccessGrants   bool               `json:"directAccessGrantsEnabled"`
			DefaultClientScopes  []string           `json:"defaultClientScopes"`
			OptionalClientScopes []string           `json:"optionalClientScopes"`
			ProtocolMappers      []kcProtocolMapper `json:"protocolMappers"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(raw, &tmpl); err != nil {
		t.Fatalf("realm template is not valid JSON: %v", err)
	}

	scopeNames := map[string]bool{}
	for _, s := range tmpl.ClientScopes {
		scopeNames[s.Name] = true
	}
	base := BeamhallRealmBaseline()
	for _, s := range base.ClientScopes {
		if !scopeNames[s.Name] {
			t.Errorf("baseline scope %q is missing from realm-template.json", s.Name)
		}
	}

	byID := map[string]int{}
	for i, c := range tmpl.Clients {
		byID[c.ClientID] = i
	}
	for _, want := range base.Clients {
		i, ok := byID[want.ClientID]
		if !ok {
			t.Errorf("baseline client %q is missing from realm-template.json", want.ClientID)
			continue
		}
		got := tmpl.Clients[i]
		has := func(list []string, name string) bool {
			for _, n := range list {
				if n == name {
					return true
				}
			}
			return false
		}
		for _, s := range want.DefaultScopes {
			if !has(got.DefaultClientScopes, s) {
				t.Errorf("template client %q lacks default scope %q", want.ClientID, s)
			}
		}
		for _, s := range want.OptionalScopes {
			if !has(got.OptionalClientScopes, s) {
				t.Errorf("template client %q lacks optional scope %q", want.ClientID, s)
			}
		}
		if want.AttachOnly {
			continue
		}
		if !got.PublicClient || !got.StandardFlow || !got.DirectAccessGrants {
			t.Errorf("template client %q flow flags diverge from the baseline", want.ClientID)
		}
		if want.GroupsClaimMapper {
			var found bool
			for _, m := range got.ProtocolMappers {
				if m.ProtocolMapper == "oidc-group-membership-mapper" && m.Config["full.path"] == "false" {
					found = true
				}
			}
			if !found {
				t.Errorf("template client %q lacks the groups membership mapper", want.ClientID)
			}
		}
		// The user client's scope guard, asserted against the template too.
		if want.ClientID == userAgentClientID {
			for _, s := range append(append([]string{}, got.DefaultClientScopes...), got.OptionalClientScopes...) {
				if !userAgentAllowedScopes[s] {
					t.Errorf("template gives the user client scope %q", s)
				}
			}
		}
	}
}
