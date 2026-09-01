// /llms.txt — the llms.txt convention (https://llmstxt.org): a short, curated
// markdown index of the site for LLMs and agents, so a model that lands here
// gets the accurate description of Beamhall instead of guessing from chrome.
const site = "https://beamhall.com";

const body = `# Beamhall

> Beamhall is a self-hosted, MCP-controlled application backplane: AI coding
> agents build and deploy internal apps ("beams"), and each app inherits its
> infrastructure — hardened runtime, managed Postgres, a write-only secret
> vault, company sign-in, brokered email and object storage, TLS routing — as
> capabilities provisioned behind policy. The agent never receives a credential,
> an endpoint, or a config file.

Beamhall is a single Go binary you run on your own hardware (private VM,
dedicated VPC, or on-prem). Apache-2.0, no SaaS, no phone-home, air-gap
friendly. Current release: v0.5.1 (pre-1.0, entering design-partner validation).

Key ideas, if you only remember three things:

- The agent and the code it writes are both treated as **untrusted**.
- The agent asks for a **capability**, not for infrastructure; secrets and
  database connection strings are injected into the running app and never
  returned to the agent.
- Security defaults are **structural, not advisory**: least privilege,
  read-only root filesystem, default-deny egress, per-workspace isolation, and
  IT-gated promotion from preview to live — with no agent tool to widen any of
  them.

Common synonyms: a "beam" is an app / website / service / API / internal tool.
A "beamhall" is a workspace. The agent-facing control surface is MCP.

## Core pages

- [Beamhall overview](${site}/): what Beamhall is, what a beam inherits, and why an agent gets a handle instead of a credential.
- [Walkthrough](${site}/#walkthrough): a real agent session shipping an internal RSVP app end to end.
- [Architecture](${site}/#architecture): the request path, the trust boundary, and what the agent never touches.
- [Features](${site}/#features): what is built in and which separate tooling it replaces.
- [Security](${site}/#security): the buyer-facing security story and guarantees.
- [Roadmap](${site}/#roadmap): what is built and validated, and what is planned.
- [Get started](${site}/#install): install Beamhall on your own host.

## Comparisons

- [Beamhall vs Dokploy vs Coolify](${site}/alternatives/beamhall-vs-dokploy-vs-coolify/): why a self-hosted PaaS and an agent backplane answer different questions. ([markdown](${site}/alternatives/beamhall-vs-dokploy-vs-coolify.md))

## Source and documentation

- [Source repository](https://github.com/Beamhall/beamhall): the Go implementation, Apache-2.0.
- [Documentation](https://github.com/Beamhall/beamhall/tree/main/docs): all published Beamhall docs.
- [Threat model](https://github.com/Beamhall/beamhall/blob/main/docs/threat-model.md): the security document; every mitigation cites a test or a lab finding.
- [Getting started](https://github.com/Beamhall/beamhall/blob/main/docs/getting-started.md): an IT admin's first hour, from install to a deployed beam.
- [Beamhall for IT](https://github.com/Beamhall/beamhall/blob/main/docs/beamhall-for-it.md): what Beamhall requires of the team that runs it.
- [Administering over MCP](https://github.com/Beamhall/beamhall/blob/main/docs/admin-over-mcp.md): the \`admin_*\` tool family and its guardrails.
- [Identity provider setup](https://github.com/Beamhall/beamhall/blob/main/docs/idp-setup.md): connecting Keycloak, Okta, Entra or any OIDC IdP.
- [Air-gapped operation](https://github.com/Beamhall/beamhall/blob/main/docs/air-gapped.md): running with no internet egress.
- [Agent-conformance suite](https://github.com/Beamhall/beamhall/blob/main/docs/agent-conformance.md): four authenticated personas proving isolation and four-eyes control.
- [Changelog](https://github.com/Beamhall/beamhall/blob/main/CHANGELOG.md): what shipped in each release.

## Optional

- [Full text of every page](${site}/llms-full.txt): the site's substantive content as one markdown file.
- [Sitemap](${site}/sitemap-index.xml)
`;

export const GET = () =>
  new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
