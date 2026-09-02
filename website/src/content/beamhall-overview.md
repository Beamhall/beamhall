# Beamhall — a self-hosted AI app platform

> Canonical page: https://beamhall.com/
> Source: https://github.com/Beamhall/beamhall (Apache-2.0) · Current release: v0.7.0

Beamhall is a self-hosted **application backplane**: AI coding agents build and
deploy internal apps (**beams**) by intent alone. Each beam **inherits everything
it needs to run** as managed capabilities from Beamhall — compute, data, secrets,
identity, and secure connectivity. The agent never provisions, configures, or
holds credentials for any of it. And once an app is live, the rest of the
company reaches it the same way: through their **own** AI agents, which discover
and use exactly the apps IT published to them.

The agent asks for a capability (a database, a secret, user authentication, a
connection to the ERP) and Beamhall provisions it behind policy, handing back a
**handle, never the wiring**.

Single Go binary · self-hosted · no SaaS · no phone-home · air-gap-friendly ·
Apache-2.0.

## The core principle

A beam **inherits its infrastructure**; the agent never touches it. Runtime,
database, secrets, end-user identity, and a secure path to internal systems are
each provisioned by Beamhall under a policy the agent cannot influence, and every
grant is audited. The agent declares the need; it never sees a credential, an
endpoint, or a config file.

## What a beam inherits

- **Runtime** — hardened, isolated compute (runc or gVisor runsc), built from source with Cloud Native Buildpacks, no Dockerfile.
- **Data & secrets** — a managed Postgres database per beam and a write-only secret vault, injected at runtime.
- **Networking** — routing and TLS at the gateway, default-deny egress, per-app isolation; apps reach each other only through IT-granted, audited relay calls, never the network.
- **Identity** — one call gives a beam company sign-in: it becomes an OIDC relying party on Beamhall's bundled IdP, so employees log in with the accounts they already have. No IdP config, no credential reaches the agent, and tokens are audience-isolated so an app token can't reach the backplane.
- **Email** — one call gives a beam outbound email through a shared in-hall broker: it sends with any SMTP library while the mail-provider credential stays in the broker, with a per-beam sender allowlist, STARTTLS, and every message audited.
- **Object storage** — one call gives a beam S3-compatible object storage the same way a database is provisioned: it uses any stock S3 SDK while Beamhall stores the bytes (on the appliance or in your own S3, and the app can't tell which), with no storage account and no credential it can use outside the hall.
- **Users** — once live, IT publishes the beam to an audience (everyone, groups, or named people) and those people's own AI agents discover it and act through its tools: brokered, audited, no rollout, no per-app accounts.
- **Connectors** — email and object storage ship today; queues and brokered paths to internal systems (ERP databases, integrations) are planned, without the beam ever holding their credentials.

## A reliable path, not improvised infrastructure

Ask a typical agent to deploy and it **improvises**: GitHub Actions, Fly.io, Neon,
a guessed Dockerfile, a half-remembered cloud CLI, scattering your app across
third-party providers in a way no two runs repeat. Beamhall gives the agent a
single, documented MCP tool surface and a built-in knowledge base that teaches it
how to ship *here*, so it follows a known-good, governed path every time.
Nothing leaves your environment.

## Employees use apps through their own agents

Shipping is half the story. Once an app is live, IT publishes it to an
**audience** — everyone, specific groups, or named people
(`admin_set_app_audience`) — and those people's own AI agents take it from
there: they discover the app (`list_apps` / `describe_app`) and act through the
tools it exposes (`use_app`), with no workspace membership, no separate
sign-in, and no rollout. Users register themselves on first contact.

Employees don't get another dashboard. A person's agent sees exactly the apps
published to them — an unpublished or out-of-audience app is indistinguishable
from one that doesn't exist — and Beamhall brokers every call: the app receives
a short-lived, Beamhall-signed statement of who is calling and what they asked
for, while the person's company sign-in token is never forwarded. Builders
rehearse the same tool surface on the preview channel with `try_beam_tool`
before anything is published, and every brokered call lands on the audit chain.

An app exposes tools by serving a tiny two-route HTTP contract
([docs/app-tools.md](https://github.com/Beamhall/beamhall/blob/main/docs/app-tools.md))
— any language, nothing to enable. The same brokered relay, under per-app IT
grants, is how apps use each other's tools.

## IT decides where apps run

You choose the substrate per workspace — a private VM, a dedicated VPC, or fully
on-prem — for heavy-compliance or strictly-internal workloads. The gateway is the
single ingress and egress is default-deny, so exposure is deliberate and
policy-driven: there is no cloud security group or load balancer to misconfigure
into accidental public access.

## What Beamhall replaces

| Built in | Replaces |
| --- | --- |
| Integrated Git: a private repo per app; `git push` builds and deploys | Git host · CI runners · pipeline YAML |
| Buildpacks: apps built from source into hardened images | Container registry · build servers · Dockerfiles |
| Built-in gateway: automatic HTTPS and a stable URL | TLS certs · DNS · reverse proxy · load balancer |
| Managed Postgres: a database per app, injected at runtime | Database provisioning · connection-string wiring |
| Secret vault: write-only, delivered into the app | Vault · CI secrets · rotation glue |

## The control IT keeps

- Set the rules once, per workspace: where it runs, resource quotas, isolation tier (hardened runc or gVisor), and what it can reach (default-deny network).
- Role-based deploy, promote and destroy; an agent can never exceed the role granted to it.
- Optional four-eyes approval before anything goes live.
- IT curates which employee groups an app's sign-in tokens may carry; preview and production get separate credentials.
- IT publishes each app to an audience — everyone, groups, or named people. Audiences live in Beamhall, not the IdP (group audiences match the groups the IdP already asserts), and anyone outside the audience can't tell the app exists.
- IT decides which apps may talk to each other: apps have no network path to one another (not even in the same workspace); app-to-app calls exist only as IT-granted pairs through Beamhall's audited relay, and revoking a grant cuts them off instantly.
- Tamper-evident, append-only audit of every action and every denied attempt, tied to an identity.
- Back up and restore the whole appliance (keys included) to a byte-identical state.

## Security posture in one paragraph

Both the agent and the code it writes are treated as untrusted. Apps start
least-privileged with a read-only root filesystem and default-deny egress. The
agent has no tool to open the network, read a secret, raise a quota, change its
runtime security context, or reach another workspace — those operations do not
exist in its tool surface. Apps have no network path to each other; the only
app-to-app channel is the platform's relay, which authenticates the calling
workload on every request, honors only IT-granted pairs, identifies the caller
to the target as an app (never a person), and audits every call. When a
person's agent uses an app, the same broker delivers a short-lived signed
statement of who is calling — never their IdP token — and only IT-published
apps resolve at all. The full
threat model is published at
https://github.com/Beamhall/beamhall/blob/main/docs/threat-model.md

## Status

Pre-1.0 (v0.7.0). The core security surface and the end-to-end workflow are built
and validated on hardware; the project is entering design-partner validation.
Company sign-in, outbound email, object storage, audience-published app tools
for employees' own agents, and IT-granted app-to-app calls ship today; queues
and further brokered connectors to internal systems are next.
