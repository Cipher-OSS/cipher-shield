# Network and corporate proxy requirements

cipher-shield's registry proxy receives `npm install` and `pip install` traffic from developer machines. If your organization runs a secure web gateway (SWG), DNS security layer, or corporate proxy, a one-time configuration change is required to allow that traffic through.

---

## How traffic flows

Developers point their package managers at your cipher-shield domain:

```
npm install axios        pip install requests
         │                      │
         └──────────┬───────────┘
                    ▼
     proxy.yourcompany.com:443  (HTTPS)
                    │
                    ▼
     cipher-shield ALB / load balancer
                    │
                    ▼
     cipher-shield proxy (scans, then forwards to registry.npmjs.org / pypi.org)
```

Traffic uses standard HTTPS on port 443 with a valid TLS certificate. No non-standard ports, no plain HTTP.

---

## Cisco Umbrella

Two policy changes are required — both are one-time, tenant-wide.

**DNS policy — allow list**

Add your cipher-shield domain to the DNS allow list so Umbrella's DNS layer never blocks resolution:

| Entry | Type |
|---|---|
| `yourcompany.com` (or the specific subdomain, e.g. `proxy.yourcompany.com`) | Domain |

Navigate to: **Umbrella dashboard → Policies → DNS Policies → [your policy] → Allow List**

**SSL inspection — bypass list**

Add your cipher-shield domain to the SSL inspection bypass list. cipher-shield is your own infrastructure — there is no value in inspecting it, and bypassing eliminates any risk of inspection breaking package manager certificate validation.

| Entry | Type |
|---|---|
| `*.yourcompany.com` (or the specific subdomains) | Domain |

Navigate to: **Umbrella dashboard → Policies → SSL Decryption Policy → Do Not Decrypt**

Once both rules are in place, Umbrella passes cipher-shield traffic transparently without inspection or intervention.

---

## Zscaler Internet Access (ZIA)

**URL category — allow**

Add your cipher-shield domain as a custom URL category set to `Allow`:

Navigate to: **ZIA → Policy → URL & Cloud App Control → Custom URL Categories → Add**

**SSL inspection — bypass**

Add your domain to the SSL inspection bypass policy:

Navigate to: **ZIA → Policy → SSL Inspection → Add Rule** → set action to `Do Not Inspect` for your cipher-shield domain.

---

## Netskope

**Real-time Protection policy**

Create a policy allowing traffic to your cipher-shield domain:

Navigate to: **Netskope → Policies → Real-time Protection → New Policy** → destination domain = your cipher-shield domain, action = `Allow`.

**SSL decryption — bypass**

Navigate to: **Netskope → Settings → Security Cloud Platform → SSL Decryption** → add your domain to the bypass list.

---

## Palo Alto Prisma Access / NGFW

Add your cipher-shield domain to a Security Policy rule with action `Allow` and exclude it from SSL decryption profiles.

---

## Generic corporate HTTP proxy (HTTPS_PROXY / http_proxy)

If developers are behind a corporate HTTP proxy rather than an agent-based SWG, npm and pip respect standard proxy environment variables:

```sh
export HTTPS_PROXY=http://proxy.yourcompany.com:8080
export NO_PROXY=shield.yourcompany.com,proxy.yourcompany.com
```

Adding cipher-shield's domains to `NO_PROXY` routes package manager traffic directly to cipher-shield, bypassing the corporate proxy. This is the recommended configuration — cipher-shield is already inspecting every package, so routing through an additional proxy is redundant. Both npm and pip traffic share `proxy.yourcompany.com`, so a single `NO_PROXY` entry covers both.

---

## Why bypass SSL inspection?

cipher-shield is internal infrastructure you control. SSL inspection is designed to catch threats from unknown third-party destinations — it provides no additional security for a service you own and operate. Bypassing it:

- Eliminates any risk of the SWG's substitute certificate breaking package manager TLS validation
- Reduces latency on every `npm install` and `pip install`
- Avoids sending your internal package traffic through the SWG's inspection infrastructure

---

## Firewall requirements

If your network uses an egress firewall, cipher-shield's proxy containers need outbound HTTPS (port 443) to:

| Destination | Purpose |
|---|---|
| `registry.npmjs.org` | npm package downloads |
| `pypi.org`, `files.pythonhosted.org` | PyPI package downloads |
| `osv.dev` | CVE lookups (Tier 2) |
| `api.anthropic.com` | Claude analysis (Tier 4, optional) |
| `shield.yourcompany.com` | Proxy reporting scan results to API (Option B — local proxy only) |
