# contextlock.net

The marketing / documentation landing page for ContextLock.

It is a **single self-contained `index.html`** — all CSS, SVG, and JS are
inlined, no build step, no dependencies, no framework. That makes it
deployable to any static host unchanged, and trivial to edit.

```
site/
├── index.html   # the whole site
├── CNAME        # custom domain for GitHub Pages (contextlock.net)
└── README.md    # this file
```

## Preview locally

Just open the file — there is nothing to build:

```bash
# from the repo root
start site/index.html      # Windows
open  site/index.html      # macOS
```

Both light and dark themes ship; the page follows the visitor's OS setting
and has a manual toggle in the top-right. Everything (the hero verification
demo, copy buttons, theme toggle) works from `file://`.

## Deploy

Pick one target. The `dist` is just `site/` itself, so switching later is cheap.

### Option A — GitHub Pages (recommended, wired up)

The repo is public, so Pages is the lowest-friction, zero-cost path and keeps
the site versioned with the code. `.github/workflows/deploy-site.yml` already
does the deploy. To turn it on:

1. **Settings → Pages → Source = "GitHub Actions".**
2. **Settings → Pages → Custom domain = `contextlock.net`** (provisions the
   managed TLS cert; `site/CNAME` already pins the domain). Tick **Enforce HTTPS**
   once the cert is issued.
3. **Point DNS** at GitHub Pages (see below).
4. Push any change under `site/` (or run the workflow manually) to deploy.

DNS records for the apex + `www` (set these at whatever hosts the zone —
Namecheap BasicDNS or a Route 53 hosted zone):

| Type  | Host | Value |
|-------|------|-------|
| A     | `@`  | `185.199.108.153` |
| A     | `@`  | `185.199.109.153` |
| A     | `@`  | `185.199.110.153` |
| A     | `@`  | `185.199.111.153` |
| AAAA  | `@`  | `2606:50c0:8000::153` |
| AAAA  | `@`  | `2606:50c0:8001::153` |
| AAAA  | `@`  | `2606:50c0:8002::153` |
| AAAA  | `@`  | `2606:50c0:8003::153` |
| CNAME | `www`| `mindmodelai.github.io.` |

Verify propagation before enabling HTTPS: `dig +short contextlock.net`.

### Option B — AWS S3 + CloudFront + Route 53

If you prefer to keep contextlock.net inside the Mind Model AWS footprint
(same account as the other properties), host the static file behind CloudFront:

1. `aws s3 mb s3://contextlock.net` and `aws s3 sync site/ s3://contextlock.net/`
   (exclude `CNAME` and `README.md` from the sync — they are Pages-only).
2. ACM cert for `contextlock.net` (+ `www`) in **us-east-1** (CloudFront requires it there).
3. CloudFront distribution: S3 origin (OAC), default root object `index.html`,
   redirect HTTP→HTTPS, the ACM cert as the viewer cert.
4. Route 53 hosted zone for `contextlock.net`, apex + `www` **A/AAAA ALIAS** to
   the distribution. (Creating the zone changes the domain's nameservers — see
   the DNS note below.)

Redeploys are `aws s3 sync site/ s3://contextlock.net/ && aws cloudfront
create-invalidation --distribution-id <id> --paths '/*'`.

## DNS note (registrar)

contextlock.net is registered at **Namecheap**. The Namecheap API is
IP-allowlisted, so DNS records cannot be scripted from every machine (the
build box currently 403s: *"Invalid request IP"*). Set records either:

- by hand in the Namecheap dashboard (Domain List → Manage → Advanced DNS), or
- by adding the build box's public IP to **Namecheap → Profile → Tools →
  API Access → whitelisted IPs**, then re-running the tooling, or
- by delegating the zone to Route 53 (Option B) — update the nameservers at
  Namecheap to the four the hosted zone hands you.

The repo homepage already points at `https://contextlock.net`.

## Editing

- Copy is grounded in `../README.md` and `../SPEC.md`; keep the two in sync
  (e.g. test count, npm scope, threat IDs). Figures currently cited: 375 tests,
  Ed25519 + Sigstore keyless, `@contextlock/*` provenance-attested.
- The visual system is a token set at the top of the `<style>` block
  (`--brass`, `--ink`/`--bg`, verdict colors, both themes). Change colors
  there, not inline.
- The hero terminal script is the `L` array near the bottom of the file —
  each entry is `[cssClass, html, delayMs]`.
