# 0004 — The module path is a vanity path, and the apex that serves it stays inert

**Status:** accepted
**Date:** 2026-08-08

## Context

`go.mod` has declared `module cruthu.dev/core` since the first commit, and `README.md` has advertised
`go install cruthu.dev/core/cmd/cruthu@latest`, but nothing answered at that domain. Module resolution
is one HTTP response:

```
GET https://cruthu.dev/core?go-get=1
<meta name="go-import" content="cruthu.dev/core git https://github.com/cruthu/cruthu">
```

Three fields — module root path, VCS, repository URL. Whatever serves that tag decides which repository
every `go get cruthu.dev/core` in the world fetches from.

That is a supply-chain root of trust for our own users, owned by us, in a project whose entire pitch is
supply-chain trust. It is also the same domain that will eventually front a commercial control plane
(`ROADMAP.md`, 2.0). Both facts had to be settled at once, because the cost of changing either later is
paid by consumers.

## Decision

**The vanity path stays, with no version suffix.** `cruthu.dev/core` rather than
`github.com/cruthu/cruthu`, so imports survive a move between code hosts — the realistic scenarios being
an org rename or a move off GitHub, neither of which should be a breaking change for consumers. No
`/v1`: Go's semantic import versioning omits the suffix for v0 and v1, and `/v2` is added to the path and
to every import only at a breaking major version.

**The mapping is an explicit allowlist, in two places that a test forces to agree.**
`site/core/index.html` serves the exact module root, which is the URL proxy.golang.org fetches.
`site/functions/core/[[path]].js` serves the same tag for deeper paths, covering direct-mode resolution
(`GOPROXY=direct`, `GOPRIVATE`) where the go command probes the full import path before falling back to
shorter prefixes. Neither derives a repository URL from the request. A handler that did would let the
request decide where `go get` fetches code from.

**`site/vanity_test.go` pins the property, offline.** It parses the `module` line out of `go.mod`, the
`go-import` tag out of each page, and the allowlist out of the JavaScript, then asserts all three agree —
plus that the VCS is `git`, the repository is `https`, and the repository is not the vanity domain itself.
It runs under the existing `make test` with no network and no new dependency. The directory contains only
test files, which is a valid package.

**The apex serves nothing dynamic.** `cruthu.dev` is static pages plus that tag: no cookies, no auth, no
script, no third-party asset, and a `default-src 'none'` CSP in `site/_headers` that is only achievable
because of it. The future control plane takes `app.cruthu.dev` and `api.cruthu.dev`. An authenticated
application sharing an origin with module resolution would put session handling and dynamic code behind a
route whose compromise redirects every user's `go get`.

**A Cloudflare Worker route on `cruthu.dev/core*` serves the tag independently of the site deployment.**
Worker routes take precedence over the Pages origin, so the module path survives a future redesign, CMS
migration, or host change. The static page alone is one careless deploy away from vanishing.

## Consequences

- **The domain is load-bearing forever.** Once `cruthu.dev/core@v0.1.0` is fetched by proxy.golang.org,
  the path and its hash are in the checksum database permanently. Already-published versions keep
  building from the proxy cache even if the domain lapses, but `@latest` resolution and every future
  version need `cruthu.dev` answering. Losing the domain forces a module path change, which breaks every
  consumer. Mitigation is a long registration and auto-renew, not a different design.
- **Never redirect `/core` to GitHub.** GitHub serves no `go-import` tag, so the go command would infer a
  `github.com/...` module path and fail with a path mismatch. The tag must be served with HTTP 200.
- **Adding a module path is a three-part change**: a row in `vanityModules`, a page, and a row in the
  JavaScript allowlist. The test fails on a partial addition, including on an extra JavaScript entry that
  no page or test row declares — an unreviewed entry there is a hole in the allowlist, and the same
  reasoning that governs noise suppression applies.
- **`internal/` means there is no importable API yet.** The path resolves as an install target. Public
  packages wait for the output schemas to stabilize, so `pkg.go.dev` will show little until then.
- **The site duplicates prose from `README.md` and `ROADMAP.md`** and will drift from them. Accepted for
  now over adding a static-site generator: the copy is small, and the docs site is a 0.7-0.9 roadmap
  item. If a generator arrives, this decision is what says not to let it own `/core`.
