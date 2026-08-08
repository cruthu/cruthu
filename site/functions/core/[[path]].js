// Wildcard module-resolution fallback for paths under /core/.
//
// site/core/index.html handles the exact module root, which is what
// proxy.golang.org fetches and is sufficient in the normal case. This handler
// covers direct-mode resolution (GOPROXY=direct, GOPRIVATE), where the go
// command probes the full import path — cruthu.dev/core/some/pkg?go-get=1 —
// before falling back to shorter prefixes. Without it, those probes 404 and
// resolution depends entirely on the fallback behavior of whichever Go version
// the user is running.
//
// The mapping is an explicit allowlist, never derived from the request path. A
// handler that synthesized a repository URL out of the incoming URL would let
// the request decide where `go get` fetches code from, which is the one failure
// this whole file exists to make impossible. Adding a module means adding a row
// here and a row in the table in site/vanity_test.go, which asserts that this
// file, site/core/index.html, and go.mod all agree.
//
// See docs/decisions/0004-module-path-and-domain.md.

// VANITY-TABLE-BEGIN
const MODULES = {
  // The open-source core: CLI plus, eventually, the reconciler packages.
  // Backed by the monorepo, whose name deliberately does not match the path.
  "cruthu.dev/core": "https://github.com/cruthu/cruthu",
};
// VANITY-TABLE-END

const DOCS = "https://pkg.go.dev/";

/**
 * Serve the go-import tag for a module path under /core/, and send humans on to
 * pkg.go.dev. Unknown paths fall through to the static site's 404 rather than
 * guessing at a repository.
 */
export function onRequest(context) {
  const modulePath = "cruthu.dev/core";
  const repo = MODULES[modulePath];
  if (repo === undefined) {
    return context.next();
  }

  const body = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="go-import" content="${modulePath} git ${repo}">
<meta http-equiv="refresh" content="0; url=${DOCS}${modulePath}">
<title>${modulePath}</title>
</head>
<body>
<p>Go module path <code>${modulePath}</code>. Redirecting to
<a href="${DOCS}${modulePath}">its documentation</a>.</p>
</body>
</html>
`;

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      // Short cache: this is release infrastructure, and a bad value sitting in
      // an edge cache for a day is worse than an extra origin fetch.
      "cache-control": "public, max-age=300",
      "x-content-type-options": "nosniff",
    },
  });
}
