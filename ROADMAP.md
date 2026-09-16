# cruthu Roadmap

The path from first correlator to stable release to the paid evidence layer. Effort estimates assume
a nights-and-weekends pace alongside other work, and are deliberately conservative. Each minor release
is designed to be shippable and announceable on its own, so that a slip in one does not stall the
project.

This roadmap is a plan, not a promise. Scope and timing will move as real usage teaches us what
matters. Schema-affecting changes are logged in `docs/decisions/`.

**Rev. 2 note:** this roadmap was restructured around a thesis change: the signed attestation is now
the product, not the third artifact bolted on at the end. The old sequence built the interesting
engineering first and the evidence layer at 0.5; this one publishes the predicate spec immediately and
gets to a verifiable artifact by the third release, because that artifact is what a discovery
conversation with a compliance buyer actually needs. A rename to a name other than `cruthu` has been
proposed for the reasons that motivated this restructure, but it is not adopted here — two trademark
and domain checks are still outstanding, and the module path, CLI binary, and GitHub org all stay
`cruthu` until that clears. See `personal_notes/updated_spec.md` for the full rationale (private,
not tracked in this repository).

### 0.0, "The spec" (one weekend, before any more code)
- Publish the runtime-reconciliation predicate schema at a stable versioned URI, with explicit
  MUST-reject rules for verifiers and a short rationale: why existing predicate types don't fit, how
  to verify one.
- Publish revocation and retention semantics as a policy document, separate from the schema.
- Take both to the in-toto and OpenSSF calls. Being publicly argued with by credible people is the
  credential a solo project cannot otherwise buy.

### 0.1, "The correlator" (3 to 4 weekends)
The smallest thing that proves the thesis. **Offline only.**
- `cruthu index` + `cruthu check` against a recorded Tetragon export file.
- CycloneDX parsing for package identity; the file-to-package index is built from the image's own
  package database (dpkg first), not from the SBOM's file list, because most SBOMs don't carry one.
  See `docs/decisions/0001-index-is-the-spine.md`.
- Single container. JSON + table output. Exit codes.
- Ship with a reproducible demo: a Dockerfile, a script that runs the container under Tetragon, drops
  a fake malicious binary in via `kubectl exec`, and shows `cruthu` catching it. **The demo repo is
  half the release**, it's what the README gif, the blog post, and any demo walkthrough all come from.
- Success gate: a stranger can clone the demo and reproduce the catch in under 10 minutes.

### 0.2, "Signed evidence" (2 to 3 weekends)
Pulled forward from 0.5. The most important release in the plan, because it is the first one that
produces the artifact the product is actually about.
- `cruthu attest` + `cruthu verify` + `cruthu export`. Keyless signing default (Rekor via Fulcio),
  local-key signing supported, and the signer interface is in place with both implementations behind
  it from day one — a hosted countersigner is a third, optional implementation of the same interface,
  not a special case.
- `export` bundles a date range plus a verification script into something that can actually be handed
  to an assessor; it is the command that gets used in an audit, not `attest`.
- Success gate: the three-minute demo. A signed record, a laptop with networking disabled, verification
  against a policy file passing, then the same verification against a tampered record failing.

### 0.3, "Live" (2 to 3 weekends)
- `watch` mode: tail Tetragon's gRPC/export stream and Tracee's JSON stream live.
- SPDX support. SQLite observation store (survives restarts, enables "observed over N days" later).
- Noise-suppression config (`cruthu.yaml`), allowlists, path scoping for interpreted apps.
- Observation-gap tracking: a window with an unmonitored hole in it is not a conformant window, and
  the attestation has to say so rather than silently paper over the gap. Gaps get signed, not hidden.
- Success gate: runs against a real service for 72h with zero false criticals.

### 0.4, "The CVE killer feature" (2 weekends)
- `cruthu cve`: ingest Grype or Trivy JSON, join against in-use package set, output "N of M CVEs are
  in code that actually executed."
- Still the most shareable release, but it is now marketing for the evidence layer rather than the
  headline claim. Lead the announcement with a real number from a popular public image.
- SARIF output lands here so the prioritized list shows up in GitHub Security tabs.

### 0.5, "Debloat advisor" (2 weekends)
- `cruthu slim`: emit the observed-necessary package set as (a) a human report and (b) an apko YAML
  skeleton for a Wolfi-based rebuild.
- Explicitly a *recommendation*, document the coverage caveat (only as good as the exercised code
  paths) prominently. This closes the loop with a minimal-base-image workflow: profile with cruthu,
  rebuild minimal with apko/Wolfi, verify with cruthu again.

### 0.6, "Kubernetes-native" (3 to 4 weekends)
- Helm chart: cruthu as a Deployment, unprivileged, single replica, consuming a cluster's *existing*
  Tetragon DaemonSet rather than shipping one of our own. No privileged component ships in this
  project, ever, in any release — see "What cruthu is not" in `README.md`.
- Per-workload SBOM discovery via registry attestation/referrers lookup (zero-config path when the
  image already carries an attached SBOM).
- CRDs (`ReconciliationPolicy`, `Reconciliation`) rather than a bolted-on UI. Multi-container,
  namespace/label selectors, Prometheus metrics endpoint (`cruthu_drift_events_total`, etc.).

### 0.7 to 0.9, Hardening to 1.0 (2 to 3 months elapsed)
- Registry SBOM pull (Harbor, generic OCI referrers API; JFrog if a user asks).
- Schema freeze process: mark JSON output and the predicate v1-rc, run a deprecation window.
- Docs site, threat model doc (what this catches, what it doesn't, honesty here builds more trust than
  breadth claims), fuzzing on the SBOM parsers, integration test matrix (Tetragon×Tracee ×
  CycloneDX×SPDX × dpkg/apk/rpm images).
- Signature longevity plan: algorithm agility and re-attestation tooling, written down before a
  ten-year-old record's algorithm assumptions age out. The index-rebuild drill (deliberately wipe and
  rebuild the disposable index/lookup state from the append-only log, as a signed artifact of its own)
  also lands here.
- Cut 1.0 when: schemas frozen, 72h+ soak on 3+ real workloads with zero false criticals, demo
  reproducible, predicate spec published and has been public long enough to have taken criticism.

### 1.0, Stable
- Announcement post structured as the full narrative: build minimal (apko) → sign (cosign) → deploy →
  **verify continuously (cruthu)** → attest → verify offline years later. Submit to CNCF landscape
  (Security & Compliance), r/kubernetes, Hacker News.
- License decision point (see below).

### 1.x series, Adoption features (6 to 9 months)
- **1.1** SIEM and OpenTelemetry export, moved up in priority from the original plan. Drift events go
  to whatever aggregator the customer already runs, in their format, as fast as possible — this is how
  a security team recognizes the tool as real software, even though the evidence layer is what gets
  paid for.
- **1.2** Admission-controller companion: block deploys of images whose *previous* version showed
  unresolved drift, or require a valid runtime attestation for promotion to prod. First taste of
  enforcement, still self-hosted.
- **1.3** Windows-container and standalone-Docker (non-K8s) support **only if users ask**, resist
  speculatively.
- **Cut, not deferred: a native eBPF sensor.** Earlier drafts of this roadmap carried it as a 1.4
  "investigation, not commitment." It is now out, not "default no" — it contradicts the unprivileged
  posture that makes the tool acceptable to the target buyer, and it was the single biggest scope risk
  in the document.

### The paid layer
Everything before this line is Apache-2.0 and free forever: the CLI and controller, full
reconciliation, unprivileged operation, local signed records under the customer's own key kept
forever, the Rekor-only (keyless) signer, and the published predicate schema and verification path.
Nothing in the verification path requires trusting or reaching a vendor — that property is load-bearing
for the sale, not a limitation of the free tier.

What's paid is receipt, not detection: an independent countersignature over the customer's own record,
long-horizon timestamp anchoring and retention, auditor-ready report generation against named
compliance frameworks, a customer-sovereign log deployment for estates that require one, and
fleet-level views with baseline persistence across workloads. A self-hoster who wants a countersigner
without paying us must be able to point the signer interface at their own service — a signer interface
with exactly one usable implementation is a hook, not an interface, and it would make the free tier
read as bait.

There is deliberately no hosted control plane and no agent phoning home over gRPC. The wedge for this
product is customers who cannot phone home by definition (air-gapped and regulated estates); anything
that requires vendor egress disqualifies the product from the market the larger, better-funded
competitors in this space can't serve. The Kubernetes controller and everything it touches runs on the
customer's side and they operate it; the paid layer is a narrow, occasionally-contacted signing and
receipt service, not a platform.

Licensing: the core stays Apache-2.0. There is no BSL-vs-proprietary control-plane question to decide,
because there is no control plane — the closed parts are the countersigning service itself, the signing
keys, the report templates, and the customer relationships. Keeping the reconciliation logic and
especially the verifier open and forkable is itself part of the pitch: a customer betting years of
audit evidence on a small vendor needs to be able to inspect and, if necessary, fork the thing that
tells them whether a record is trustworthy.

---

## Risks worth writing down

- **File-level SBOM gap** (most SBOMs lack file lists), mitigated by owning the index step; this is
  also quietly a differentiator.
- **Interpreted languages** (python/node app code isn't "packages"), scope v1 claims to binaries +
  shared objects; app-code integrity is dm-verity/IMA territory, not a v1 promise.
- **Tetragon/Tracee API churn**, pin versions, adapter interface, integration tests in CI.
- **Competitors.** Not just Kubescape and Sysdig. Runtime reachability ("which CVEs actually execute")
  is a funded, crowded category — Oligo, Upwind, Kodem, Endor Labs, Wiz, Aqua, Sysdig, Kubescape — and
  at least one already publishes a runtime-evidence-to-compliance mapping against named frameworks.
  Shipping a better free version of their headline feature competes on their turf with none of their
  budget. The counter is not a feature list: it's no-egress operation plus a verification path that
  doesn't require trusting the vendor's continued existence. If an incumbent ships a genuinely
  self-hosted, no-egress tier with verifiable attestation, this wedge closes.
- **No technology moat.** Rekor is public, cosign is open, the underlying cryptography is standard; a
  competent engineer could rebuild the core of this in a quarter. What isn't easily rebuilt is a
  countersignature backed by an entity with a track record — reputation, longevity, and assessor
  relationships matter more here than the code does.
- **Signature longevity.** Ten-year retention horizons outlive algorithm assumptions. Version the
  schema, record the algorithm used, and build re-attestation tooling before a customer asks for it
  rather than after.
- **Regulatory timing.** Compliance mandates this product leans on (CMMC and similar) move on their
  own schedule and can pause with no revised timeline, which buyers may read as permission to wait.
  Underlying obligations (e.g. DFARS 7012, NIST 800-171, SPRS) tend to outlast any single program's
  pause, but expect the objection in early conversations regardless.
- **Maintainer bandwidth.** This is a solo, part-time project. The 0.x releases are deliberately sized
  so that any single one can slip without the project dying. 0.0 through 0.2 alone (publish the spec,
  correlate, sign the evidence) form a complete and coherent story on their own if nothing past that
  ships on schedule.
