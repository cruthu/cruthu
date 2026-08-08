# cruthu Roadmap

The path from first correlator to stable release to the commercial control plane. Effort estimates assume a nights-and-weekends pace alongside other work, and are deliberately conservative. Each minor release is designed to be shippable and announceable on its own, so that a slip in one does not stall the project.

This roadmap is a plan, not a promise. Scope and timing will move as real usage teaches us what matters. Schema-affecting changes are logged in `docs/decisions/`.

### 0.1, "The correlator" (3 to 4 weekends)
The smallest thing that proves the thesis. **Offline only.**
- `cruthu index` + `cruthu check` against a recorded Tetragon export file.
- CycloneDX parsing only. Single container. JSON + table output. Exit codes.
- Ship with a reproducible demo: a Dockerfile, a script that runs the container under Tetragon, drops a fake malicious binary in via `kubectl exec`, and shows `cruthu` catching it. **The demo repo is half the release**, it's what the README gif, the blog post, and any demo walkthrough all come from.
- Success gate: a stranger can clone the demo and reproduce the catch in under 10 minutes.

### 0.2, "Live" (2 to 3 weekends)
- `watch` mode: tail Tetragon's gRPC/export stream and Tracee JSON stream live.
- SPDX support. SQLite observation store (survives restarts, enables "observed over N days" later).
- Noise-suppression config (`cruthu.yaml`), allowlists, path scoping for interpreted apps.
- Success gate: runs against a real service for 72h with zero false criticals.

### 0.3, "The CVE killer feature" (2 weekends)
- `cruthu cve`: ingest Grype or Trivy JSON, join against in-use package set, output "N of M CVEs are in code that actually executed."
- This is the release that gets shared, because it answers the question every platform team asks ("which of these 400 CVEs do I actually care about?"). Lead the announcement with a real number from a popular public image.
- SARIF output lands here so the prioritized list shows up in GitHub Security tabs.

### 0.4, "Debloat advisor" (2 weekends)
- `cruthu slim`: emit the observed-necessary package set as (a) a human report and (b) an apko YAML skeleton for a Wolfi-based rebuild.
- Explicitly a *recommendation*, document the coverage caveat (only as good as the exercised code paths) prominently. This closes the loop with a minimal-base-image workflow: profile with cruthu, rebuild minimal with apko/Wolfi, verify with cruthu again. The end-to-end story (build minimal, sign, deploy, verify continuously, attest) is a coherent narrative for a talk or writeup.

### 0.5, "Signed evidence" (2 to 3 weekends)
- `cruthu attest` + `cruthu verify`. Publish the runtime-conformance predicate spec v0 as a standalone versioned document; solicit feedback in Sigstore/OpenSSF Slack.
- Keyless signing default, key-based supported.
- This is the release that differentiates cruthu from Kubescape and Sysdig in one screenshot: `cosign verify-attestation` succeeding on a runtime claim.

### 0.6, "Kubernetes-native" (3 to 4 weekends)
- Helm chart: cruthu as a Deployment consuming a cluster's existing Tetragon DaemonSet; per-workload SBOM discovery via registry attestation lookup (if the image has a Syft SBOM attached as an attestation, fetch it automatically, zero-config path).
- Multi-container, namespace/label selectors, Prometheus metrics endpoint (`cruthu_drift_events_total`, etc.).

### 0.7 to 0.9, Hardening to 1.0 (2 to 3 months elapsed)
- Registry SBOM pull (Harbor, generic OCI referrers API; JFrog if a user asks).
- Schema freeze process: mark JSON output and predicate v1-rc, run a deprecation window.
- Docs site, threat model doc (what this catches, what it doesn't, honesty here builds more trust than breadth claims), fuzzing on the SBOM parsers, integration test matrix (Tetragon×Tracee × CycloneDX×SPDX × dpkg/apk/rpm images).
- Cut 1.0 when: schemas frozen, 72h+ soak on 3+ real workloads with zero false criticals, demo reproducible, predicate spec published.

### 1.0, Stable
- Announcement post structured as the full narrative: build minimal (apko) → sign (cosign) → deploy → **verify continuously (cruthu)** → attest. Submit to CNCF landscape (Security & Compliance), r/kubernetes, Hacker News.
- License decision point (see below).

### 1.x series, Adoption features (6 to 9 months)
- **1.1** OpenTelemetry export; Falco alert output format (meet SOC teams where they are rather than competing with their SIEM).
- **1.2** Admission-controller companion: block deploys of images whose *previous* version showed unresolved drift, or require a valid runtime attestation for promotion to prod. First taste of enforcement, still self-hosted.
- **1.3** Windows-container and standalone-Docker (non-K8s) support **only if users ask**, resist speculatively.
- **1.4** Native thin sensor *investigation* (not commitment): a minimal CO-RE eBPF probe covering only exec + mmap-exec, as an optional alternative to requiring Tetragon. Go/no-go based on how often "we don't run Tetragon" blocks adoption. This is the single biggest scope risk in the whole roadmap, default answer stays no.

### 2.0, The control plane (the business)
Everything before this is Apache-2.0 and free forever. 2.0 adds the hosted/enterprise layer. By this point there is real usage data indicating which of these features people will pay for:
- **Fleet view**: one pane across clusters, conformance status per workload, drift timeline, attestation coverage %.
- **Policy engine**: org-wide rules ("prod namespaces require conformant attestation < 7 days old"), distributed to admission controllers.
- **Compliance packs**: mapped evidence bundles, EO 14028, EU CRA (the timing tailwind; CRA SBOM obligations are landing on every vendor selling into the EU), SOC 2 change-management evidence, FedRAMP ConMon inputs. "Export auditor-ready evidence" is the actual purchase trigger.
- **Attestation ledger**: retained, searchable history of signed runtime attestations, the compliance artifact as a service.
- Architecture: control plane is a separate closed (or BSL) repo; agents phone home over gRPC; single-tenant deploy option for the security-sensitive buyers who are, definitionally, the whole market.

**Business model note:** open-core with a hard line, anything a single team on one cluster needs is OSS; anything about *many teams, many clusters, auditors, and retention* is paid. That line is legible and defensible. License the core Apache-2.0 (CNCF-compatible, maximizes adoption and job-market value); decide at 1.0 whether the control plane warrants BSL vs. plain proprietary, no need to decide now, and don't let license anxiety slow 0.x.

---

## Risks worth writing down

- **File-level SBOM gap** (most SBOMs lack file lists), mitigated by owning the index step; this is also quietly a differentiator.
- **Interpreted languages** (python/node app code isn't "packages"), scope v1 claims to binaries + shared objects; app-code integrity is a 2.x idea (dm-verity/IMA territory), not a v1 promise.
- **Tetragon/Tracee API churn**, pin versions, adapter interface, integration tests in CI.
- **Kubescape ships portable attestations.** Worth watching their releases. The counter is vendor-neutrality, the published predicate spec, and a Sigstore-native workflow.
- **Maintainer bandwidth.** This is a solo, part-time project. The 0.x releases are deliberately sized so that any single one can slip without the project dying. If timelines compress, 0.1, 0.3, and 0.5 together (correlate, prioritize CVEs, sign the evidence) form a complete and coherent story on their own.