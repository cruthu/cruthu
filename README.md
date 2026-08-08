# cruthu

**Verify that what's running in your container is what the SBOM says was built, and produce signed, portable evidence of it.**

> **cruthú** (KRUH-hoo): Irish for *proof*; also *to create, to form*. The tool that proves what you created is what's running. The canonical spelling everywhere in this project (domain, module path, binary) is the plain-ASCII `cruthu`, without the fada.

An SBOM is a contract written at build time. Runtime is reality. `cruthu` reconciles the two: it reads a container's build-time SBOM, watches which binaries and libraries the container actually loads and executes, and reports the difference. From that single data stream it produces three things:

- **Drift detection.** Binaries or shared libraries that run but were never declared in the SBOM. This catches injected payloads, dropped cryptominers, and interactive `apt install` sessions in production.
- **In-use analysis.** Which declared packages actually loaded, so you can prioritize the CVEs that matter. Most vulnerabilities in a typical image sit in code that never executes.
- **Runtime attestation.** A cosign-signed, in-toto statement asserting that an image ran for a given window with zero drift. Supply-chain provenance extended past deploy into production.

## Why another container security tool

Because the baseline here is a signed build artifact, not a learned statistical model. "A binary executed that isn't in the SBOM" is a fact, not an anomaly score. That means no training period, no false-positive tuning treadmill, and an explanation you can hand to an auditor.

Existing "in-use" analysis lives locked inside vendor platforms. `cruthu` is the vendor-neutral, SBOM-standard-native version whose output is a portable signed artifact. The evidence is the product, not the dashboard.

## What cruthu is not

- **Not an eBPF agent (yet).** v1 consumes events from existing sensors (Tetragon, Tracee) rather than maintaining its own kernel probes. An optional native sensor is under evaluation for a later release, not a v1 promise.
- **Not an anomaly detector.** Matching is deterministic against a declared manifest. No machine learning, no baseline learning mode.
- **Not an image mutator.** The debloat feature emits recommendations (a report, an apko package list). It never strips your image, so it can never break your image.
- **Not an enforcement agent (in the OSS core).** It reports and exits nonzero for CI gating. Fleet-wide policy and enforcement belong to the future control plane.

## Status

Early development. Interfaces and output schemas are unstable until 1.0. Do not build production compliance workflows on the JSON or attestation schemas before they are frozen. Watch the releases and the `docs/decisions/` log for schema-affecting changes.

## Quick start

> Requires Go 1.23+ and a recorded event export from Tetragon or Tracee. See `examples/demo/` for a fully reproducible walkthrough that runs a container, injects a fake malicious binary, and shows `cruthu` catching it.

```bash
# Build the file-to-package index for an image
cruthu index ghcr.io/example/app:1.4.0 --output app.index.json

# Reconcile a recorded event stream against the SBOM
cruthu check \
  --sbom app.sbom.json \
  --index app.index.json \
  --events tetragon-export.json \
  --fail-on critical
```

Exit codes: `0` clean, `1` drift at or above the threshold, `2` tool error.

## Command overview

| Command | Purpose | Status |
|---|---|---|
| `cruthu index` | Build a file-to-package index from an image and its SBOM | available |
| `cruthu check` | Offline reconcile of an event log against an SBOM | available |
| `cruthu watch` | Live reconcile from a Tetragon or Tracee stream | planned 0.2 |
| `cruthu cve` | Prioritize scanner findings by in-use packages | planned 0.3 |
| `cruthu slim` | Emit a debloat recommendation (report or apko YAML) | planned 0.4 |
| `cruthu attest` | Produce a signed runtime-conformance attestation | planned 0.5 |
| `cruthu verify` | Verify an existing runtime attestation on an image | planned 0.5 |

See [ROADMAP.md](ROADMAP.md) for the full 0.1 to 2.0 plan.

## Install

```bash
go install cruthu.dev/core/cmd/cruthu@latest
```

The module path is served from `cruthu.dev`, independent of where the source is hosted, so imports stay stable even if the repository moves.

## Supported inputs

- **SBOM formats:** CycloneDX JSON, SPDX JSON (the formats Syft emits).
- **Event sources:** Tetragon (export file and live stream), Tracee (JSON). New sources plug in through a stable adapter interface.
- **Image package databases:** dpkg, apk, rpm, for building the file-to-package index directly when the SBOM lacks file-level detail.

## How this project is built

`cruthu` is developed with AI assistance under a documented, review-first process. Every change is specified and reviewed by a human before merge, passes automated security tooling and continuous fuzzing of all untrusted-input parsers, and undergoes an independent adversarial review pass. The governing rule is simple: no line merges that a human maintainer cannot explain and defend. See [CONTRIBUTING.md](CONTRIBUTING.md) and `docs/development-workflow.md` for the details.

We hold a security tool to a higher bar and document how we meet it, rather than hoping nobody asks.

## Security

`cruthu` parses untrusted input (SBOMs from registries, event streams from sockets, filesystems from arbitrary images) and handles signing material. Please report vulnerabilities through the process in [SECURITY.md](SECURITY.md), not through public issues. Automated or unverified vulnerability reports that show no evidence of human analysis or reproduction will be closed without extended discussion.

## License

Apache-2.0. The open-source core is, and will remain, Apache-2.0. A future hosted control plane (fleet management, org-wide policy, compliance evidence packs, attestation retention) will be a separate commercial offering; nothing a single team needs on a single cluster will move behind that line.

## The name

*cruthú* is Irish for **proof**, and also means *to create* or *to form*. Both senses fit: the tool is concerned with the provenance of what you built and with the evidence it emits about it. Pronounced roughly **KRUH-hoo** (the Irish *th* is an h-sound, not a hard t). Written `cruthu` without the fada wherever it needs to be typed.

## Acknowledgements

Built on the shoulders of Syft, Tetragon, Tracee, Sigstore/cosign, in-toto, and the OCI ecosystem.
