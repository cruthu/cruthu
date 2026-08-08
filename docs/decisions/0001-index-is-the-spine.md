# 0001 — The file-to-package index, not the SBOM, is the authority on paths

**Status:** accepted
**Date:** 2026-08-07

## Context

`cruthu` reconciles observed runtime paths against declared packages. That requires answering one question per event: *which package declares this file?*

The obvious source is the SBOM. It is the artifact the whole product is framed around, users already have one, and both CycloneDX and SPDX can express file-level detail. Building an independent index of the image looks like duplicated work.

It is not, for two reasons.

**Most SBOMs do not carry file lists.** Package-level SBOMs are the norm. A component entry records a name, a version, and a purl, not the hundreds of paths that package installed.

**Even Syft's CycloneDX output does not reliably carry them.** Syft's internal model has per-package file ownership — the dpkg cataloger reads `/var/lib/dpkg/info/*.list` and exposes it — but that ownership does not reliably survive the mapping into CycloneDX JSON. The `syft:location:N:path` properties on a component point at the *metadata* file the package was discovered in (`/var/lib/dpkg/status`), not at the files the package owns. Enabling file cataloging adds file components, but the package-to-file relationship a reconciler needs is not dependably there.

So an SBOM-only design would work on the subset of SBOMs whose author happened to generate them correctly, and silently degrade on the rest. Silent degradation in a drift detector means false criticals on every binary, which trains users to ignore it, or — after they tune it — false negatives.

## Decision

The **file-to-package index is a first-class artifact of the tool**, built by `cruthu index` from the image's own package databases (dpkg, apk, rpm), serialized with its own versioned schema (`cruthu.dev/index/v0`), and used as the sole authority for resolving an observed path to a package.

The SBOM contributes what it is actually good at: the declared package set, package identity and versions, and a digest to bind an attestation to. It is not consulted for path resolution.

## Consequences

- `cruthu check` takes both `--index` and `--sbom`. Requiring two inputs is worse ergonomics than one, and it is the honest shape of the problem. The 0.6 zero-config path can fetch both from registry attestations.
- We own dpkg, apk, and rpm database parsing. That is real work and real attack surface, and every one of those parsers gets a fuzz target.
- The tool works on images whose SBOM is package-level only, which is most of them. This is quietly a differentiator rather than only a cost.
- The index is the thing to get right. Path normalization inside it — notably merged-`/usr` symlink aliasing, where dpkg records `/usr/bin/sh` and the sensor reports `/bin/sh` — is detection logic, not formatting, and is covered by its own decision note.
- Because the index is serialized and versioned, it can be built once in a pipeline and reused, and later attestations can reference the exact index digest they were computed against.

## Alternatives rejected

**Use `anchore/syft` as a library** for both SBOM parsing and image cataloging. This would supply dpkg, apk, and rpm support and layer walking for free, and was the original sketch. Rejected because its transitive dependency tree is very large, and a tool whose entire pitch is supply-chain trust cannot casually take on a dependency surface it cannot audit. The `Builder` interface leaves the door open if hand-rolled database parsing proves more costly than expected.

**Require SBOMs generated with file cataloging enabled.** Rejected: it pushes the tool's correctness onto the SBOM author, fails on any SBOM `cruthu` did not commission, and makes the failure mode silent.
