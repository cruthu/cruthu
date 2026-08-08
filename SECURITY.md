# Security Policy

`cruthu` is a security tool. It parses untrusted input (SBOMs pulled from registries, event streams read from sockets, filesystems from arbitrary container images) and it handles signing material. We hold it to a higher standard than a typical project and we practice coordinated disclosure from the earliest releases, before anyone is watching, so that the habit is reflexive when they are.

## Supported versions

During the 0.x series, only the most recent minor release receives security fixes. Once 1.0 ships, this section will list the specific versions under support. Because schemas and interfaces are unstable before 1.0, the safest posture is to track the latest release.

| Version | Supported |
|---|---|
| latest 0.x | yes |
| older 0.x | no |

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Public disclosure before a fix is available puts every user at risk.

Report privately through GitHub's Security Advisory process:

1. Go to the Security tab of this repository.
2. Choose "Report a vulnerability" to open a private advisory.
3. Include the information below.

If you cannot use GitHub Security Advisories, contact the maintainer through the address listed on the maintainer's GitHub profile and clearly mark the message as a security report.

### What to include

A good report lets us reproduce the issue without a back-and-forth. Please provide:

- The version, commit, or release you tested.
- The affected component (for example: the CycloneDX parser, the SPDX parser, the event ingester, the attestor).
- The input that triggers the issue. A minimal SBOM, event log, or image reference that reproduces it is worth more than a description.
- What you observed (panic, crash, incorrect result, missed drift) and what you expected.
- Any assessment of impact you have. If you are not sure of the impact, report it anyway.

### A note on false-negative reports

For most tools, a security report is "this can be made to crash or be exploited." `cruthu` has a second failure mode that is often more serious: **drift that goes unreported.** If you can construct an event stream that represents real drift (an executed binary or loaded library absent from the SBOM) that `cruthu` classifies as clean, that is a security-relevant finding and we want to hear about it through the same private channel.

## What to expect

- We aim to acknowledge a report within a few days. This is currently a small project, so please allow for that.
- We will confirm the issue, determine affected versions, and agree on a disclosure timeline with you.
- When a fix is released, we will publish a GitHub Security Advisory crediting you, unless you prefer to remain anonymous.
- We add a regression test for every fixed vulnerability, and where the root cause is a class of bug rather than a single instance, we add a lint or static-analysis rule so the class cannot recur silently.

## Automated and AI-generated reports

Unverified, automated, or AI-generated vulnerability reports that show no evidence of human analysis or reproduction will be closed without extended discussion. A report that cannot demonstrate the issue against a real version is not actionable, and triaging a flood of speculative reports takes time away from fixing real ones. Human-authored, reproducible reports, including AI-assisted ones where the author understands and has verified the finding, are always welcome.

## Scope

In scope: the `cruthu` codebase and its released artifacts.

Out of scope: vulnerabilities in upstream dependencies (Syft, Tetragon, Tracee, Sigstore, and others) should be reported to those projects directly, though we appreciate a heads-up if one affects `cruthu` users. Issues that require an already-fully-compromised host, or that describe general properties of SBOMs or container runtimes rather than a defect in `cruthu`, are also out of scope.
