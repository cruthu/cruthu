# Contributing to cruthu

Thanks for your interest. `cruthu` is a security tool that parses untrusted input and produces signed evidence, so the contribution bar is a little higher than for a typical project. This document explains what that means in practice. None of it is meant to discourage you; it is meant to keep the trust story of the tool intact.

## The one rule everything else follows

**Do not submit code you cannot explain and defend.** If you cannot describe what your change does, why it is correct, and why it is safe against hostile input, it is not ready. This applies equally to human-written and AI-assisted contributions. Maintainers will ask questions about your change, and "I am not sure, the tool wrote it" will result in the pull request being closed.

## AI-assisted contributions

AI-assisted contributions are welcome. This project is itself built with AI assistance, and we think that is fine when paired with genuine human understanding and review. To contribute AI-assisted code:

- You must fully understand every line you submit and be able to answer questions about it.
- You must have run the code and the tests locally, not merely generated them.
- Your pull request description must state clearly what the change does, what it deliberately does not handle, and any new dependencies with justification.

Pull requests and security reports that show no evidence of human understanding, testing, or reproduction will be closed without extended discussion. We say this plainly because unverified AI-generated reports are a real and growing drain on maintainers of security projects, and protecting review time is how this project stays alive.

## Before you start

- For anything larger than a small fix, open an issue first and agree on the approach. Unsolicited large pull requests are hard to review and often cannot be merged as-is.
- Keep pull requests small. The working limit is roughly 300 lines of non-test diff. Larger changes should be split into a reviewable sequence.
- One logical change per pull request.

## Developer Certificate of Origin

All commits must be signed off. By signing off you certify that you wrote the change or otherwise have the right to submit it under the project license, per the [Developer Certificate of Origin](https://developercertificate.org/).

Add the sign-off with:

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by:` line to your commit. Commits without it will fail CI.

## Development setup

Requirements: Go 1.23 or newer, plus the tooling invoked by the pre-commit hooks.

```bash
git clone https://github.com/cruthu/cruthu
cd cruthu
make setup     # installs git hooks and dev tooling
make test      # runs the suite with the race detector
make lint      # runs the full linter and security tool set
make fuzz      # runs a short fuzz pass over the parsers
```

Please run `make lint` and `make test` before opening a pull request. The same checks run in CI and will block the merge otherwise.

## Coding standards

The house rules live in `AGENTS.md` (also mirrored as `CLAUDE.md`) so that both human and AI contributors work from the same guardrails. The essentials:

- **All external input is hostile.** SBOMs, event streams, and image filesystems are attacker-controlled. Never panic on malformed input; return an error. Every error path gets a test.
- **No new dependencies without justification.** List and justify any new dependency in the pull request description. Prefer the standard library. New dependencies receive extra scrutiny because they are our largest supply-chain exposure.
- **Path handling is a security boundary.** Clean and confine any path derived from input. Assume symlink and traversal attacks on image filesystems.
- **No hand-rolled cryptography.** Signing and verification go through the Sigstore and in-toto libraries, never bespoke code.
- **Tests are table-driven** and cover the hostile cases, not only the happy path. Parsers of untrusted input require fuzz targets.

## What review looks like

Every change passes through several gates:

1. **Automated checks** in CI: vet, linters including gosec, staticcheck, govulncheck, semgrep, secret scanning, the race detector, and a short fuzz pass on the parsers.
2. **An adversarial review pass** framed around hostile input and, for reconciler changes, the question "could this be made to miss real drift?" A false negative that hides drift is treated as more serious than a crash.
3. **Human maintainer review** focused on architecture, trust boundaries, and whether the change can be explained out loud.

Expect questions. They are not a judgment of you; they are the process working. The full workflow is documented in `docs/development-workflow.md`.

## Reporting security issues

Do not open a public issue for a vulnerability. Follow the process in [SECURITY.md](SECURITY.md). We practice coordinated disclosure even at this early stage.

## Commit and pull request style

- Conventional commit style for messages (`feat:`, `fix:`, `docs:`, and so on). This keeps the changelog clean.
- A good pull request description states the change, the non-goals, new dependencies, and the line you consider riskiest. Naming your own riskiest line genuinely speeds up review.

## License

By contributing, you agree that your contributions are licensed under the project's Apache-2.0 license.
