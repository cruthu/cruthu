# CLAUDE.md

House rules for AI agents and human contributors working on `cruthu`. This is the canonical file; `AGENTS.md` is a symlink to it so that every tool reads the same constraints.

`cruthu` is a security tool. It parses untrusted input (SBOMs pulled from registries, event streams read off sockets, filesystems from arbitrary images) and it handles signing material. Anyone evaluating this project will read the code with exactly that in mind. These rules exist so they like what they find.

---

## The rule everything else follows

**Do not produce code a human maintainer cannot explain and defend.** If a change cannot be narrated out loud — what it does, why it is correct, why it is safe against hostile input — it does not merge. This applies identically to human-written and AI-generated code.

## The false-negative rule (specific to this project)

Most security review asks "can this be exploited?" `cruthu` has a second failure mode that is worse for the product: **drift that goes unreported.** A tool that misses the cryptominer is worse than no tool, because it converts an unknown into a false assurance.

So, for any change to the reconciler, the index, the path-matching logic, or the event adapters, answer this explicitly before proposing it:

> Construct an event that represents real drift but that this code would classify as clean.

If you cannot construct one, say why not. If you can, that is a bug in the change, not a corner case. **A false negative that hides drift is treated as more serious than a crash.**

Corollaries:
- Never widen a suppression list, an allowlist, or a "known noise" default without a test proving the specific noise is suppressed and a comment justifying it. Every entry is a hole in the detector.
- Error paths must fail closed. A parse failure, an unreadable index, or a truncated event stream is `ExitError` (2), never `ExitClean` (0). A pipeline must never read "the tool broke" as "the image is clean."
- Path normalization is detection logic, not string formatting. Any change to how paths are compared can silently create evasion, so it gets the question above.

## Input handling

**All external input is hostile.** SBOMs, event streams, image filesystems, and config files are attacker-controlled by default.

- **Never panic on malformed input.** Return an error. Panics are for programmer invariants, never for data.
- **Bound every allocation derived from input.** No `make([]T, n)` where `n` came from a file. Cap line lengths, element counts, and decompressed sizes with named constants, and test the caps.
- **Path handling is a security boundary.** Use `filepath.Clean` plus explicit confinement checks on any path derived from input. Prefer `fs.FS` over path strings, and open an untrusted filesystem with `os.OpenRoot` + `Root.FS()` — **not** `os.DirFS`, which follows a symlink out of its own tree exactly as `os.Open` would (see `docs/decisions/0003-rootfs-confinement.md`). `fs.ValidPath` rejects `..`, absolute paths, and empty elements, but it only checks the name being requested; it says nothing about what the filesystem contains. Assume symlink and traversal attacks on image filesystems.
- **Verify before you parse** where signatures are involved, not after.
- Decompression is a trust boundary too: assume zip bombs in image layers.

## Dependencies

**No new dependency without justification in the pull request description.** Dependencies are the largest supply-chain exposure in a project whose entire pitch is supply-chain trust, and they are the thing AI-assisted changes add most casually.

- Standard library first. Reach outside it only when the alternative is hand-rolling something genuinely risky.
- The deliberate choice on record (see `docs/decisions/`): minimal, auditable dependencies over convenience. `anchore/syft` was rejected as a library because its transitive tree is too large to defend, even though it would have saved real work.
- **No hand-rolled cryptography, ever.** Signing and verification go through the Sigstore and in-toto libraries.
- If a change adds a dependency, say so prominently and name what it replaces.

## Testing

- **Tests are table-driven**, and the cases come from the spec before the implementation exists.
- **Every error path gets a test.** Not the happy path plus one; every branch that returns an error.
- **Every parser of untrusted input gets a fuzz target.** `scripts/fuzz.sh` discovers targets automatically, so a new `FuzzXxx` is picked up by CI as soon as it is written.
- Hostile cases are the point: truncation, no trailing newline, NUL bytes, duplicate records, absurd sizes, `..` escapes, symlinks pointing out of the root, empty files.
- **Never weaken a test to make a build pass.** If a test fails, either the code is wrong or the test encodes the wrong contract; decide which, out loud, and fix that.

## Scope

- **Never mutate a user's image.** The debloat feature emits recommendations — a report, an apko package list. It never strips anything, so it can never break anything.
- **The OSS core reports; it does not enforce.** It exits nonzero for CI gating. Fleet-wide policy belongs to the future control plane.
- Output schemas are versioned from their first commit (`cruthu.dev/index/v0`, `cruthu.dev/report/v0`). Changing one is a schema change and needs a note in `docs/decisions/`.

## Changes and pull requests

- **Small diffs.** Roughly 300 lines of non-test diff per pull request. If a task generates more, split it before review, not after. AI can produce a 2,000-line change effortlessly; nobody can review one.
- One logical change per branch.
- Conventional commit messages (`feat:`, `fix:`, `docs:`), signed off with `git commit -s` — CI blocks merges without the DCO line.
- **The generator never grades its own homework.** The session that wrote a change does not perform its security review. Gate 2 is a fresh session with `.github/REVIEW_PROMPT.md`.
- End every change by drafting a pull request description stating: what changed, what it deliberately does **not** handle, new dependencies with justification, and **the line you consider riskiest**. That last one is not a formality; a maintainer checks whether they agree, and a disagreement means one of you has misread the change.

## Style

- American English spelling everywhere — comments, docs, commit messages. `misspell` enforces it in Go files and nothing enforces it in Markdown, so watch for it there.
- Exported identifiers carry doc comments explaining behavior and error contracts, not restating the signature.
- Comments explain *why*, especially why something is safe. A comment that says what the next line already says is noise; a comment recording an attack it defends against is worth its space.

## Workflow

`make lint && make test` must be green before a commit. The full pipeline is in `docs/development-workflow.md`; `CONTRIBUTING.md` covers the same ground for outside contributors.

When a gate catches something real: fix it, add the test that would have caught it, then ask whether a lint rule or a rule in this file prevents the whole *class*. If yes, add it. That is how the pipeline compounds.
