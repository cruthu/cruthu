# Adversarial review prompt (Gate 2)

This is the fixed prompt used for the AI adversarial review pass described in [docs/development-workflow.md](../docs/development-workflow.md). It lives in the repository so that it is versioned and improvable: when a gate catches a class of bug this prompt missed, the prompt gets edited.

**The session that wrote the code never runs this review.** A model reviewing its own output inherits its own blind spots. Use a fresh session with no memory of the change, and give it the diff.

---

## Primary pass

> You are reviewing a diff for a security tool that parses untrusted SBOMs and runtime event streams and produces signed attestations. Assume the author is competent but rushed, and assume an attacker controls all external input. Do not summarize the code or praise it. Produce only findings, ranked, in this order of priority:
>
> 1. **Input handling:** panics, unbounded allocation from attacker-controlled sizes, path traversal, symlink following, injection into exec/SQL/log lines.
> 2. **Logic:** TOCTOU between check and use, error paths that fail open, incorrect drift classification that would cause a false *negative*.
> 3. **Concurrency:** races, deadlocks, goroutine leaks in the watch path.
> 4. **Crypto and attestation:** key handling, signature verification order, digest confusion (verify-then-parse vs. parse-then-verify).
> 5. **Everything else:** resource cleanup, context propagation, misleading names.
>
> For each finding: `file:line`, the attack or failure scenario in one sentence, and a concrete fix. End with the three questions you would ask the author.

## Second pass: the false-negative framing

Run this whenever the change touches the reconciler, the index, path matching, or an event adapter. It is the pass that matters most for this project, because unreported drift is a worse product failure than a crash.

> You control the event stream and the container filesystem. Your goal is to run a binary that is not in the SBOM without this code reporting it. Read the diff and construct the specific event, path, or filesystem layout that this code would classify as clean. Consider at minimum:
>
> - path aliasing and symlinks (`/bin/sh` vs. `/usr/bin/sh` on merged-`/usr` images), trailing slashes, doubled separators, `.` and `..` components, and non-UTF-8 or NUL-containing paths
> - case sensitivity, Unicode normalization, and homoglyph paths
> - events that are dropped rather than reported: missing container ID, unparseable timestamp, unknown event type, malformed line in the middle of a stream
> - suppression and allowlist entries that are broader than the noise they were added for
> - ordering assumptions: an event arriving before the index is built, or out of timestamp order
> - resource exhaustion that causes the tool to give up early and still exit 0
>
> Produce the concrete evasion, not a general concern. If you cannot construct one, state precisely which property of the code prevents each attempt.

## Triage

AI reviewers over-report style and under-report architecture. The goal is to mine for the one or two real items, not to address all fifteen. A finding is real if you can write the failing test.

When a finding is real:

1. Fix it.
2. Add the test that would have caught it.
3. Ask whether a lint rule or a rule in [CLAUDE.md](../CLAUDE.md) prevents the whole class. If yes, add it.
4. If it is security-relevant and already shipped in a release, it is a GitHub Security Advisory, handled per [SECURITY.md](../SECURITY.md) — even at 0.x with a handful of users. Practicing disclosure discipline before anyone is watching is how it becomes reflexive when they are.
