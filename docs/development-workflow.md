# How cruthu is built

`cruthu` is developed with AI assistance under a review-first process. This document describes that process in full, because a security tool that will not say how it was built is asking for trust it has not earned.

The short version: AI writes most of the code; every line passes three gates before merge, and a human maintainer owns every merged line.

## Governing principles

**1. The maintainer owns every merged line.** The operating rule that makes everything else work: *never merge code you cannot explain out loud.* If a maintainer cannot narrate what a function does and why it is safe, it does not merge — they either learn it or reject it. This is the single rule that separates AI-assisted from AI-generated.

**2. The generator never grades its own homework.** The session that wrote the code never performs its security review. Fresh context, adversarial framing, a different session. A model reviewing its own output inherits its own blind spots.

**3. Small diffs or no review.** AI produces 2,000-line changes effortlessly; humans cannot review them. The working cap is roughly 300 lines of non-test diff per pull request. A task that generates more gets split before review, not after.

**4. Tests are the spec, and the human writes the spec.** The maintainer authors the test cases — at minimum the list of cases, including the hostile ones — before generation. AI implementing against a human-authored spec is constrained. AI writing both the implementation and its tests is just agreeing with itself.

**5. The higher bar is public.** `cruthu` parses untrusted input and touches signing material. Anyone evaluating it will read the code with that in mind. Documenting the process is part of the product.

## The pipeline

```
spec + test cases  →  generate  →  gate 1: machines  →  gate 2: AI adversary  →  gate 3: human  →  merge
     (human)            (AI)         (CI, blocking)        (fresh session)         (maintainer)
```

### Gate 0 — Specification (human)

Roughly 20% of the time budget for a change, spent before any code exists.

- Write the interface first: Go types, function signatures, error contracts, doc comments describing behavior.
- Write the test cases as a list, including the hostile ones — *"the parser must not panic on truncated JSON," "path resolution must reject `..` escapes," "an event with a null container ID is dropped, not crashed on."*
- State the trust boundaries for the change explicitly. What input is untrusted? For `cruthu` the default answer is all of it: SBOMs come from registries, events come over a socket, filesystems come from arbitrary images.

### Gate 0.5 — Generation (AI)

[CLAUDE.md](../CLAUDE.md) holds the house rules so that every session starts constrained rather than being reminded ad hoc. One task per session, scoped to one pull request, fed the interface and test list from Gate 0. The session runs the tests itself and iterates until green — against a definition of green it did not write.

Each session ends by drafting the pull request description: what changed, what it deliberately does not handle, new dependencies with justification, and **the line it considers riskiest**. That last question is unusually productive.

### Gate 1 — Machines (CI, blocking, zero human time)

Everything in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), mirrored locally by `make ci` so nobody waits on CI to learn something a linter already knew:

- `go vet`, `golangci-lint` (including `gosec`, `errcheck`, `bodyclose`, `noctx`, `nilerr`, `errorlint`), `staticcheck`
- `govulncheck` — known-vulnerability reachability in our own dependencies
- the race detector on the full suite
- **fuzzing as a first-class citizen:** native Go fuzz targets on every parser entry point — CycloneDX, SPDX, Tetragon JSON, Tracee JSON, the config file. A short pass (30s per target) runs on every pull request; [`fuzz-nightly.yml`](../.github/workflows/fuzz-nightly.yml) runs hours per target overnight with a cached corpus. Parsers of untrusted input are exactly where fuzzing pays.
- dependency review — fails a pull request on new dependencies with known vulnerabilities or unwanted licenses, and makes every addition visible in review
- DCO sign-off on every commit

`scripts/fuzz.sh` discovers fuzz targets by enumeration rather than from a list, so a new parser is fuzzed the moment its target is written and nobody has to remember to register it.

**Custom rules grow from incidents.** Every time gate 2 or gate 3 catches a class of bug, the question is "can a rule catch this pattern forever?" If yes, it gets written. That is how the pipeline compounds: bugs found once become bugs found automatically.

### Gate 2 — AI adversarial review (fresh session)

A new session, with no memory of writing the code, gets the diff and the fixed prompt in [`.github/REVIEW_PROMPT.md`](../.github/REVIEW_PROMPT.md). Keeping the prompt in-repo makes it versioned and improvable.

The prompt runs twice when a change touches a trust boundary: once as a general adversarial review, once role-played as an attacker who controls the event stream and is trying to hide a drift event. Different framings surface different bugs.

Findings are triaged ruthlessly. AI reviewers over-report style and under-report architecture, so this pass is mining for the one or two real items, not addressing all fifteen. A finding is real if you can write the failing test.

**The false-negative pass is specific to this project.** Most security review asks "can this be exploited?" `cruthu` has a second failure mode that is worse for the product: drift that goes unreported. Every reconciler change gets the explicit question — *construct an event that represents real drift but that this code would classify as clean.* A tool that misses the cryptominer is worse than no tool.

### Gate 3 — The human (the gate that cannot be delegated)

Maintainer review time is the scarcest resource in the project, so it is spent where machines and AI are weakest:

- **Architecture and boundaries.** Does the change respect the adapter interfaces? Did logic leak between layers? Is the trust boundary where the design says it is?
- **The explain-out-loud pass.** For anything non-obvious, narrate it. Where the narration goes vague is exactly where the bug is. Budget: 30–45 minutes for a 300-line change. If it is taking two hours, the change was too big — split it and regenerate.
- **The riskiest-line claim.** The generator named one. Verify you agree. Disagreement means one of you has misread the change; find out which.
- **Diff-only discipline.** Review the diff, not the AI's summary of the diff. Summaries are where hallucinated reassurance lives.
- Anything the reviewer had to *learn* in order to approve gets a short note in [`docs/decisions/`](decisions/).

## Cadence

- **Branch, pull request, self-review, merge — even solo.** The pull request is the unit that all gates attach to, and reviewing your own change in the GitHub UI genuinely catches things the editor does not.
- **Weekly, not per-change: the audit pass.** One session where a fresh AI reviews a whole *subsystem* against its design notes: "here is `internal/reconcile` and its spec; find divergence, dead code, and missing hostile-input tests." Diffs hide drift of intent; periodic whole-file review catches it.
- **Before 1.0: one independent human review.** An experienced Go and security person reviews the trust-boundary code — the parsers and the attestor — before the 1.0 announcement. AI review has blind spots correlated with AI generation, and one independent human on the critical fraction of the code is the cheapest de-risking available.

## When a gate catches something real

1. Fix it.
2. Add the test that would have caught it.
3. Ask whether a lint rule or a [CLAUDE.md](../CLAUDE.md) rule prevents the *class*. Add it.
4. If it is security-relevant and shipped in a release, it is a GitHub Security Advisory, handled per [SECURITY.md](../SECURITY.md) — even at 0.x. Practicing disclosure discipline before anyone is watching is how it becomes reflexive when they are.

## Why this is written down

Two reasons. The first is that a security tool built with AI assistance either explains its process or invites the assumption of the worst; transparent-and-rigorously-reviewed beats quietly hoping nobody asks. The second is that the process is load-bearing. Writing it down is what makes it survive a busy week.
