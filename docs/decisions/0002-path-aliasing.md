# 0002 — Directory-symlink aliasing is detection logic, and it ships in the index

**Status:** accepted
**Date:** 2026-08-08

## Context

On merged-`/usr` images — current Debian, Ubuntu, and Alpine — `/bin`, `/sbin`, `/lib`, and `/lib64` are symlinks into `/usr`. The package database and the runtime sensor disagree about how to spell the same file:

- dpkg's `/var/lib/dpkg/info/dash.list` records `/usr/bin/sh`.
- Tetragon reports the exec as `/bin/sh`.

Compared as strings, those do not match. The immediate consequence is that **every binary on such an image reports as unowned**, which is a CRITICAL finding per executable and makes the tool useless on its most common target.

The consequence that matters more is the second one. Once a user tunes that noise away — by suppressing `/bin`, or by lowering the severity of unowned execs — the tool stops reporting the thing it exists to report. Noise on day one and a false negative on day thirty are the same bug.

## Decision

Normalization through a directory-symlink alias map is part of matching, not part of formatting.

**Both sides are normalized through the same function.** `NewLookup` normalizes every declared path at construction and `Owner` normalizes the observed path on every query. Normalizing one side only is the specific defect this design exists to prevent, and it has its own test (`TestLookupNormalizesDeclaredPaths`).

**The alias map is discovered at index time and serialized into the index.** `cruthu check` runs from the index file alone, often on a different machine and long after the filesystem is gone, and it still has to normalize what the sensor reports. Aliases are therefore part of `cruthu.dev/index/v0` from its first commit rather than something the checker recomputes.

**Targets are read, not traversed.** `BuildAliases` requires `fs.ReadLinkFS` and resolves each target itself. `os.Root` deliberately refuses to follow absolute symlinks, but `/bin -> /usr/bin` written absolutely is still a real alias that must be recorded; reading the link and resolving it against the container root captures both the relative and the absolute spelling. See [0003](0003-rootfs-confinement.md).

**Matching is component-aware.** An alias for `/bin` rewrites `/bin/sh` and `/bin` itself, never `/binary`. Longest `From` wins, so `/usr/bin` beats `/usr` deterministically rather than in map order.

## The false-negative question

*Construct an event that represents real drift but that this code would classify as clean.*

There is one, and it is worth stating rather than hiding.

Aliases are derived from the image's own filesystem. An attacker who can add a symlink **to the image at build time** can influence normalization — for example shipping `/opt/app -> /usr/bin`, after which an exec of `/opt/app/ls` normalizes onto the real, package-owned `/usr/bin/ls` and is classified clean.

Three things bound it, and none of them is "this cannot happen":

1. It requires compromising the image build, which is a different and earlier threat than the runtime drift this tool detects. An attacker with that access has better options than an alias trick.
2. The alias is recorded in the index, and the index is serialized, diffable, and eventually attested. The evasion is written down in the artifact rather than being invisible.
3. Only symlinks resolving to real directories inside the root become aliases; targets outside the root, dangling targets, and targets that are files are dropped.

What this design does **not** defend against, and does not claim to: an attacker who overwrites a package-owned path in place — dropping a malicious binary at `/usr/bin/ls` itself. v0 matches paths, not content. Content integrity needs per-file digests in the index and is out of scope until the index carries them.

## Consequences

- Every change to `Normalize`, `NewAliases`, or `BuildAliases` gets the false-negative question above, per `CLAUDE.md`.
- The alias count is bounded (`maxAliases`), as is the scan (`maxWalkEntries`) and chain resolution (`maxAliasHops`). A cyclic alias set terminates rather than spinning.
- An unreadable subtree during the scan is skipped rather than fatal. That is safe in one direction only, and the direction is the safe one: a *missing* alias can only stop an observed path from matching, which over-reports. It cannot hide drift.

---

## Amendment — path semantics are a contract, not a formatting detail

**Date:** 2026-08-08
**Changes:** the meaning of an unrooted observed path, and the handling of an alias set with no fixed point.

Two things this ADR left implicit turned out to be decisions, and both were decided wrong.

### An unrooted path is un-normalizable

`cleanAbs` prepended `/` to any path lacking one, which made `Owner("bin/sh")` and `Owner("/bin/sh")` the same query. That is a false negative with a short recipe: an attacker in a writable working directory creates `./bin/sh` and execs it by relative path. The sensor reports the binary as `bin/sh`, `cleanAbs` anchors it to `/bin/sh`, this ADR's alias table sends that to `/usr/bin/sh`, and a planted binary resolves to dash and is classified **clean**. It needs no control over the image and no symlink — only a writable directory.

The anchoring was never a decision about paths. It was a guess at a missing working directory, made in the one place that cannot know it. `Owner` now returns unowned for an unrooted path.

**This moves a requirement onto the event adapters, and it is the reason the decision could not wait.** An adapter must produce rooted paths: resolving an observed relative path against the cwd the event carries, and dropping the event as unparseable when the event carries none. Dropping is the fail-closed choice and it is also a blind spot — an event that cannot be placed is an event that cannot be checked — so adapters must count what they drop rather than discarding it silently.

### A set with no fixed point is refused, not clamped

`Normalize` bounded chain resolution at `maxAliasHops` and returned whatever it had rewritten so far. The original consequence note claimed a bounded result "is still consistent between them", on the reasoning that both sides pass through the same function.

That reasoning is wrong, and the error is worth recording because it is the kind that reads as correct. The two sides do use the same function, but they do not enter the chain at the same point. A declared `/a0/x` and an observed `/a3/x` on a nine-link chain are the same file; after eight hops each they are `/a8/x` and `/a9/x` — different strings, no match. Measured on the code before this change: `Normalize("/a0/x")` is `/a8/x` while `Normalize("/a8/x")` is `/a9/x`, so the function was not even idempotent.

`NewAliases` now walks the graph once and refuses a cycle or an over-long chain, so a pathological set fails at load with `ExitError` instead of being clamped per query. `Normalize` returns the un-normalizable `""` if it somehow still hits the bound, because a path with no fixed point has no comparable spelling and must be owned by nothing. `FuzzNormalize` pins idempotence and fails on the previous implementation.

### The false-negative question, for this amendment

*Construct an event that represents real drift but that this code would classify as clean.*

Not from this change. It only removes matches: unrooted paths stop resolving to anything, and a non-converging alias set stops producing a comparison at all. Removing a match can turn a legitimate file into a reported finding, never the reverse. The new failure mode is over-reporting — an adapter that emits relative paths makes every such event unowned and noisy — which is visible on day one rather than silent forever.

The blind spot this creates is real and belongs to the adapters, named above: an event with no cwd is dropped, and a dropped event is not checked. That is a gap in coverage rather than a path that resolves to the wrong answer, and it is why the drop must be counted and reported.

---

## Amendment — alias discovery is scoped to the root

**Date:** 2026-08-08
**Changes:** which symlinks become aliases, and what an unreadable root means.

### 95% of the table was noise, and noise in this table is not harmless

Measured on the images this has to work on:

| Image | Total symlinks | Directory symlinks | Merged-`/usr` aliases |
|---|---|---|---|
| `debian:bookworm` | 643 | 26 | 4 (`/bin`, `/lib`, `/lib64`, `/sbin`) |
| `python:3.12-bookworm` | 2,646 | 88 | 4 |

The 84 extra entries in the larger image are `/usr/share/doc/libssl3 -> libssl-dev` (37), `/usr/share/zoneinfo/posix/America -> ../America` (16), and `/usr/share/bug/*` (12). None is a path alias in the merged-`/usr` sense this ADR exists for.

They are not merely useless. Every entry in this table is a global path rewrite applied to every observed path, which makes it a drift-suppression primitive; the amendment above records what one well-chosen entry can hide. A mechanism that mints one of those for any symlink dropped anywhere in an image is too generous by construction. Discovery now records a directory symlink only when it sits directly in the root, which captures all four real aliases in both images and drops all 84.

It also cuts `Normalize`'s per-path linear scan by roughly 20×, and that scan runs once per declared file at load and once per event at check time.

### The lexical/physical resolution differential

A relative target was resolved with `path.Join(path.Dir(name), target)`, which collapses `..` lexically. The kernel resolves it physically. Where a component of the link's own directory is itself a symlink, the two disagree: with `/a -> /usr` and `/a/b -> ../lib`, this code recorded `/a/b -> /lib` while the kernel resolves `/a/b` to `/usr/lib`. `fs.Stat` confirmed only that the lexical answer was a real directory, not that it was the answer the kernel would give.

That is a path-resolution differential in detection logic, which is the class this project treats most seriously. Scoping to the root closes it outright rather than papering over it: at the root `path.Dir(name)` is always `"."`, so there are no intermediate components to disagree about. This is the second reason for the scoping rule and would justify it alone.

### An unreadable root is fatal

The original consequence note said an unreadable subtree is skipped rather than fatal, and that this is safe because a missing alias can only over-report. That holds for a subtree. It did not hold for the root, and the code did not distinguish them: `fs.WalkDir` reports a failure to stat the root by calling back with a nil `DirEntry`, the `d != nil && d.IsDir()` guard fell through to `return nil`, and the scan returned success with an empty alias set.

An empty alias set is indistinguishable from an image that genuinely has no directory symlinks — the exact confusion this ADR's `fs.ReadLinkFS` requirement exists to prevent, reached by another route. On a merged-`/usr` image it means every binary reports as unowned, and the first thing a user does with that much noise is suppress it. Opening the root now fails the scan.

### The false-negative question, for this amendment

*Construct an event that represents real drift but that this code would classify as clean.*

Not from the scoping change: it only removes aliases, and removing an alias removes a rewrite, so a path that used to normalize onto an owned path now fails to match and is reported. The change moves entries out of a suppression table, which is the safe direction by definition.

The one that remains is the one already named at the top of this ADR — an attacker who controls the image build ships `/opt` as a symlink into `/usr/bin`. Scoping does not fix that, because a root-level symlink is exactly what such an attacker would create. What bounds it now is that the deserialized table is validated against the canonical merged-`/usr` shape, so an index carrying `/opt -> /usr/bin` is refused at load whatever the filesystem said. Discovery being generous and validation being strict is a disagreement worth naming: `BuildAliases` can still record a root-level alias that `LoadVerified` will later refuse, and the index writer is where that should be caught.
