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
