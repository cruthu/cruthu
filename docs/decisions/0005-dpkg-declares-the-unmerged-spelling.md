# 0005 — dpkg declares the unmerged spelling and the kernel reports the merged one

**Status:** accepted
**Date:** 2026-08-13
**Amends:** [0002](0002-path-aliasing.md), whose worked example has the two sides the wrong way round.

## Context

ADR 0002 established that directory-symlink aliasing is detection logic, and it is right about that. Its worked example is backwards, and the error is worth recording because every reader of that ADR will otherwise reason about normalization in the wrong direction.

0002 says:

> - dpkg's `/var/lib/dpkg/info/dash.list` records `/usr/bin/sh`.
> - Tetragon reports the exec as `/bin/sh`.

Measured on `debian:bookworm`, both halves are inverted.

**dpkg declares the unmerged spelling.** `dash.list` records `/bin/dash` and `/bin/sh`; `coreutils.list` records `/bin/ls`. Across all 88 installed packages, 8,029 declared paths break down as 7,340 under `/usr` and 398 under the four aliased roots — 83 under `/bin`, 239 under `/lib`, 74 under `/sbin`, 2 under `/lib64`. Debian's merged-`/usr` transition moved the *files* into `/usr` and left the *package manifests* naming the compatibility symlink path, so roughly 5% of declared paths are in the aliased spelling.

**The kernel reports the merged spelling.** A sensor does not see the path the user typed; it sees the path the kernel resolved. Running `readlink /proc/self/exe` inside `debian:bookworm` prints `/usr/bin/readlink`, and `readlink -f /bin/ls` prints `/usr/bin/ls`. Tetragon derives its `binary` field from the exec'd file, after symlink resolution, so an exec spelled `/bin/sh` on the command line arrives as `/usr/bin/dash`.

So the sides are: **the declared side needs rewriting, and the observed side already arrives normalized.**

## Decision

No code changes. The mechanism 0002 specifies — normalize both sides through the same alias table, `/bin` → `/usr/bin` — is correct and direction-agnostic, which is exactly why the inverted example survived review without breaking anything. `NewLookup` normalizes declared paths at construction and `Owner` normalizes observed paths per query; the 398 declared `/bin/...` paths are rewritten to `/usr/...` and meet the sensor's spelling there.

What changes is the reasoning recorded for the next person, and one consequence that follows from it:

**The declared side is load-bearing, not the observed side.** Anyone tempted to "simplify" by normalizing only the incoming event — a natural reading of 0002's example, where the sensor is the side with the odd spelling — would break ownership for 398 paths on `debian:bookworm` while every test built from the ADR's example kept passing. `TestLookupNormalizesDeclaredPaths` is the test that catches that, and it is the more important of the two normalization tests rather than a symmetric twin.

**Both spellings must resolve.** The tool accepts an index built from one image and events from a sensor that may or may not resolve symlinks, and 0.2 adds a second sensor. Aliasing to a single fixed point means `/bin/ls` and `/usr/bin/ls` are the same query regardless of which side each arrives from, so cruthu does not depend on Tetragon's resolution behavior staying what it is today.

## The false-negative question

*Construct an event that represents real drift but that this measurement would classify as clean.*

The measurement itself classifies nothing; it corrects a comment. But it does sharpen one case that 0002 states abstractly.

Because ~5% of declared paths are in the `/bin`, `/lib`, `/sbin`, `/lib64` spelling, the alias table is not a convenience on a Debian image — it is load-bearing for 398 real files, including `sh`, `ls`, and every shared object under `/lib`. An alias table that fails to load, loads empty, or is scoped so narrowly that it misses one of the four entries does not fail loudly. It reports those 398 paths as unowned, which surfaces as a burst of CRITICAL findings on exactly the binaries a user expects to be legitimate — and the user's fix is to suppress them. That is the noise-on-day-one, false-negative-on-day-thirty path 0002 opens with, reached without an attacker doing anything.

This is why `BuildAliases` treats an unreadable root as fatal rather than returning an empty set, and why an empty alias table on a merged-`/usr` image is a bug and not a quiet no-op. Verified end to end during this measurement: with the alias table present, `/usr/bin/ls` resolves to `coreutils` and `/tmp/ls` does not; with the rootfs symlinks absent so the table comes back empty, `/usr/bin/ls` — the spelling a sensor actually reports — resolves to nothing at all.

## Measurements

Reproduced with `docker export` of each image and the extracted rootfs handed to `index.OpenRootfs`.

| | `debian:bookworm` | `python:3.12-bookworm` |
|---|---|---|
| Installed packages | 88 | 429 |
| Declared paths (excluding root markers) | 7,941 | 29,377 |
| `/.` root markers | 88 | 429 |
| Bare `/` declared | 0 | 0 |
| Directory symlinks at the root | 4 | 4 |
| Alias table built | `/bin`, `/lib`, `/lib64`, `/sbin` → `/usr/...` | identical |
| Longest declared path | 81 bytes | 129 bytes |

The four-entry alias table on both images is the success gate `personal_notes/0.1-revision.md` adds, and the depth ≤ 1 scoping in [0002](0002-path-aliasing.md)'s implementation is what produces exactly four rather than 26 and 88.
