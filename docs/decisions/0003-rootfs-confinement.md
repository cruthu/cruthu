# 0003 — `os.Root`, not `os.DirFS`, is what confines a rootfs

**Status:** accepted
**Date:** 2026-08-08

## Context

`cruthu index` reads a container filesystem that arrives as an extracted directory today and as unpacked image layers later. It is attacker-controlled: anyone who can get an image into a registry can decide what symlinks it contains.

The project's house rules already said to prefer `fs.FS` over path strings, and gave a reason that was **wrong**:

> `fs.ValidPath` rejects `..`, absolute paths, and empty elements, and `os.DirFS` does not escape its root.

The first half is true. The second is not, and `os.DirFS`'s own documentation says so:

> Note that `DirFS("/prefix")` only guarantees that the `Open` calls it makes to the operating system will begin with `"/prefix"`: `DirFS("/prefix").Open("file")` is the same as `os.Open("/prefix/file")`. So if `/prefix/file` is a symbolic link pointing outside the `/prefix` tree, then using `DirFS` does not stop the access any more than using `os.Open` does. […] Use `Root.FS` to obtain a `fs.FS` that prevents escapes from the tree via symbolic links.

`fs.ValidPath` checks the *name being asked for*. It says nothing about what the filesystem contains. An image carrying `etc/passwd -> ../../../../etc/passwd` passes every name check, because the traversal is in the filesystem, not in the request.

This mattered concretely: the first plan for `internal/index` specified `os.DirFS`, on the strength of the incorrect rule.

## Decision

`index.OpenRootfs` opens the directory with `os.OpenRoot` and returns `Root.FS()`. Nothing in the index package accepts a path string, and nothing calls `os.DirFS`.

`os.Root` refuses to traverse any symlink that leaves the root and refuses absolute symlinks entirely, so a hostile link is an error at open time rather than a silent read of a host file. `Root.FS()` also implements `fs.ReadLinkFS`, which alias discovery needs — see [0002](0002-path-aliasing.md).

The corresponding sentence in `CLAUDE.md` is corrected in the same change. A wrong rule in the house-rules file is worse than no rule: it is the thing every future contributor and every AI session reads first, and this one actively recommended the unsafe call.

## Consequences

- **This requires Go 1.24+** for `os.Root` and 1.25+ for `fs.ReadLinkFS`. The module moved to Go 1.26 in its own change immediately before this one, for exactly this reason.
- Two tests pin the property rather than the mechanism: a symlink to a file outside the root, and a `../../../etc` traversal. Both must fail to resolve. If `OpenRootfs` is ever rewritten, those tests fail rather than quietly passing.
- `os.Root` does not protect against every filesystem hazard, and the doc is explicit about what it leaves alone: bind mounts, `/proc` special files, and Unix device files. For an extracted image directory none of those apply; if `cruthu` ever indexes a live mounted filesystem, that assumption needs revisiting.
- `Root` holds an open file descriptor, so `OpenRootfs` returns a close function and every caller is responsible for it.
