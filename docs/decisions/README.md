# Decision log

Short notes on choices that shaped the codebase and cannot be recovered by reading it.

Two kinds of entry belong here:

- **Architectural decisions** with consequences a later reader would otherwise have to reverse-engineer, especially ones where the obvious choice was rejected.
- **Things a maintainer had to learn in order to approve a change.** These are cheap to write down at the moment of understanding and expensive to reconstruct later.

Schema-affecting changes are always logged, because `README.md` promises they will be.

Entries are numbered, immutable once merged, and superseded rather than edited. Keep them short — a few paragraphs. If an entry needs to be long, it is probably design documentation and belongs elsewhere.

| # | Decision |
|---|---|
| [0001](0001-index-is-the-spine.md) | The file-to-package index, not the SBOM, is the authority on paths |
| [0002](0002-path-aliasing.md) | Directory-symlink aliasing is detection logic, and it ships in the index |
| [0003](0003-rootfs-confinement.md) | `os.Root`, not `os.DirFS`, is what confines a rootfs |
| [0005](0005-dpkg-declares-the-unmerged-spelling.md) | dpkg declares the unmerged spelling and the kernel reports the merged one |
