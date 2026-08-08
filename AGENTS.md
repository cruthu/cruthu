# AGENTS.md

This project keeps its AI and agent house rules in a single canonical file so that every agent, whichever tool a contributor uses, works from the same constraints.

**The canonical rules live in [CLAUDE.md](CLAUDE.md). Read that file.**

`AGENTS.md` and `CLAUDE.md` are intended to hold identical content. If you are maintaining this repository, keep them in sync (a symlink is the simplest way: `ln -sf CLAUDE.md AGENTS.md`). If they ever disagree, `CLAUDE.md` is authoritative.

In short: `cruthu` is a security tool that parses untrusted input and handles signing material. All external input is treated as hostile. Do not produce code a human maintainer cannot explain and defend, do not add dependencies or new input surfaces without flagging them, do not weaken tests to pass a build, and do not let the tool mutate a user's image. The full set, including the false-negative rule that is specific to this project, is in [CLAUDE.md](CLAUDE.md).
