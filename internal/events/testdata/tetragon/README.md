# Tetragon export fixtures

`sample.jsonl` is hand-written, not a real Tetragon capture. It models the
documented export shape (https://tetragon.io/docs/concepts/events/) closely
enough to exercise this package's reader end to end: a legitimate exec
through the merged-`/usr` compatibility path (`/bin/ls`, resolved by
`internal/index`'s alias table to `/usr/bin/ls`), a `process_exit` event this
reader skips, a blank line, and a planted `/tmp/ls` — the "obvious-name"
false-negative case `personal_notes/0.1-revision.md`'s success gate calls out
by name.

This gets replaced with a real recording once branch G (the demo repo) runs
a container under Tetragon for real, per
`docs/decisions/0006-event-adapter-path-contract.md`. Until then, treat any
field value here — exec IDs, PIDs, the fake image digest — as arbitrary.
