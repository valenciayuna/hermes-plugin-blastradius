# Audit

Two questions: is the impact measurement correct, and does Hermes actually consult the hook.

```
tests/blast_proof.py        80/80   the shipped suite
tests/audit_parser.py       16/16   adversarial command shapes
tests/audit_snapshot.py     12/12   snapshot, restore, policy, one-shot allow
tests/audit_integration.py   7/7    Hermes dispatcher and register()
hermes plugins validate .   passed
```

## Bugs the audit found and fixed

1. **A crash for targets outside the git repository.** `measure()` computed a path relative to the
   repository root using a `rel` value that had been computed against a different root, so analysing
   `rm -rf /tmp/x` from inside a repo raised `ValueError: ... is not in the subpath of ...`. This runs
   inside `pre_tool_call`, where an exception costs the whole report. Fixed with a `_display()` helper
   that falls back to the absolute path, and there is now a check for a target outside the repo.
2. **Globs were never expanded, so the report said zero files.** `rm -rf src/*.py` on a directory with
   two Python files reported `files=0`, which reads as a harmless command. The shell expands that glob
   before `rm` ever runs, so the report has to as well. Fixed with `glob.glob(..., recursive=True)`
   before walking; the same command now reports 2 files, 1 tracked and 1 untracked.

Both bugs point the same way: an understated impact report. That is the direction that gets someone
to approve a command they should not.

## What the parser audit covers

Quoted paths containing spaces, tracked versus untracked split, nested `bash -c` two levels deep,
subshells with `cd`, `cd` chains with relative targets, `$(...)` reported as unmeasured, `ssh`,
`eval` and `xargs` payloads reported as unmeasured, globs, symlinks (the link is counted, the target's
contents are not), and five benign commands that must never be flagged.

## What the snapshot audit covers

The tree is measured, snapshotted, deleted with `rmtree`, and restored. Restore reports
`restored=5 verified=5` and every file's sha256 matches the pre-delete value. A tampered stored blob
makes the restore refuse instead of writing wrong bytes. Policy: `strict` blocks an unmeasurable
destructive command, `balanced` reports it without blocking, non-terminal tools are ignored, a benign
command passes under `strict`, and a one-shot allow is spent exactly once (`first=None`,
`second=block`).

## What is not covered

- **Windows and macOS.** Only Linux was exercised.
- **Shell features the parser does not model.** Process substitution (`<(cmd)`), here-docs that build
  paths, and aliases inside interactive shells. These should be reported as unmeasured; the audit
  checks the three opaque forms it knows (`ssh`, `eval`, `xargs`) but not every possible one.
- **Concurrent modification.** A file created between measurement and snapshot is not in the
  snapshot. The window is small and the manifest records what it saved, but it is not atomic.
- **Snapshots above the retention limits.** Pruning is unit-tested through `prune()`, not through a
  long-running install with hundreds of snapshots.
