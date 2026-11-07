# blastradius — measure before you delete

Hermes asks *"allow this command?"* and you answer yes without knowing what dies. This plugin
answers the question that actually matters: **how many files, and how many of them can git
restore?**

```
⛔ blast radius: rm -rf src/
   84 file(s), 3.1 MB
   tracked by git : 3    (recoverable)
   UNTRACKED      : 81   (gone permanently)
   e.g. .env.local, data/app.db, migrations/0007_draft.sql
```

The blocking call is `pre_tool_call`. The command does not run until the number is on the
record. `BLASTRADIUS_ALLOW=1` lets it through for operators who have decided.

## Why the split matters

`git clean -fd` deletes exactly the untracked set — the `.env`, the local database, the
migration nobody committed yet. Those are the files people lose, and they are the files a
risk *opinion* cannot count. A regex can flag `rm -rf` as dangerous; only measuring the
target can say "81 of these 84 are unrecoverable".

## What it measures

| Command shape | What is counted |
|---|---|
| `rm`, `rm -rf <path>` | every file under the target paths |
| `git clean -f` / `-fd` / `-fdx` | the worktree, split into tracked vs untracked |
| `git reset --hard` | the worktree as it stands now |
| `truncate -s 0` / `> file` | the file being zeroed |
| `mv` onto an existing path | the destination being overwritten |

## What it does NOT measure (by design)

- commands whose damage happens inside a program (`python cleanup.py`)
- anything over SSH, or inside `bash -c "…"` quoting the parser does not unwrap
- `rm` in a subshell or after a pipe — reported as unmeasured, never guessed
- `DROP TABLE` / `DELETE` inside SQL strings

It measures filesystem state before the command runs. It cannot be wrong about a number it
counted; it can be incomplete about a command it does not understand. That trade is
documented rather than hidden — a plugin claiming full coverage would be lying.

## Install

```bash
git clone <this repo> ~/.hermes/plugins/blastradius
hermes plugins enable blastradius
```

## Use

```
> /blast rm -rf src
```
or ask the agent to preview a command; the `blast_radius` tool runs the same measurement
without executing anything.

## Not a replacement for

- `tools/approval_floors.py` — regex approval floors (asks *may I?*)
- `tools/approval_smart.py` — auxiliary-LLM risk opinion (guesses *how risky?*)
- `plugins/security-guidance` — scans written file *content* for dangerous patterns

All three answer a different question. None of them opens the target.

## Tests

```bash
python3 tests/blast_proof.py     # 16 checks: builds a repo, measures it, asserts the split
hermes plugins validate .
hermes plugins doctor .
```

## License

MIT
