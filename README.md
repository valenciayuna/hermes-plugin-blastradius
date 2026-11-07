# blastradius

Hermes asks "allow this command?" You answer yes without knowing what dies. This plugin answers the question that actually matters: how many files, and how many of them can git bring back.

```
⛔ blast radius: rm -rf src/
   84 file(s), 3.1 MB
   tracked by git : 3    (recoverable)
   UNTRACKED      : 81   (gone permanently)
   e.g. .env.local, data/app.db, migrations/0007_draft.sql
```

The blocking call is `pre_tool_call`. The command does not run until the number is on the record.

Then you decide, and the plugin gets out of the way:

- `blast_allow("rm -rf data")` permits exactly that command, once, for 5 minutes. The grant is spent on the next matching call and the gate closes again.
- `BLASTRADIUS_ALLOW=1` is the session-wide override, for when you trust everything in front of you.

## Why the split matters

`git clean -fd` deletes exactly the untracked set: the `.env`, the local database, the migration nobody committed yet. Those are the files people lose, and they are the files a risk opinion cannot count. A regex can flag `rm -rf` as dangerous. Only measuring the target can say that 81 of these 84 files are unrecoverable.

## What it measures

| Command shape | What is counted |
|---|---|
| `rm`, `rm -rf <path>` | every file under the target paths |
| `git clean -f`, `-fd`, `-fdx` | the worktree, split into tracked and untracked |
| `git reset --hard` | the worktree as it stands now |
| `truncate -s 0`, `> file` | the file being zeroed |
| `mv` onto an existing file | the file that gets overwritten |
| `mv into a directory`, plain rename | nothing, so it is not gated |

## What it does not measure

By design, so the numbers stay honest:

- commands whose damage happens inside a program (`python cleanup.py`)
- anything over SSH, or inside `bash -c "..."` quoting the parser does not unwrap
- `rm` in a subshell or after a pipe, reported as unmeasured instead of guessed
- `DROP TABLE` or `DELETE` inside SQL strings

It measures filesystem state before the command runs. It cannot be wrong about a number it counted, and it can be incomplete about a command it does not understand. The README states that trade rather than hiding it.

## Install

```bash
git clone https://github.com/valenciayuna/hermes-plugin-blastradius ~/.hermes/plugins/blastradius
hermes plugins enable blastradius
```

## Use

```
> /blast rm -rf src
```

Or ask the agent to preview a command. The `blast_radius` tool runs the same measurement without executing anything, and `blast_allow` issues the one-shot confirmation after you have seen the number.

## Related, but different

- `tools/approval_floors.py` matches command shapes and asks "may I?"
- `tools/approval_smart.py` asks an auxiliary LLM "how risky is this?"
- `plugins/security-guidance` scans the content of files being written

All three answer a different question, and none of them opens the target.

## Tests

```bash
python3 tests/blast_proof.py
hermes plugins validate .
hermes plugins doctor .
```

The proof script builds a git repo with 84 files in a folder, commits 3 of them, and asserts that a destructive command reports 3 recoverable and 81 unrecoverable.

## License

MIT
