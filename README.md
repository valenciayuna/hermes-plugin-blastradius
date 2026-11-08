# Blast Radius 2.0

**Know what breaks before your agent does — and keep a way back.**

A Hermes Agent plugin that measures a destructive command's real target, copies it into a
checksummed snapshot before it runs, and restores it afterwards when something goes wrong.

```bash
hermes plugins install https://github.com/valenciayuna/hermes-plugin-blastradius
hermes plugins enable blastradius
```

---

## Why it exists

Hermes already asks "allow this command?" and can ask a model "is this dangerous?". Neither
answers the useful question: **what dies if I say yes?** A risk opinion is formed from the
command text; it never opens the target.

Blast Radius opens it. It expands the paths, walks them, and splits the result into files git
can restore and files it cannot. `git clean -fd`, an uncommitted `.env`, a local database: all
untracked, all invisible to a guess about the command string.

2.0 adds the missing half: a real way back.

---

## What it does

### 1. Impact report

```
BLASTRADIUS // IMPACT REPORT

Command: "rm -rf ."

Impact:
  43 file(s) affected
  7 tracked by git
  36 untracked (2 ignored)
  29.4 KB affected

Potentially valuable data:
  ".env"
  "data/app.db"
  "migrations/0007_draft.sql"

Recovery:
  Git-tracked files may be recoverable from the repository.
  Untracked files are not recoverable from Git.

Risk level: HIGH
```

It reports what it measured, flags the file kinds that hurt to lose (`.env*`, databases, dumps,
keys, migrations), and says **"not recoverable from Git"** rather than "gone forever" — because
another recovery source may exist.

### 2. Verified snapshots

Before the command runs, every affected regular file is copied outside the target tree with a
SHA-256 per file, then re-read to confirm the copy matches the original.

```
snapshot id : blast-20261108-112604-6f3b
files copied: 43
verified    : True
```

- stored under `~/.hermes/plugin-data/blastradius/snapshots/<id>/` (0700 dirs, 0600 files)
- symlinks are recorded but **not followed**, so a link cannot pull unrelated data in
- the snapshot directory is outside the target, so the destructive command cannot eat it
- free space is checked before copying; a failed snapshot is reported as failed

### 3. Restore with conflict detection

```
/blast restore last            # plan only: what changes, what conflicts
/blast restore last confirm    # apply, then verify checksums
```

Restoring refuses to proceed from a snapshot that fails its own verification, and a file that
changed after the snapshot is reported as a conflict rather than silently overwritten.
Every restore is appended to `recovery.log`.

### 4. Risk policies

| Policy | Behaviour |
|---|---|
| `relaxed` | report the impact, block only high-impact changes (10+ untracked, 3+ valuable, 50 MB+) |
| `balanced` *(default)* | block when untracked data would not be recoverable from git |
| `strict` | block every measured destructive call until a verified snapshot exists; `blast_allow` creates one automatically and withholds the grant if it fails |

```
/blast policy            # show
/blast policy strict     # set
BLASTRADIUS_POLICY=relaxed hermes ...   # per-session override
```

---

## Tools and commands

| Interface | What it does |
|---|---|
| `blast_radius(command, cwd?)` | measure impact without running anything |
| `blast_snapshot(command, cwd?)` | back up the targets and verify the copies |
| `blast_snapshots()` | list snapshots with size and verification status |
| `blast_restore(snapshot_id?, confirm?)` | plan or apply a restore |
| `blast_allow(command, ttl_s?)` | permit exactly one future execution (spent on use) |
| `blast_policy(policy?)` | read or set the risk policy |
| `/blast <command>` | shorthand for the impact report |
| `/blast snapshot <command>` · `/blast snapshots` · `/blast restore [id] [confirm]` · `/blast policy [name]` | same actions from chat |

`BLASTRADIUS_ALLOW=1` remains the operator's blanket override for a session.

---

## Measured vs unknown

These shapes are reported as **unmeasured** instead of guessed:

- `bash -c "..."`, other `-c` strings, and `( ... )` subshells
- anything over `ssh`
- command substitution (`$(...)`, backticks) that builds the path at runtime
- destructive work inside a program (`python cleanup.py`)
- SQL hidden in a shell string

Under `strict`, a command that looks destructive but cannot be measured is blocked for explicit
authorisation. Under the other policies it passes through untouched, because blocking what we
cannot see would be a guess too.

---

## Install and verify

```bash
git clone https://github.com/valenciayuna/hermes-plugin-blastradius
cd hermes-plugin-blastradius

python3 tests/blast_proof.py     # 49 checks, isolated temp repos
python3 demo/demo.py             # full protect -> destroy -> restore transcript
hermes plugins validate .
hermes plugins doctor .
```

The proof suite builds a real git repository with 84 generated files, tracked and untracked data,
a `.env`, a SQLite file and a draft migration, then exercises measurement, the gate, one-shot
authorisation, snapshots, restore, conflicts, corrupted snapshots, all three policies, and
expiry. Nothing destructive ever touches the project directory itself.

---

## Honest limitations

- **Heuristic parsing.** Impact is inferred from the command string. Anything the parser cannot
  see is reported as unmeasured, never estimated.
- **No universal undo.** Restore covers regular files that were in a snapshot. It does not cover
  database state, remote operations, blockchain transactions, or external services.
- **Race window.** The filesystem can change between analysis and execution. Metadata is
  recorded during analysis and re-checked on restore, but there is no lock; a file created
  between snapshot and delete is simply not protected.
- **Hard links and special files** are counted but not archived.
- **Snapshots cost disk.** A large target means a large copy; free space is checked first, and
  a snapshot that cannot complete blocks the command under `strict`.

---

## Layout

```
__init__.py       measurement, snapshots, restore, policies, hook, tools, command
tests/blast_proof.py   49 assertions, stdlib only
demo/demo.py     end-to-end demo transcript, real deletes and real restores
plugin.yaml      manifest (name, version, provided tools/hooks)
```

MIT.
