# sideledger

A local CLI that gives you a per-turn receipt of what your coding agent changed **outside the repo**: deploys, pushes, database writes and cloud changes.

A clean Git diff can hide a dropped table. File rollback does not undo a deploy. sideledger records each Bash command your agent runs in Claude Code, rates whether it can be undone, and warns you before you commit.

```
sideledger receipt: session sess-1, turn 1

IRREVERSIBLE (2)
  #2 2026-11-03 02:24  deploy  fly deploy --access-token [REDACTED]
      why: Live to users once it runs. A rollback restores the code, not what happened while it was live.
  #3 2026-11-03 02:24  cloud  terraform apply -auto-approve
      why: Changes real infrastructure and can replace stateful resources. Reapplying old config does not bring data back.
      note: failed, may have partly run

1 local command hidden (--all shows them).

Limits: sideledger reads command text only. A side effect hidden inside a script is rated unknown at best, and nothing here proves a command did only what its text says.
```

## Install

```sh
pip install sideledger
sideledger install
```

Python 3.10 or newer, no dependencies. `sideledger install` adds three hooks to `~/.claude/settings.json` and keeps everything else in that file. Use `--settings PATH` for another file. New Claude Code sessions are then recorded.

| Hook | Why |
| --- | --- |
| `PostToolUse` (Bash) | Records each command. |
| `PostToolUseFailure` (Bash) | A deploy that exits non-zero may still have changed something. |
| `UserPromptSubmit` | Marks where a new turn starts. The prompt text is not stored. |

To remove them, delete the entries ending in `-m sideledger hook` from that file.

## Usage

```sh
sideledger receipt                          # the latest turn
sideledger receipt --turn 3                 # one turn of the latest session
sideledger receipt --session latest         # a whole session (or pass a session id)
sideledger receipt --all                    # include local commands
sideledger receipt --format json            # or sarif

sideledger check                            # exit 1 if this repo has unreviewed irreversible actions
sideledger ack                              # mark them reviewed
sideledger ack --id 12                      # mark one action, of any rating
sideledger retention 30                     # keep 30 days of history (default 90)
```

To warn before each commit:

```sh
printf '#!/bin/sh\nexec sideledger check\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

`check` and `ack` look only at actions recorded in the current repo. Add `--all` for every repo. `ack` refuses to run inside a Claude Code session, because a person should do the reviewing. That stops the easy route, but it is not a security boundary: an agent that wants to can edit the database or commit with `--no-verify`.

## Ratings

The ruleset is public: [`sideledger/rules.json`](sideledger/rules.json). Rules run in order and the first match wins. When a command has several parts, the worst rating is kept.

| Rating | Meaning |
| --- | --- |
| `reversible` | A normal follow-up undoes it, or it only reads. |
| `unknown` | The command text does not say. Scripts, unnamed tools and unclear targets land here. |
| `irreversible` | Data is destroyed or something is public, and a rollback will not fully undo it. |

Categories: `git-push`, `deploy`, `database`, `cloud`, `package-publish`, `network`, `local`. Ratings cover effects outside the repo. Changes inside it are for your Git diff to show.

## What is stored

A SQLite file at `~/.sideledger/ledger.db`, readable only by you. Set `SIDELEDGER_HOME` to move it. Nothing leaves your machine.

Stored: the redacted command, its rating, destinations, session, turn, folder and time. Never stored: prompts, tool output, and request bodies, heredoc bodies or SQL values in the command. Secrets are removed by pattern, so an unusual secret format can get through. Old history is deleted after the retention period, except unreviewed irreversible actions, which stay until reviewed.

## Limits

- **It reads command text only.** A deploy inside `./ship.sh` shows as `unknown`. It does not watch the network or block anything.
- **Coverage gap in 0.1.0.** The ruleset has no named rules yet for several of the most common hosted deploy and cloud CLIs, or for the main npm, PyPI, crates and Docker publish commands. These show on receipts as `local / unknown` ("not in the ruleset") and do **not** fail `check`. See [`backlog.md`](backlog.md).
- **Claude Code only** for now.

## How it is different

Audit tools such as Gryph and hooklens log what the agent did. Checkpoint tools such as Reviu and Turnal restore or explain repo state. sideledger answers a narrower question: what did this turn change outside the repo, and can it be undone? It complements those tools. (Based on their public descriptions.)

## Development

```sh
python3 -m unittest discover -s tests -t .
```

The tests include labelled command and secret sets that measure detection, false alarms and secret leakage.

## License

MIT
