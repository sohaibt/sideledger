"""sideledger command line."""
import argparse
import json
import os
import pathlib
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time

from . import __version__, receipt, store

HOOK_SUFFIX = " -m sideledger hook"
# PostToolUseFailure matters: a deploy that exits non-zero may still have changed something.
HOOK_EVENTS = (("UserPromptSubmit", None), ("PostToolUse", "Bash"), ("PostToolUseFailure", "Bash"))


def _log_hook_error(exc):
    # The type name only: an exception message could quote the payload.
    try:
        os.makedirs(store.home(), mode=0o700, exist_ok=True)
        with open(store.home() / "hook-errors.log", "a") as log:
            log.write(time.strftime("%Y-%m-%d %H:%M") + " " + type(exc).__name__ + "\n")
    except OSError:
        pass


def cmd_hook(_args):
    """Called by Claude Code. Prints nothing and always exits 0, so it can never block or steer the agent."""
    try:
        event = json.load(sys.stdin)
        name, session = event.get("hook_event_name"), event.get("session_id") or "unknown"
        if name == "UserPromptSubmit":
            conn = store.connect()
            store.next_turn(conn, session)
            conn.close()
        elif name in ("PostToolUse", "PostToolUseFailure") and event.get("tool_name") == "Bash":
            command = (event.get("tool_input") or dict()).get("command")
            if command:
                conn = store.connect()
                cwd = os.path.realpath(event.get("cwd") or os.getcwd())
                store.record(conn, session, cwd, command, name == "PostToolUseFailure")
                conn.close()
    except Exception as exc:
        _log_hook_error(exc)
    return 0


def _load_settings(path):
    if not path.exists():
        return dict()
    settings = json.loads(path.read_text())
    if not isinstance(settings, dict) or not isinstance(settings.get("hooks", dict()), dict):
        raise ValueError("expected an object with a hooks object")
    for entries in settings.get("hooks", dict()).values():
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise ValueError("expected each hook event to hold a list of objects")
    return settings


def _is_ours(hook):
    return isinstance(hook, dict) and str(hook.get("command", "")).endswith(HOOK_SUFFIX)


def _without_ours(entries):
    kept = []
    for entry in entries:
        hooks = entry.get("hooks")
        if isinstance(hooks, list) and any(_is_ours(h) for h in hooks):
            entry = dict(entry, hooks=[h for h in hooks if not _is_ours(h)])
            if not entry["hooks"]:
                continue
        kept.append(entry)
    return kept


def cmd_install(args):
    # realpath: settings files are often symlinks into a dotfiles repo, and replacing the link would break that.
    path = pathlib.Path(os.path.realpath(args.settings))
    try:
        settings = _load_settings(path)
    except ValueError as exc:
        print("sideledger: did not change %s, it is not valid settings JSON: %s" % (args.settings, exc), file=sys.stderr)
        return 2
    # The full interpreter path, because Claude Code may not have this venv on its PATH.
    command = shlex.quote(sys.executable) + HOOK_SUFFIX
    hooks = settings.setdefault("hooks", dict())
    for event, matcher in HOOK_EVENTS:
        entry = dict(hooks=[dict(type="command", command=command)])
        if matcher:
            entry["matcher"] = matcher
        hooks[event] = _without_ours(hooks.get(event, [])) + [entry]
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".settings-")
    with os.fdopen(fd, "w") as out:
        json.dump(settings, out, indent=2)
        out.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    print("sideledger: hooks added to %s. New Claude Code sessions will be recorded." % args.settings)
    return 0


def cmd_receipt(args):
    conn = store.connect()
    session = args.session
    if session is None or session == "latest":
        session = store.latest_session(conn, _scope()) or store.latest_session(conn)
    if session is None:
        print("No commands recorded yet.")
        return 0
    # No selection at all means the latest turn. Naming a session means all of it, unless a turn is named too.
    turn = args.turn
    if args.session is None and turn is None:
        turn = store.latest_turn(conn, session)
    rows = store.actions(conn, session, turn)
    if not rows:
        print("sideledger: nothing recorded for that session or turn.", file=sys.stderr)
        return 2
    shown = {r["id"] for r in rows}
    elsewhere = sum(r["id"] not in shown for r in store.unreviewed(conn))
    print(receipt.FORMATS[args.format](receipt.build(rows, session, turn, args.all, elsewhere)))
    return 0


def _scope():
    """The repo this command runs in: only that repo's actions should stop its commits."""
    try:
        found = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if found.returncode == 0 and found.stdout.strip():
            return os.path.realpath(found.stdout.strip())
    except OSError:
        pass
    return os.path.realpath(os.getcwd())


def _short(row):
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["ts"]))
    return "  #%d %s  %s  %s" % (row["id"], when, row["categories"], row["command"])


def cmd_check(args):
    conn = store.connect()
    root = None if args.all else _scope()
    errors = store.home() / "hook-errors.log"
    if errors.exists():
        print("sideledger: warning: some commands may not have been recorded. See %s, and delete it once you have looked." % errors, file=sys.stderr)
    rows = store.unreviewed(conn, root)
    unknown = len(store.unreviewed(conn, root, "unknown"))
    if rows:
        print("sideledger: %d unreviewed irreversible action(s):" % len(rows))
        for row in rows:
            print(_short(row))
            print("      why: " + row["why"])
        print("Look at them, then run: sideledger ack")
    else:
        print("sideledger: no unreviewed irreversible actions.")
    others = len(store.unreviewed(conn)) - len(rows)
    if others:
        print("Also %d unreviewed irreversible action(s) in other folders, which do not fail this check. See: sideledger check --all" % others)
    if unknown:
        print("Also %d unknown action(s), which do not fail this check. See: sideledger receipt --session latest" % unknown)
    print(receipt.LIMITS)
    return 1 if rows else 0


def cmd_ack(args):
    # Not a security boundary (an agent could edit the database), but it stops the easy way of clearing its own warning.
    if os.environ.get("CLAUDECODE"):
        print("sideledger: refused. This is running inside an agent session, and a person should review these actions.", file=sys.stderr)
        return 1
    conn = store.connect()
    if args.id:
        if store.ack(conn, args.id) != len(args.id):
            print("sideledger: an id was not found or was already reviewed.", file=sys.stderr)
            return 2
        print("sideledger: marked %d action(s) as reviewed." % len(args.id))
        return 0
    rows = store.unreviewed(conn, None if args.all else _scope())
    if not rows:
        print("sideledger: Nothing to review.")
        return 0
    store.ack(conn, [r["id"] for r in rows])
    print("sideledger: marked %d action(s) as reviewed:" % len(rows))
    for row in rows:
        print(_short(row))
    return 0


def cmd_retention(args):
    conn = store.connect()
    if args.days is not None:
        try:
            store.set_retention_days(conn, args.days)
        except ValueError as exc:
            print("sideledger: %s" % exc, file=sys.stderr)
            return 2
    print("sideledger: history is kept for %d days. Unreviewed irreversible actions stay until reviewed." % store.retention_days(conn))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="sideledger", description="A per-turn receipt of what a coding agent changed outside the repo.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hook", help="called by Claude Code, reads a hook payload on stdin").set_defaults(run=cmd_hook)
    install = sub.add_parser("install", help="add the hooks to Claude Code settings")
    install.add_argument("--settings", default=str(pathlib.Path.home() / ".claude" / "settings.json"))
    install.set_defaults(run=cmd_install)
    show = sub.add_parser("receipt", help="print the receipt for a turn or session (default: the latest turn)")
    show.add_argument("--session", help="a session id, or latest. Without --turn, shows the whole session")
    show.add_argument("--turn", type=int)
    show.add_argument("--format", choices=sorted(receipt.FORMATS), default="text")
    show.add_argument("--all", action="store_true", help="also show local commands")
    show.set_defaults(run=cmd_receipt)
    check = sub.add_parser("check", help="exit 1 if this repo has unreviewed irreversible actions (for pre-commit)")
    check.add_argument("--all", action="store_true", help="look at every repo, not just this one")
    check.set_defaults(run=cmd_check)
    ack = sub.add_parser("ack", help="mark unreviewed irreversible actions in this repo as reviewed")
    ack.add_argument("--all", action="store_true", help="every repo, not just this one")
    ack.add_argument("--id", type=int, action="append", help="only this action (any rating). Repeatable")
    ack.set_defaults(run=cmd_ack)
    retention = sub.add_parser("retention", help="show or set how many days of history to keep")
    retention.add_argument("days", type=int, nargs="?")
    retention.set_defaults(run=cmd_retention)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except sqlite3.Error as exc:
        print("sideledger: cannot read the ledger in %s: %s" % (store.home(), exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
