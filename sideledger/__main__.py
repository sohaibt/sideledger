"""sideledger command line."""
import argparse
import json
import os
import pathlib
import shlex
import sys
import tempfile
import time

from . import __version__, store

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


def build_parser():
    parser = argparse.ArgumentParser(prog="sideledger", description="A per-turn receipt of what a coding agent changed outside the repo.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hook", help="called by Claude Code, reads a hook payload on stdin").set_defaults(run=cmd_hook)
    install = sub.add_parser("install", help="add the hooks to Claude Code settings")
    install.add_argument("--settings", default=str(pathlib.Path.home() / ".claude" / "settings.json"))
    install.set_defaults(run=cmd_install)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
