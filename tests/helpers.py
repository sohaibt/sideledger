import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent.parent
HOOKS = pathlib.Path(__file__).parent / "fixtures" / "hooks"


def run(home, *args, stdin="", cwd=None, env=None):
    """Run the real CLI in a child process, with the ledger in a temp folder."""
    full_env = dict(os.environ, SIDELEDGER_HOME=str(home), PYTHONPATH=str(ROOT))
    full_env.pop("CLAUDECODE", None)
    full_env.update(env or dict())
    return subprocess.run([sys.executable, "-m", "sideledger", *args], input=stdin, capture_output=True,
                          text=True, cwd=cwd, env=full_env)


def fire(home, name, **overrides):
    payload = dict(json.loads((HOOKS / (name + ".json")).read_text()), **overrides)
    return run(home, "hook", stdin=json.dumps(payload))
