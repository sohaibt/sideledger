import json
import os
import pathlib
import shlex
import stat
import sys
import tempfile
import unittest

from sideledger import store
from tests.helpers import fire, run


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.home = self.tmp / "home"

    def rows(self, session="sess-1"):
        os.environ["SIDELEDGER_HOME"] = str(self.home)
        self.addCleanup(os.environ.pop, "SIDELEDGER_HOME", None)
        conn = store.connect()
        self.addCleanup(conn.close)
        return store.actions(conn, session)


class HookTest(Base):
    def test_records_a_bash_command_silently(self):
        result = fire(self.home, "bash_deploy")
        self.assertEqual((result.returncode, result.stdout), (0, ""))
        row = self.rows()[0]
        self.assertEqual((row["categories"], row["rating"], row["turn"], row["failed"]), ("deploy", "irreversible", 1, 0))
        self.assertTrue(row["cwd"].endswith("/work/app"))

    def test_nothing_but_the_redacted_command_reaches_disk(self):
        for name in ("prompt", "bash_deploy", "bash_failed"):
            fire(self.home, name)
        raw = (self.home / "ledger.db").read_bytes()
        for canary in (b"PROMPTCANARY", b"TOKENCANARY", b"DESCCANARY", b"RESPONSECANARY", b"ERRORCANARY"):
            self.assertNotIn(canary, raw)

    def test_failed_commands_are_recorded_and_flagged(self):
        fire(self.home, "bash_failed")
        row = self.rows()[0]
        self.assertEqual((row["rating"], row["failed"]), ("irreversible", 1))

    def test_prompts_start_a_new_turn(self):
        fire(self.home, "prompt")
        fire(self.home, "bash_local")
        fire(self.home, "prompt")
        fire(self.home, "bash_deploy")
        self.assertEqual([r["turn"] for r in self.rows()], [1, 2])

    def test_sessions_are_kept_apart(self):
        fire(self.home, "bash_local")
        fire(self.home, "bash_local", session_id="sess-2")
        self.assertEqual(len(self.rows("sess-1")), 1)
        self.assertEqual(len(self.rows("sess-2")), 1)

    def test_other_tools_are_ignored(self):
        fire(self.home, "read_tool")
        self.assertEqual(self.rows(), [])

    def test_bad_input_never_blocks_the_agent_and_leaves_a_trace(self):
        result = run(self.home, "hook", stdin="not json SECRETCANARY")
        self.assertEqual((result.returncode, result.stdout), (0, ""))
        log = (self.home / "hook-errors.log").read_text()
        self.assertIn("JSONDecodeError", log)
        self.assertNotIn("SECRETCANARY", log)

    def test_payload_of_the_wrong_shape_does_not_crash(self):
        result = run(self.home, "hook", stdin="[1, 2]")
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.home / "hook-errors.log").exists())


class InstallTest(Base):
    def settings(self):
        return self.tmp / "settings.json"

    def test_adds_every_hook_to_a_new_file(self):
        result = run(self.home, "install", "--settings", str(self.settings()))
        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = json.loads(self.settings().read_text())["hooks"]
        expected = shlex.quote(sys.executable) + " -m sideledger hook"
        self.assertEqual(hooks["PostToolUse"][0]["matcher"], "Bash")
        self.assertEqual(hooks["PostToolUseFailure"][0]["matcher"], "Bash")
        self.assertNotIn("matcher", hooks["UserPromptSubmit"][0])
        for event in ("PostToolUse", "PostToolUseFailure", "UserPromptSubmit"):
            self.assertEqual(hooks[event][0]["hooks"], [dict(type="command", command=expected)])

    def test_keeps_existing_settings_and_other_hooks(self):
        other = dict(matcher="Bash", hooks=[dict(type="command", command="other-tool")])
        self.settings().write_text(json.dumps(dict(model="x", hooks=dict(PostToolUse=[other]))))
        run(self.home, "install", "--settings", str(self.settings()))
        data = json.loads(self.settings().read_text())
        self.assertEqual(data["model"], "x")
        self.assertEqual(data["hooks"]["PostToolUse"][0], other)
        self.assertEqual(len(data["hooks"]["PostToolUse"]), 2)

    def test_running_twice_does_not_duplicate_and_replaces_an_old_path(self):
        old = dict(matcher="Bash", hooks=[dict(type="command", command="/old/python -m sideledger hook")])
        self.settings().write_text(json.dumps(dict(hooks=dict(PostToolUse=[old]))))
        run(self.home, "install", "--settings", str(self.settings()))
        run(self.home, "install", "--settings", str(self.settings()))
        entries = json.loads(self.settings().read_text())["hooks"]["PostToolUse"]
        self.assertEqual(len(entries), 1)
        self.assertNotIn("/old/python", entries[0]["hooks"][0]["command"])

    def test_refuses_a_broken_settings_file_and_leaves_it_alone(self):
        for broken in ("not json", "[1]", json.dumps(dict(hooks=[1])), json.dumps(dict(hooks=dict(PostToolUse=7)))):
            self.settings().write_text(broken)
            result = run(self.home, "install", "--settings", str(self.settings()))
            self.assertNotEqual(result.returncode, 0, broken)
            self.assertEqual(self.settings().read_text(), broken)

    def test_uninstall_removes_only_our_hooks(self):
        other = dict(matcher="Bash", hooks=[dict(type="command", command="other-tool")])
        self.settings().write_text(json.dumps(dict(model="x", hooks=dict(PostToolUse=[other]))))
        run(self.home, "install", "--settings", str(self.settings()))
        result = run(self.home, "uninstall", "--settings", str(self.settings()))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.settings().read_text())
        self.assertEqual(data, dict(model="x", hooks=dict(PostToolUse=[other])))

    def test_writes_through_a_symlink_and_keeps_the_mode(self):
        real = self.tmp / "dotfiles.json"
        real.write_text("{}")
        real.chmod(0o640)
        self.settings().symlink_to(real)
        run(self.home, "install", "--settings", str(self.settings()))
        self.assertTrue(self.settings().is_symlink())
        self.assertIn("hooks", json.loads(real.read_text()))
        self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
