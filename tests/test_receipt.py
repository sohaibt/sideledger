import json
import pathlib
import tempfile
import unittest

from tests.helpers import fire, run


class ReceiptTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = pathlib.Path(tmp.name) / "home"

    def seed(self):
        fire(self.home, "prompt")
        fire(self.home, "bash_local")
        fire(self.home, "prompt")
        fire(self.home, "bash_local")
        fire(self.home, "bash_deploy")
        fire(self.home, "bash_failed")

    def test_empty_ledger(self):
        result = run(self.home, "receipt")
        self.assertEqual(result.returncode, 0)
        self.assertIn("No commands recorded", result.stdout)

    def test_default_is_the_latest_turn_as_text(self):
        self.seed()
        out = run(self.home, "receipt").stdout
        self.assertIn("turn 2", out)
        self.assertIn("IRREVERSIBLE (2)", out)
        self.assertIn("fly deploy --access-token [REDACTED]", out)
        self.assertIn("deploy", out)
        self.assertIn("1 local command hidden", out)
        self.assertNotIn("TOKENCANARY", out)

    def test_every_format_states_the_command_text_limit(self):
        self.seed()
        self.assertIn("reads command text only", run(self.home, "receipt").stdout)
        self.assertIn("reads command text only", run(self.home, "receipt", "--format", "json").stdout)
        self.assertIn("reads command text only", run(self.home, "receipt", "--format", "sarif").stdout)

    def test_failed_commands_are_marked(self):
        self.seed()
        self.assertIn("failed, may have partly run", run(self.home, "receipt").stdout)

    def test_turn_and_session_selection(self):
        self.seed()
        turn1 = json.loads(run(self.home, "receipt", "--turn", "1", "--format", "json").stdout)
        self.assertEqual((turn1["turn"], turn1["total"], turn1["actions"]), (1, 1, []))
        session = json.loads(run(self.home, "receipt", "--session", "sess-1", "--format", "json").stdout)
        self.assertEqual((session["turn"], session["total"]), (None, 4))
        latest = json.loads(run(self.home, "receipt", "--session", "latest", "--format", "json").stdout)
        self.assertEqual(latest["total"], 4)

    def test_all_shows_local_commands(self):
        self.seed()
        data = json.loads(run(self.home, "receipt", "--all", "--format", "json").stdout)
        self.assertEqual([a["command"] for a in data["actions"]][0], "pytest -q")
        self.assertEqual(data["local_hidden"], 0)

    def test_unknown_selection_is_an_error(self):
        self.seed()
        self.assertEqual(run(self.home, "receipt", "--session", "nope").returncode, 2)
        self.assertEqual(run(self.home, "receipt", "--turn", "99").returncode, 2)

    def test_clean_turn_says_so_with_the_limit(self):
        fire(self.home, "bash_local")
        out = run(self.home, "receipt").stdout
        self.assertIn("Nothing outside the repo", out)
        self.assertIn("reads command text only", out)

    def test_sarif_shape(self):
        self.seed()
        doc = json.loads(run(self.home, "receipt", "--format", "sarif").stdout)
        self.assertEqual(doc["version"], "2.1.0")
        sarif_run = doc["runs"][0]
        self.assertEqual(sarif_run["tool"]["driver"]["name"], "sideledger")
        rule_ids = [r["id"] for r in sarif_run["tool"]["driver"]["rules"]]
        self.assertEqual(sorted(rule_ids), ["deploy-live", "iac-apply"])
        for result in sarif_run["results"]:
            self.assertEqual(result["level"], "error")
            self.assertIn(result["ruleId"], rule_ids)
            self.assertEqual(sarif_run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"], result["ruleId"])
            self.assertEqual(result["properties"]["rating"], "irreversible")

    def test_sarif_marks_reviewed_as_suppressed(self):
        self.seed()
        run(self.home, "ack", "--all")
        doc = json.loads(run(self.home, "receipt", "--format", "sarif").stdout)
        self.assertEqual(doc["runs"][0]["results"][0]["suppressions"], [dict(kind="external")])


if __name__ == "__main__":
    unittest.main()
