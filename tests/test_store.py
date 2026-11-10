import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from sideledger import store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, dict(SIDELEDGER_HOME=self.tmp.name + "/home"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.conn = store.connect()
        self.addCleanup(self.conn.close)

    def test_files_are_private(self):
        home = pathlib.Path(self.tmp.name) / "home"
        self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((home / "ledger.db").stat().st_mode), 0o600)

    def test_record_stores_rating_and_redacted_text_only(self):
        store.record(self.conn, "s1", "/repo", "psql postgres://u:pw123456@db.example.com/app -c 'DROP TABLE t'", False)
        row = store.actions(self.conn, "s1")[0]
        self.assertEqual((row["categories"], row["rating"], row["rule"]), ("database", "irreversible", "sql-destructive"))
        self.assertEqual(row["destinations"], "postgres://db.example.com")
        self.assertNotIn("pw123456", row["command"])
        raw = (pathlib.Path(self.tmp.name) / "home" / "ledger.db").read_bytes()
        self.assertNotIn(b"pw123456", raw)

    def test_cwd_is_stored_as_claude_code_sends_it(self):
        # Live 2026-11-10: `cd .. && true` run from repo/bin arrived with cwd=repo (the folder after it ran).
        repo = self.tmp.name + "/repo"
        os.makedirs(repo + "/bin")
        store.record(self.conn, "s1", repo, "cd .. && rm -rf build", False)
        self.assertEqual(store.actions(self.conn, "s1")[0]["cwd"], repo)

    def test_classifies_before_redacting(self):
        # The heredoc body is not stored, but it still counts towards the rating.
        store.record(self.conn, "s1", "/repo", "psql <<SQL\nDROP TABLE t;\nSQL", False)
        row = store.actions(self.conn, "s1")[0]
        self.assertEqual(row["rating"], "irreversible")
        self.assertNotIn("DROP", row["command"])

    def test_turns_count_per_session(self):
        store.record(self.conn, "s1", "/r", "ls", False)
        self.assertEqual(store.actions(self.conn, "s1")[0]["turn"], 1)
        store.next_turn(self.conn, "s1")
        store.record(self.conn, "s1", "/r", "pwd", False)
        store.next_turn(self.conn, "s2")
        store.record(self.conn, "s2", "/r", "date", False)
        self.assertEqual([r["turn"] for r in store.actions(self.conn, "s1")], [1, 2])
        self.assertEqual([r["command"] for r in store.actions(self.conn, "s1", 2)], ["pwd"])
        self.assertEqual(store.actions(self.conn, "s2")[0]["turn"], 1)
        self.assertEqual(store.latest_session(self.conn), "s2")
        self.assertEqual(store.latest_turn(self.conn, "s1"), 2)

    def test_retention_default_and_setting(self):
        self.assertEqual(store.retention_days(self.conn), 90)
        store.set_retention_days(self.conn, 7)
        self.assertEqual(store.retention_days(self.conn), 7)
        with self.assertRaises(ValueError):
            store.set_retention_days(self.conn, 0)

    def test_old_rows_go_but_unreviewed_irreversible_stays(self):
        store.set_retention_days(self.conn, 7)
        old = 1000
        store.record(self.conn, "s1", "/r", "ls", False, now=old)
        store.record(self.conn, "s1", "/r", "git push -f", False, now=old)
        store.record(self.conn, "s1", "/r", "git push --force origin x", False, now=old)
        reviewed = store.actions(self.conn, "s1")[2]["id"]
        store.ack(self.conn, [reviewed], now=old)
        store.record(self.conn, "s1", "/r", "pwd", False, now=old + 8 * 86400)
        self.assertEqual([r["command"] for r in store.actions(self.conn, "s1")], ["git push -f", "pwd"])

    def test_unreviewed_is_scoped_to_a_tree(self):
        store.record(self.conn, "s1", "/work/repo/sub", "git push -f", False)
        store.record(self.conn, "s1", "/work/repo-other", "git push -f", False)
        store.record(self.conn, "s1", "/work/repo", "git push", False)
        self.assertEqual([r["cwd"] for r in store.unreviewed(self.conn, "/work/repo")], ["/work/repo/sub"])
        self.assertEqual(len(store.unreviewed(self.conn)), 2)

    def test_ack_clears_unreviewed_and_reports_count(self):
        store.record(self.conn, "s1", "/r", "git push -f", False)
        ids = [r["id"] for r in store.unreviewed(self.conn)]
        self.assertEqual(store.ack(self.conn, ids), 1)
        self.assertEqual(store.unreviewed(self.conn), [])
        self.assertEqual(store.ack(self.conn, ids), 0)


if __name__ == "__main__":
    unittest.main()
