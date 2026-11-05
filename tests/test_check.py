import os
import pathlib
import subprocess
import tempfile
import unittest

from tests.helpers import fire, run


class CheckTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(os.path.realpath(tmp.name))
        self.home = self.tmp / "home"
        self.repo = self.tmp / "repo"
        self.other = self.tmp / "repo-other"
        for folder in (self.repo / "sub", self.other):
            folder.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "init", "-q", str(self.other)], check=True)

    def deploy_in(self, folder):
        fire(self.home, "bash_deploy", cwd=str(folder))

    def test_clean_passes(self):
        result = run(self.home, "check", cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unreviewed_irreversible_fails_and_is_listed(self):
        self.deploy_in(self.repo / "sub")
        result = run(self.home, "check", cwd=self.repo)
        self.assertEqual(result.returncode, 1)
        self.assertIn("fly deploy", result.stdout)
        self.assertIn("sideledger ack", result.stdout)

    def test_other_repos_do_not_fail_this_one(self):
        self.deploy_in(self.other)
        self.assertEqual(run(self.home, "check", cwd=self.repo).returncode, 0)
        self.assertEqual(run(self.home, "check", "--all", cwd=self.repo).returncode, 1)

    def test_other_folders_are_mentioned_but_do_not_fail(self):
        self.deploy_in(self.other)
        result = run(self.home, "check", cwd=self.repo)
        self.assertEqual(result.returncode, 0)
        self.assertIn("1 unreviewed irreversible action(s) in other folders", result.stdout)

    def test_a_cd_from_the_parent_folder_counts_for_the_repo(self):
        fire(self.home, "bash_local", cwd=str(self.tmp), tool_input=dict(command="cd repo && terraform apply"))
        self.assertEqual(run(self.home, "check", cwd=self.repo).returncode, 1)

    def test_an_absolute_rm_inside_the_repo_does_not_block_commits(self):
        fire(self.home, "bash_local", cwd=str(self.repo), tool_input=dict(command="rm -rf %s/build" % self.repo))
        self.assertEqual(run(self.home, "check", cwd=self.repo).returncode, 0)

    def test_runs_from_a_subfolder_of_the_repo(self):
        self.deploy_in(self.repo)
        self.assertEqual(run(self.home, "check", cwd=self.repo / "sub").returncode, 1)

    def test_outside_git_uses_the_current_folder(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        self.deploy_in(plain)
        self.assertEqual(run(self.home, "check", cwd=plain).returncode, 1)

    def test_unknown_and_reversible_do_not_fail_but_unknown_is_mentioned(self):
        fire(self.home, "bash_local", cwd=str(self.repo), tool_input=dict(command="./run.sh"))
        fire(self.home, "bash_local", cwd=str(self.repo), tool_input=dict(command="git push origin feat"))
        result = run(self.home, "check", cwd=self.repo)
        self.assertEqual(result.returncode, 0)
        self.assertIn("1 unknown", result.stdout)

    def test_ack_clears_this_repo_only(self):
        self.deploy_in(self.repo)
        self.deploy_in(self.other)
        result = run(self.home, "ack", cwd=self.repo)
        self.assertEqual(result.returncode, 0)
        self.assertIn("fly deploy", result.stdout)
        self.assertEqual(run(self.home, "check", cwd=self.repo).returncode, 0)
        self.assertEqual(run(self.home, "check", cwd=self.other).returncode, 1)

    def test_ack_by_id(self):
        self.deploy_in(self.repo)
        self.assertEqual(run(self.home, "ack", "--id", "1", cwd=self.other).returncode, 0)
        self.assertEqual(run(self.home, "check", cwd=self.repo).returncode, 0)

    def test_ack_with_an_unknown_id_is_an_error(self):
        self.assertEqual(run(self.home, "ack", "--id", "99", cwd=self.repo).returncode, 2)

    def test_ack_with_nothing_to_do(self):
        result = run(self.home, "ack", cwd=self.repo)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Nothing", result.stdout)

    def test_an_agent_cannot_ack_its_own_actions(self):
        self.deploy_in(self.repo)
        result = run(self.home, "ack", cwd=self.repo, env=dict(CLAUDECODE="1"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(run(self.home, "check", cwd=self.repo).returncode, 1)

    def test_hook_errors_are_reported_so_a_pass_is_not_trusted_blindly(self):
        run(self.home, "hook", stdin="not json")
        result = run(self.home, "check", cwd=self.repo)
        self.assertEqual(result.returncode, 0)
        self.assertIn("hook-errors.log", result.stderr)

    def test_a_broken_ledger_fails_loudly(self):
        self.home.mkdir()
        (self.home / "ledger.db").write_text("this is not a database, not even close to one")
        result = run(self.home, "check", cwd=self.repo)
        self.assertEqual(result.returncode, 2)
        self.assertIn("ledger", result.stderr)

    def test_retention_command(self):
        self.assertIn("90", run(self.home, "retention").stdout)
        self.assertEqual(run(self.home, "retention", "30").returncode, 0)
        self.assertIn("30", run(self.home, "retention").stdout)
        self.assertEqual(run(self.home, "retention", "0").returncode, 2)


if __name__ == "__main__":
    unittest.main()
