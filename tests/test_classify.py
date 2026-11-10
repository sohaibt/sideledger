import json
import os
import pathlib
import re
import tempfile
import time
import unittest

from sideledger.classify import CATEGORIES, RATINGS, _relative_to_repo, classify, destinations_of
from sideledger.redact import redact
from tests.command_cases import BENIGN, SIDE_EFFECTS


class LabelledSet(unittest.TestCase):
    def test_detection(self):
        wrong = []
        for command, category, rating in SIDE_EFFECTS:
            got = classify(command)
            if category not in got["categories"] or got["rating"] != rating:
                wrong.append((command, category, rating, got["categories"], got["rating"], got["rule"]))
        print("\ndetection: %d/%d" % (len(SIDE_EFFECTS) - len(wrong), len(SIDE_EFFECTS)))
        self.assertEqual(wrong, [])

    def test_false_alarms(self):
        wrong = []
        for command in BENIGN:
            got = classify(command)
            if got["categories"] != ["local"] or got["rating"] != "reversible":
                wrong.append((command, got["categories"], got["rating"], got["rule"]))
        print("\nfalse alarms: %d/%d" % (len(wrong), len(BENIGN)))
        self.assertEqual(wrong, [])

    def test_set_is_not_trivial(self):
        self.assertGreaterEqual(len(SIDE_EFFECTS), 100)
        self.assertGreaterEqual(len(BENIGN), 70)


class Combining(unittest.TestCase):
    def test_worst_rating_wins_and_every_category_is_kept(self):
        got = classify("git push origin feat && psql -c 'DROP TABLE x'")
        self.assertEqual(got["rating"], "irreversible")
        self.assertEqual(sorted(got["categories"]), ["database", "git-push"])

    def test_empty_command_is_local(self):
        self.assertEqual(classify("   ")["categories"], ["local"])

    def test_unbalanced_quote_does_not_crash(self):
        self.assertIn("git-push", classify("git push -f 'oops")["categories"])


class ShellForms(unittest.TestCase):
    def test_hidden_inside_shell_syntax(self):
        for command in [
            "echo \x24\x28git push -f\x29",
            "echo \x60git push -f\x60",
            "for f in a b; do git push -f; done",
            "bash <<EOF\ngit push -f\nEOF",
            'eval "git push -f"',
            "true || git push -f",
            "sudo -u root env A=1 git push -f",
            "xargs -n 1 git push -f",
            "find . -name x -exec git push -f \\;",
            "nohup git push -f &",
            "timeout 30 git push -f",
            "env -i git push -f",
            "cd x;git push -f",
            'sudo -u root bash -c "git push -f"',
            '"git" push -f',
            "git -c a=b --no-pager push -f",
        ]:
            got = classify(command)
            self.assertEqual((got["categories"], got["rating"]), (["git-push"], "irreversible"), command)

    def test_arithmetic_and_redirects_are_not_commands(self):
        for command in ["echo \x24\x28\x281+2\x29\x29", "ls 2>&1", "for f in *.py; do wc -l \x24f; done"]:
            got = classify(command)
            self.assertEqual((got["categories"], got["rating"]), (["local"], "reversible"), command)


class CurlFlags(unittest.TestCase):
    def test_attached_and_combined_data_flags_are_writes(self):
        for command in ["curl -sd x=1 https://a.example.com", "curl -dx=1 https://a.example.com", "curl -sST f https://a.example.com"]:
            self.assertEqual(classify(command)["rating"], "unknown", command)

    def test_common_download_flags_stay_reads(self):
        for command in ["curl -fsSL https://a.example.com", "curl -sS -o f https://a.example.com", "curl -LO https://a.example.com/f"]:
            self.assertEqual(classify(command)["rating"], "reversible", command)


class Ruleset(unittest.TestCase):
    rules = json.loads((pathlib.Path(__file__).parent.parent / "sideledger" / "rules.json").read_text())

    def test_rules_are_well_formed(self):
        ids = [r["id"] for r in self.rules]
        self.assertEqual(len(ids), len(set(ids)))
        for r in self.rules:
            self.assertIn(r["category"], CATEGORIES)
            self.assertIn(r["rating"], RATINGS)
            self.assertTrue(r["why"])
            re.compile(r["pattern"])


class Folders(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = os.path.realpath(tmp.name)
        self.repo = os.path.join(self.top, "repo")
        os.makedirs(os.path.join(self.repo, ".git"))
        os.makedirs(os.path.join(self.repo, "sub"))

    def rating(self, command, cwd):
        return classify(command, cwd)["rating"]

    def test_absolute_path_inside_the_repo_is_not_outside_it(self):
        self.assertEqual(self.rating("rm -rf %s/build" % self.repo, self.repo), "reversible")
        self.assertEqual(self.rating("rm -rf %s/build" % self.repo, os.path.join(self.repo, "sub")), "reversible")

    def test_paths_that_leave_the_repo_stay_irreversible(self):
        # The test folder itself is under the system temp, which rm-outside allows, so these leave it too.
        for path in ("/opt/other", "%s/../other" % self.repo, "/tmp/../etc/x"):
            self.assertEqual(self.rating("rm -rf " + path, self.repo), "irreversible", path)

    def test_a_sibling_with_the_same_prefix_is_not_inside(self):
        token = "%s-sibling/x" % self.repo
        self.assertEqual(_relative_to_repo(["rm", token], self.repo), ["rm", token])

    def test_without_a_folder_an_absolute_path_is_outside(self):
        self.assertEqual(classify("rm -rf /opt/repo/build")["rating"], "irreversible")


class Speed(unittest.TestCase):
    def test_long_commands_cannot_stall_the_hook(self):
        # The hook runs on every agent command. A nested regex here once took over 10 seconds on 200 tokens.
        heads = ["aws", "kubectl", "gcloud", "az", "fly", "npm", "pnpm", "terraform", "pulumi", "git push",
                 "git -C x push", "wrangler", "vercel", "netlify", "stripe", "gh api", "gh repo create", "docker compose",
                 "curl", "psql", "rm -rf", "mvn"]
        bodies = ["--a b ", "-x y ", "--a ", "-x ", "a b ", "a -b ", "-a -b c ", "x=1 ", "http://localhost/ "]
        started = time.monotonic()
        for head in heads:
            for body in bodies:
                command = head + " " + body * 500
                classify(command)
                redact(command)
        self.assertLess(time.monotonic() - started, 30)


class Destinations(unittest.TestCase):
    def test_extraction(self):
        for command, expected in [
            ("curl https://api.example.com/v1/items?a=1", ["https://api.example.com"]),
            ("curl -s -o out.json api.example.com/x", ["api.example.com"]),
            ("wget http://files.example.com:8080/f.tgz", ["http://files.example.com:8080"]),
            ("psql postgres://admin:pw123456@db.example.com:5432/app -c 'select 1'", ["postgres://db.example.com:5432"]),
            ("psql -h db.example.com -c 'select 1'", ["db.example.com"]),
            ("mysql --host=db.example.com -e 'select 1'", ["db.example.com"]),
            ('psql "$DATABASE_URL"', ["$DATABASE_URL"]),
            ("ssh -i key.pem -p 22 deploy@box.example.com uptime", ["box.example.com"]),
            ("scp a.txt deploy@box.example.com:/tmp/a.txt", ["box.example.com"]),
            ("rsync -a dir/ box.example.com:/srv/", ["box.example.com"]),
            ("git push git@github.com:a/b.git main", ["github.com"]),
            ("git push https://github.com/a/b.git main", ["https://github.com"]),
            ("git push origin main", ["origin"]),
        ]:
            self.assertEqual(classify(command)["destinations"], expected, command)

    def test_body_values_are_not_destinations(self):
        got = classify("curl -d 'next=https://private.example.com' https://api.example.com")
        self.assertEqual(got["destinations"], ["https://api.example.com"])

    def test_local_commands_have_no_destinations(self):
        self.assertEqual(classify('echo "see https://docs.example.com"')["destinations"], [])

    def test_helper_is_token_based(self):
        self.assertEqual(destinations_of(["curl", "https://a.example.com/x"]), ["https://a.example.com"])


if __name__ == "__main__":
    unittest.main()
