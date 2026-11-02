import unittest

from sideledger.redact import redact
from tests.secret_cases import CASES


class RedactTest(unittest.TestCase):
    def test_labelled_secrets_never_survive(self):
        self.assertGreaterEqual(len(CASES), 45)
        leaks = [(command, s) for command, secrets in CASES for s in secrets if s in redact(command)]
        self.assertEqual(leaks, [])

    def test_what_a_person_needs_stays_readable(self):
        for command in [
            "git push origin main",
            "git push -d origin old-branch",
            "fly deploy",
            "psql -h db.example.com -d app -c 'DROP TABLE users'",
            "mkdir -p src/lib",
            "curl https://api.example.com/v1/items",
            "docker run -d nginx",
        ]:
            self.assertEqual(redact(command), command)

    def test_sql_statement_kept_but_values_removed(self):
        out = redact("psql -c \"UPDATE users SET email='a@b.co' WHERE id=1\"")
        self.assertIn("UPDATE users SET email=", out)
        self.assertNotIn("a@b.co", out)

    def test_host_kept_when_password_removed(self):
        out = redact("psql postgres://admin:pw123456@db.example.com/app")
        self.assertIn("db.example.com", out)
        self.assertNotIn("pw123456", out)

    def test_idempotent(self):
        once = redact("curl -H 'Authorization: Bearer abc' -d 'x=1' https://u:p@a.example.com")
        self.assertEqual(redact(once), once)

    def test_long_commands_are_cut(self):
        self.assertLessEqual(len(redact("echo " + "a b " * 5000)), 2001)


if __name__ == "__main__":
    unittest.main()
