"""Tests for wp_user_doctor."""

import datetime
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import wp_user_doctor as wud

HEADER = ("ID,user_login,user_nicename,user_email,url,"
          "user_registered,user_status,display_name,user_role,"
          "last_login\n")

AS_OF = datetime.date(2026, 11, 11)


def row(login, email, role, last_login="", registered="2022-01-10"):
    """Build one CSV row with the standard header columns."""
    return ("1,%s,%s,%s,https://example.com,%s,0,%s,%s,%s\n"
            % (login, login, email, registered, login, role,
               last_login))


def analyze_text(text, **kwargs):
    """Analyze CSV text and return the report dict."""
    with tempfile.NamedTemporaryFile("w", suffix=".csv",
                                     delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        return wud.analyze_file(
            path, as_of=kwargs.get("as_of", AS_OF),
            stale_days=kwargs.get("stale_days", 90),
            max_admins=kwargs.get("max_admins", 3))
    finally:
        os.unlink(path)


def rules(report):
    """Return the sorted list of rule names in the report."""
    return sorted(f["rule"] for f in report["findings"])


def finding_for(report, rule):
    """Return the first finding with this rule, or None."""
    for finding in report["findings"]:
        if finding["rule"] == rule:
            return finding
    return None


class TestParsing(unittest.TestCase):
    def test_parse_date(self):
        self.assertEqual(wud.parse_date("2026-11-01"),
                         datetime.date(2026, 11, 1))
        self.assertEqual(wud.parse_date("2026-11-01 09:30:00"),
                         datetime.date(2026, 11, 1))
        self.assertEqual(wud.parse_date("2026-11-01T09:30:00"),
                         datetime.date(2026, 11, 1))
        self.assertEqual(wud.parse_date("2026/11/01"),
                         datetime.date(2026, 11, 1))
        self.assertEqual(wud.parse_date("01/11/2026"),
                         datetime.date(2026, 11, 1))
        self.assertIsNone(wud.parse_date("Nov 1 2026"))
        self.assertIsNone(wud.parse_date("not-a-date"))
        self.assertIsNone(wud.parse_date(""))
        self.assertIsNone(wud.parse_date(None))

    def test_parse_roles(self):
        self.assertEqual(wud.parse_roles("administrator"),
                         ["administrator"])
        self.assertEqual(wud.parse_roles("administrator,editor"),
                         ["administrator", "editor"])
        self.assertEqual(wud.parse_roles("administrator;editor"),
                         ["administrator", "editor"])
        self.assertEqual(wud.parse_roles("administrator|editor"),
                         ["administrator", "editor"])
        self.assertEqual(wud.parse_roles("Administrator, Editor"),
                         ["administrator", "editor"])
        self.assertEqual(wud.parse_roles("Super Admin"),
                         ["super_admin"])
        self.assertEqual(wud.parse_roles(""), [])
        self.assertEqual(wud.parse_roles(None), [])

    def test_is_personal_domain(self):
        self.assertTrue(wud.is_personal_domain("a@gmail.com"))
        self.assertTrue(wud.is_personal_domain("a@YAHOO.COM"))
        self.assertTrue(wud.is_personal_domain("a@proton.me"))
        self.assertTrue(wud.is_personal_domain("a@hotmail.com"))
        self.assertFalse(wud.is_personal_domain("a@example.com"))
        self.assertFalse(wud.is_personal_domain("a@company.co.uk"))
        self.assertFalse(wud.is_personal_domain("not-an-email"))
        self.assertFalse(wud.is_personal_domain("a@mail.example.com"))

    def test_resolve_columns(self):
        columns = wud.resolve_columns(
            ["ID", "user_login", "user_email", "user_registered",
             "user_role", "last_login"])
        self.assertEqual(columns["user_login"], 1)
        self.assertEqual(columns["user_role"], 4)
        self.assertEqual(columns["last_login"], 5)
        aliases = wud.resolve_columns(
            ["id", "login", "email", "role"])
        self.assertEqual(aliases["user_login"], 1)
        self.assertEqual(aliases["user_email"], 2)
        self.assertEqual(aliases["user_role"], 3)
        self.assertNotIn("last_login", aliases)
        self.assertIsNone(wud.resolve_columns(
            ["ID", "user_login", "user_email"]))
        self.assertIsNone(wud.resolve_columns(
            ["ID", "user_login", "user_role"]))

    def test_parse_as_of(self):
        self.assertEqual(wud.parse_as_of("2026-11-11"),
                         datetime.date(2026, 11, 11))
        with self.assertRaises(ValueError):
            wud.parse_as_of("11/11/2026")
        with self.assertRaises(ValueError):
            wud.parse_as_of("yesterday")


class TestRules(unittest.TestCase):
    def test_default_admin(self):
        report = analyze_text(HEADER + row(
            "admin", "admin@example.com", "administrator",
            "2026-11-10"))
        self.assertIn("default-admin", rules(report))
        self.assertEqual(report["summary"]["errors"], 1)

    def test_default_admin_case_insensitive(self):
        report = analyze_text(HEADER + row(
            "Admin", "admin@example.com", "administrator",
            "2026-11-10"))
        self.assertIn("default-admin", rules(report))

    def test_orphaned_admin_stale(self):
        report = analyze_text(HEADER + row(
            "mike", "mike@example.com", "administrator",
            "2026-06-01"))
        finding = finding_for(report, "orphaned-admin")
        self.assertIsNotNone(finding)
        self.assertIn("163 days", finding["message"])
        self.assertEqual(finding["severity"], "error")

    def test_orphaned_admin_never_logged_in(self):
        report = analyze_text(HEADER + row(
            "oldboss", "oldboss@example.com", "administrator", ""))
        finding = finding_for(report, "orphaned-admin")
        self.assertIsNotNone(finding)
        self.assertIn("never logged in", finding["message"])

    def test_orphaned_admin_boundary(self):
        # Exactly stale-days old is not stale.
        report = analyze_text(HEADER + row(
            "edge", "edge@example.com", "administrator",
            "2026-08-13"))
        self.assertNotIn("orphaned-admin", rules(report))
        # One day older is stale.
        report = analyze_text(HEADER + row(
            "edge", "edge@example.com", "administrator",
            "2026-08-12"))
        self.assertIn("orphaned-admin", rules(report))

    def test_stale_days_override(self):
        report = analyze_text(
            HEADER + row("mike", "mike@example.com",
                         "administrator", "2026-06-01"),
            stale_days=180)
        self.assertNotIn("orphaned-admin", rules(report))

    def test_admin_personal_email(self):
        report = analyze_text(HEADER + row(
            "boss", "boss@gmail.com", "administrator",
            "2026-11-10"))
        finding = finding_for(report, "admin-personal-email")
        self.assertIsNotNone(finding)
        self.assertIn("gmail.com", finding["message"])
        self.assertEqual(finding["severity"], "error")

    def test_admin_company_email_ok(self):
        report = analyze_text(HEADER + row(
            "boss", "boss@example.com", "administrator",
            "2026-11-10"))
        self.assertNotIn("admin-personal-email", rules(report))

    def test_personal_email_on_non_admin_ok(self):
        report = analyze_text(HEADER + row(
            "reader", "reader@gmail.com", "subscriber",
            "2026-11-10"))
        self.assertNotIn("admin-personal-email", rules(report))
        self.assertEqual(report["summary"]["findings"], 0)

    def test_stale_account(self):
        report = analyze_text(HEADER + row(
            "tom", "tom@example.com", "subscriber", "2025-01-01"))
        finding = finding_for(report, "stale-account")
        self.assertIsNotNone(finding)
        self.assertIn("679 days", finding["message"])
        self.assertEqual(finding["severity"], "warning")

    def test_never_logged_in(self):
        report = analyze_text(HEADER + row(
            "newhire", "newhire@example.com", "contributor", ""))
        self.assertIn("never-logged-in", rules(report))
        self.assertEqual(report["summary"]["warnings"], 1)

    def test_recent_login_clean(self):
        report = analyze_text(HEADER + row(
            "amy", "amy@example.com", "editor", "2026-11-10"))
        self.assertEqual(report["summary"]["findings"], 0)

    def test_multiple_roles(self):
        report = analyze_text(HEADER + row(
            "priya", "priya@example.com", "administrator;editor",
            "2026-11-10"))
        finding = finding_for(report, "multiple-roles")
        self.assertIsNotNone(finding)
        self.assertIn("administrator, editor", finding["message"])
        self.assertEqual(finding["severity"], "warning")

    def test_duplicate_login_skipped(self):
        text = HEADER + row("sarah", "sarah@example.com", "editor",
                            "2026-11-09")
        text += row("sarah", "other@example.com", "author",
                    "2026-11-09")
        report = analyze_text(text)
        self.assertIn("duplicate-login", rules(report))
        self.assertEqual(report["summary"]["users"], 1)

    def test_duplicate_email_kept(self):
        text = HEADER + row("jane", "jane@example.com", "author",
                            "2026-11-08")
        text += row("janedup", "JANE@example.com", "subscriber",
                    "2026-11-05")
        report = analyze_text(text)
        self.assertIn("duplicate-email", rules(report))
        self.assertEqual(report["summary"]["users"], 2)

    def test_invalid_email(self):
        report = analyze_text(HEADER + row(
            "badmail", "not-an-email", "subscriber", "2026-11-02"))
        self.assertIn("invalid-email", rules(report))

    def test_missing_email(self):
        report = analyze_text(HEADER + row(
            "noemail", "", "subscriber", "2026-11-02"))
        self.assertIn("invalid-email", rules(report))

    def test_missing_role(self):
        report = analyze_text(HEADER + row(
            "norole", "norole@example.com", "", "2026-11-01"))
        self.assertIn("missing-role", rules(report))
        self.assertEqual(report["summary"]["errors"], 1)

    def test_unknown_role(self):
        report = analyze_text(HEADER + row(
            "weird", "weird@example.com", "superuser",
            "2026-10-30"))
        finding = finding_for(report, "unknown-role")
        self.assertIsNotNone(finding)
        self.assertIn("superuser", finding["message"])
        self.assertEqual(finding["severity"], "warning")

    def test_known_extra_roles_ok(self):
        for role in ("shop_manager", "customer", "super_admin"):
            report = analyze_text(HEADER + row(
                "user1", "user1@example.com", role, "2026-11-10"))
            self.assertNotIn("unknown-role", rules(report),
                             role)

    def test_malformed_row(self):
        report = analyze_text(HEADER + "14,short,short\n")
        self.assertIn("malformed-row", rules(report))
        self.assertEqual(report["summary"]["users"], 0)

    def test_invalid_registered_date(self):
        report = analyze_text(HEADER + row(
            "baddate", "baddate@example.com", "subscriber",
            "2026-11-10", registered="not-a-date"))
        self.assertIn("invalid-date", rules(report))

    def test_invalid_last_login_date(self):
        report = analyze_text(HEADER + row(
            "badlogin", "badlogin@example.com", "subscriber",
            "not-a-date"))
        self.assertIn("invalid-date", rules(report))

    def test_future_registered_date(self):
        report = analyze_text(HEADER + row(
            "future", "future@example.com", "subscriber",
            "2026-11-10", registered="2027-01-01"))
        self.assertIn("future-date", rules(report))

    def test_future_last_login(self):
        report = analyze_text(HEADER + row(
            "future", "future@example.com", "subscriber",
            "2026-12-01"))
        self.assertIn("future-date", rules(report))

    def test_missing_login(self):
        report = analyze_text(HEADER + row(
            "", "anon@example.com", "subscriber", "2026-11-10"))
        self.assertIn("missing-login", rules(report))

    def test_too_many_admins(self):
        text = HEADER
        for name in ("a1", "a2", "a3", "a4"):
            text += row(name, "%s@example.com" % name,
                        "administrator", "2026-11-10")
        report = analyze_text(text)
        finding = finding_for(report, "too-many-admins")
        self.assertIsNotNone(finding)
        self.assertIn("4 administrator accounts", finding["message"])
        self.assertEqual(report["summary"]["admins"], 4)

    def test_max_admins_override(self):
        text = HEADER
        for name in ("a1", "a2", "a3", "a4"):
            text += row(name, "%s@example.com" % name,
                        "administrator", "2026-11-10")
        report = analyze_text(text, max_admins=4)
        self.assertNotIn("too-many-admins", rules(report))

    def test_three_admins_ok(self):
        text = HEADER
        for name in ("a1", "a2", "a3"):
            text += row(name, "%s@example.com" % name,
                        "administrator", "2026-11-10")
        report = analyze_text(text)
        self.assertNotIn("too-many-admins", rules(report))


class TestOutput(unittest.TestCase):
    def test_no_last_login_column(self):
        header = ("ID,user_login,user_email,user_registered,"
                  "user_role\n")
        text = header + ("1,alice,alice@example.com,2022-01-10,"
                         "administrator\n")
        report = analyze_text(text)
        self.assertFalse(report["summary"]["last_login_column"])
        self.assertEqual(report["summary"]["findings"], 0)
        output = wud.format_text(report)
        self.assertIn("no last_login column found", output)

    def test_missing_required_column(self):
        header = "ID,user_login,user_email\n"
        text = header + "1,alice,alice@example.com\n"
        with tempfile.NamedTemporaryFile("w", suffix=".csv",
                                        delete=False) as handle:
            handle.write(text)
            path = handle.name
        try:
            with self.assertRaises(ValueError):
                wud.analyze_file(path, as_of=AS_OF)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv",
                                        delete=False) as handle:
            handle.write("")
            path = handle.name
        try:
            with self.assertRaises(ValueError):
                wud.analyze_file(path, as_of=AS_OF)
        finally:
            os.unlink(path)

    def test_bom_header(self):
        text = "\ufeff" + HEADER + row(
            "amy", "amy@example.com", "editor", "2026-11-10")
        report = analyze_text(text)
        self.assertEqual(report["summary"]["users"], 1)
        self.assertEqual(report["summary"]["findings"], 0)

    def test_blank_lines_skipped(self):
        text = HEADER + "\n" + row(
            "amy", "amy@example.com", "editor", "2026-11-10") + "\n"
        report = analyze_text(text)
        self.assertEqual(report["summary"]["users"], 1)

    def test_role_table_counts_multi_role_twice(self):
        report = analyze_text(HEADER + row(
            "priya", "priya@example.com", "administrator;editor",
            "2026-11-10"))
        roles = {r["role"]: r["users"] for r in report["roles"]}
        self.assertEqual(roles["administrator"], 1)
        self.assertEqual(roles["editor"], 1)
        self.assertEqual(report["summary"]["roles"], 2)

    def test_json_shape(self):
        report = analyze_text(HEADER + row(
            "amy", "amy@example.com", "editor", "2026-11-10"))
        parsed = json.loads(wud.format_json(report))
        self.assertEqual(parsed["summary"]["users"], 1)
        self.assertEqual(parsed["roles"][0]["role"], "editor")
        self.assertEqual(parsed["findings"], [])

    def test_text_clean_message(self):
        report = analyze_text(HEADER + row(
            "amy", "amy@example.com", "editor", "2026-11-10"))
        self.assertIn("All users clean.",
                      wud.format_text(report))


class TestSamples(unittest.TestCase):
    def setUp(self):
        self.base = os.path.join(
            os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "examples")

    def test_users_sample(self):
        path = os.path.join(self.base, "users.csv")
        report = wud.analyze_file(path, as_of=AS_OF)
        summary = report["summary"]
        self.assertEqual(summary["users"], 14)
        self.assertEqual(summary["admins"], 4)
        self.assertEqual(summary["findings"], 16)
        self.assertEqual(summary["errors"], 9)
        self.assertEqual(summary["warnings"], 7)
        expected = ["admin-personal-email", "default-admin",
                    "duplicate-email", "duplicate-login",
                    "future-date", "invalid-date", "invalid-email",
                    "malformed-row", "missing-role",
                    "multiple-roles", "never-logged-in",
                    "orphaned-admin", "stale-account",
                    "too-many-admins", "unknown-role"]
        for rule in expected:
            self.assertIn(rule, rules(report), rule)

    def test_clean_sample(self):
        path = os.path.join(self.base, "clean.csv")
        report = wud.analyze_file(path, as_of=AS_OF)
        self.assertEqual(report["summary"]["findings"], 0)
        self.assertEqual(report["summary"]["users"], 3)

    def test_warnings_only_sample(self):
        path = os.path.join(self.base, "warnings-only.csv")
        report = wud.analyze_file(path, as_of=AS_OF)
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(report["summary"]["warnings"], 3)


class TestCli(unittest.TestCase):
    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "wp_user_doctor"] + list(argv),
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))

    def sample(self, name):
        return os.path.join(
            os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "examples", name)

    def test_check_exit_codes(self):
        result = self.run_cli(self.sample("users.csv"),
                              "--as-of", "2026-11-11", "--check")
        self.assertEqual(result.returncode, 1)
        result = self.run_cli(self.sample("clean.csv"),
                              "--as-of", "2026-11-11", "--check")
        self.assertEqual(result.returncode, 0)
        result = self.run_cli(self.sample("warnings-only.csv"),
                              "--as-of", "2026-11-11", "--check")
        self.assertEqual(result.returncode, 0)
        result = self.run_cli(self.sample("warnings-only.csv"),
                              "--as-of", "2026-11-11", "--check",
                              "--strict")
        self.assertEqual(result.returncode, 1)

    def test_missing_file(self):
        result = self.run_cli("no-such-file.csv")
        self.assertEqual(result.returncode, 2)
        self.assertIn("file not found", result.stderr)

    def test_bad_as_of(self):
        result = self.run_cli(self.sample("clean.csv"),
                              "--as-of", "yesterday")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--as-of", result.stderr)

    def test_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.txt")
            result = self.run_cli(self.sample("clean.csv"),
                                  "--as-of", "2026-11-11",
                                  "--out", out)
            self.assertEqual(result.returncode, 0)
            with open(out, encoding="utf-8") as handle:
                self.assertIn("All users clean.", handle.read())

    def test_json_output(self):
        result = self.run_cli(self.sample("clean.csv"),
                              "--as-of", "2026-11-11", "--json")
        self.assertEqual(result.returncode, 0)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["summary"]["users"], 3)


if __name__ == "__main__":
    unittest.main()
