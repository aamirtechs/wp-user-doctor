"""WordPress users CSV audit CLI.

Reads a WordPress users CSV export (from `wp user list`, plus an
optional last_login column from a last-login plugin) and audits
it for the accounts that most often get a site hacked or leave
it unmanageable: orphaned administrator accounts that nobody
has logged into for months, the default username admin,
administrators on personal email domains, stale accounts with
no login for N days, accounts that never logged in, accounts
with multiple roles, duplicate logins and emails, and bad data
such as invalid emails, missing roles, unknown roles, and
unparseable or future dates.

Orphaned admin accounts are a top overlooked WordPress
security risk: an admin left behind by a departed developer or
agency keeps full access forever, and a site with four or five
admins rarely knows who they all are. WP-CLI lists users but
does not score them, and the audit guides are all manual
checklists. This tool is the offline audit of the exported
list: it reads the file, flags every problem with a rule name
and a severity, and never touches the site.

Each problem is a finding with a user login, a rule name, a
severity (error or warning), and a message. Errors are the
ones that are a live security risk or break the audit;
warnings are accounts worth following up. --check exits 1
when any error is found, and --strict also fails on warnings.

Zero dependencies, Python 3.10 or newer, standard library only.

Usage:
    python3 wp_user_doctor.py examples/users.csv --as-of 2026-11-11
    python3 wp_user_doctor.py users.csv --json --check
    python3 wp_user_doctor.py users.csv --stale-days 180 --max-admins 2
"""

import argparse
import csv
import datetime
import json
import re
import sys

__version__ = "1.0.0"

KNOWN_ROLES = (
    "administrator", "editor", "author", "contributor",
    "subscriber", "shop_manager", "customer", "super_admin",
)

PERSONAL_DOMAINS = frozenset((
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk",
    "yahoo.co.in", "ymail.com", "hotmail.com", "outlook.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "protonmail.com", "proton.me", "yandex.com",
    "mail.com", "gmx.com", "gmx.net", "zoho.com", "inbox.com",
    "fastmail.com", "tutanota.com",
))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
    "%Y/%m/%d", "%d/%m/%Y",
)

# Header aliases: the export column names this tool accepts.
COLUMN_ALIASES = {
    "user_login": ("user_login", "login", "username"),
    "user_email": ("user_email", "email"),
    "user_registered": ("user_registered", "registered",
                        "registration_date"),
    "user_role": ("user_role", "role", "roles"),
    "last_login": ("last_login", "last_logged_in", "lastlogin",
                   "last_login_date"),
}

REQUIRED_COLUMNS = ("user_login", "user_email", "user_role")

DEFAULT_STALE_DAYS = 90
DEFAULT_MAX_ADMINS = 3


class Finding:
    """One audit finding for one user or for the site."""

    def __init__(self, login, rule, severity, message):
        self.login = login
        self.rule = rule
        self.severity = severity
        self.message = message

    def as_dict(self):
        """Return the finding as a plain dict."""
        return {"login": self.login, "rule": self.rule,
                "severity": self.severity, "message": self.message}

    def __str__(self):
        return "%s [%s] %s: %s" % (self.severity.upper(), self.rule,
                                   self.login, self.message)


def parse_date(value):
    """Parse a date string, or return None when it is invalid.

    Accepted formats are YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, ISO
    datetime with T, YYYY/MM/DD, and DD/MM/YYYY. A blank value
    returns None.
    """
    if value is None:
        return None
    value = value.strip()
    if value == "":
        return None
    for fmt in DATE_FORMATS:
        try:
            return datetime.datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def parse_roles(value):
    """Split a role cell into a list of role names.

    Roles may be separated by commas, semicolons, or pipes, as
    different export plugins write them. A blank cell returns
    an empty list.
    """
    if value is None:
        return []
    parts = re.split(r"[,;|]", value)
    return [part.strip().lower().replace(" ", "_")
            for part in parts if part.strip()]


def is_personal_domain(email):
    """Return True when the email domain is a personal provider."""
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].strip().lower()
    return domain in PERSONAL_DOMAINS


def resolve_columns(header):
    """Map export header names to the canonical column names.

    Returns a dict of canonical name to header index, or None
    when a required column is missing. Header matching is
    case-insensitive and ignores surrounding spaces.
    """
    lowered = [name.strip().lower() for name in header]
    resolved = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                resolved[canonical] = lowered.index(alias)
                break
    for required in REQUIRED_COLUMNS:
        if required not in resolved:
            return None
    return resolved


class User:
    """One user, parsed from one CSV row."""

    def __init__(self, login, email, registered, roles, last_login):
        self.login = login
        self.email = email
        self.registered = registered
        self.roles = roles
        self.last_login = last_login

    @property
    def is_admin(self):
        """Return True when the user holds the administrator role."""
        return "administrator" in self.roles


def load_users(path, as_of, stale_days):
    """Read the users CSV and return (users, findings, has_last_login).

    A duplicate login is reported once and the duplicate row is
    skipped, so one account cannot count twice. A malformed row
    is reported and skipped, never a crash. When the export has
    no last_login column, the stale, never-logged-in, and
    orphaned-admin checks are skipped.
    """
    users = []
    findings = []
    seen_logins = set()
    seen_emails = set()
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("file is empty, no header row found")
        columns = resolve_columns(header)
        if columns is None:
            raise ValueError(
                "missing required column: one of user_login, "
                "user_email, user_role is absent from the header")
        expected = len(header)
        has_last_login = "last_login" in columns
        has_registered = "user_registered" in columns
        for line_no, row in enumerate(reader, start=2):
            if not row or all(not cell.strip() for cell in row):
                continue
            if len(row) != expected:
                findings.append(Finding(
                    "row %d" % line_no, "malformed-row", "error",
                    "row has %d fields but the header has %d, so "
                    "the row was skipped" % (len(row), expected)))
                continue
            login = row[columns["user_login"]].strip()
            email = row[columns["user_email"]].strip()
            roles = parse_roles(row[columns["user_role"]])
            registered_text = ""
            if has_registered:
                registered_text = row[
                    columns["user_registered"]].strip()
            last_login_text = ""
            if has_last_login:
                last_login_text = row[columns["last_login"]].strip()
            if not login:
                findings.append(Finding(
                    "row %d" % line_no, "missing-login", "error",
                    "row has no username, so the account cannot be "
                    "identified"))
                login = "row %d" % line_no
            if login in seen_logins:
                findings.append(Finding(
                    login, "duplicate-login", "error",
                    "login already appears in this export, so this "
                    "duplicate row was skipped"))
                continue
            seen_logins.add(login)
            if email:
                lowered = email.lower()
                if lowered in seen_emails:
                    findings.append(Finding(
                        login, "duplicate-email", "error",
                        "email %s is already used by another account"
                        % email))
                else:
                    seen_emails.add(lowered)
            if not email or not EMAIL_RE.match(email):
                findings.append(Finding(
                    login, "invalid-email", "error",
                    "email %r is missing or not a valid email "
                    "address" % email))
            if login.lower() == "admin":
                findings.append(Finding(
                    login, "default-admin", "error",
                    "username 'admin' is the WordPress default, "
                    "rename it to a unique username"))
            if not roles:
                findings.append(Finding(
                    login, "missing-role", "error",
                    "account has no role, so it cannot log in or "
                    "do anything useful"))
            else:
                if len(roles) > 1:
                    findings.append(Finding(
                        login, "multiple-roles", "warning",
                        "account has multiple roles: %s"
                        % ", ".join(roles)))
                for role in roles:
                    if role not in KNOWN_ROLES:
                        findings.append(Finding(
                            login, "unknown-role", "warning",
                            "role %r is not a standard WordPress "
                            "role" % role))
            registered = parse_date(registered_text)
            if registered_text and registered is None:
                findings.append(Finding(
                    login, "invalid-date", "warning",
                    "registered date %r is not a recognised date"
                    % registered_text))
            elif registered is not None and registered > as_of:
                findings.append(Finding(
                    login, "future-date", "warning",
                    "registered date %s is in the future"
                    % registered))
            last_login = None
            if has_last_login:
                last_login = parse_date(last_login_text)
                if last_login_text and last_login is None:
                    findings.append(Finding(
                        login, "invalid-date", "warning",
                        "last login %r is not a recognised date"
                        % last_login_text))
                elif last_login is not None and last_login > as_of:
                    findings.append(Finding(
                        login, "future-date", "warning",
                        "last login %s is in the future"
                        % last_login))
            if has_last_login and "administrator" in roles:
                if last_login is None and not last_login_text:
                    findings.append(Finding(
                        login, "orphaned-admin", "error",
                        "administrator has never logged in, so the "
                        "account looks orphaned"))
                elif last_login is not None:
                    days = (as_of - last_login).days
                    if days > stale_days:
                        findings.append(Finding(
                            login, "orphaned-admin", "error",
                            "administrator has not logged in for %d "
                            "days, so the account looks orphaned"
                            % days))
            if has_last_login and "administrator" not in roles:
                if last_login is None and not last_login_text:
                    findings.append(Finding(
                        login, "never-logged-in", "warning",
                        "account has never logged in"))
                elif last_login is not None:
                    days = (as_of - last_login).days
                    if days > stale_days:
                        findings.append(Finding(
                            login, "stale-account", "warning",
                            "account has not logged in for %d days"
                            % days))
            if "administrator" in roles and email \
                    and is_personal_domain(email):
                domain = email.rsplit("@", 1)[1].strip().lower()
                findings.append(Finding(
                    login, "admin-personal-email", "error",
                    "administrator uses a personal email domain "
                    "(%s), use a company address" % domain))
            users.append(User(login, email, registered, roles,
                              last_login))
    return users, findings, has_last_login


def analyze_file(path, as_of=None, stale_days=DEFAULT_STALE_DAYS,
                 max_admins=DEFAULT_MAX_ADMINS):
    """Audit one users file and return the report dict."""
    if as_of is None:
        as_of = datetime.date.today()
    users, findings, has_last_login = load_users(
        path, as_of, stale_days)
    admins = [user for user in users if user.is_admin]
    if len(admins) > max_admins:
        findings.append(Finding(
            "(site)", "too-many-admins", "warning",
            "%d administrator accounts is above the maximum of "
            "%d" % (len(admins), max_admins)))
    role_counts = {}
    for user in users:
        for role in user.roles:
            role_counts[role] = role_counts.get(role, 0) + 1
    role_rows = [{"role": role, "users": role_counts[role]}
                 for role in sorted(role_counts)]
    summary = {
        "users": len(users),
        "admins": len(admins),
        "roles": len(role_counts),
        "findings": len(findings),
        "errors": sum(1 for f in findings if f.severity == "error"),
        "warnings": sum(1 for f in findings
                        if f.severity == "warning"),
        "last_login_column": has_last_login,
    }
    return {"summary": summary, "roles": role_rows,
            "findings": [f.as_dict() for f in findings]}


def format_text(report):
    """Render the audit as plain text."""
    summary = report["summary"]
    lines = []
    for finding in report["findings"]:
        lines.append("%s [%s] %s: %s"
                     % (finding["severity"].upper(),
                        finding["rule"], finding["login"],
                        finding["message"]))
    if report["roles"]:
        lines.append("")
        lines.append("Per role:")
        for row in report["roles"]:
            noun = "user" if row["users"] == 1 else "users"
            lines.append("%s: %d %s" % (row["role"], row["users"],
                                        noun))
    lines.append("")
    lines.append("Users: %d, admins: %d, findings: %d, errors: %d, "
                 "warnings: %d"
                 % (summary["users"], summary["admins"],
                    summary["findings"], summary["errors"],
                    summary["warnings"]))
    if not summary["last_login_column"]:
        lines.append("Note: no last_login column found, so stale, "
                     "never-logged-in, and orphaned-admin checks "
                     "were skipped.")
    if not report["findings"]:
        lines.append("All users clean.")
    return "\n".join(lines) + "\n"


def format_json(report):
    """Render the audit as JSON."""
    return json.dumps(report, indent=2) + "\n"


def parse_as_of(value):
    """Parse a YYYY-MM-DD reference date, or raise ValueError."""
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(
            "--as-of must be a YYYY-MM-DD date, got %r" % value)


def main(argv=None):
    """Entry point for the wp-user-doctor CLI."""
    parser = argparse.ArgumentParser(
        description="Audit a WordPress users CSV export for "
                    "orphaned admins, stale accounts, the default "
                    "username admin, multiple roles, and personal "
                    "emails on admin accounts.")
    parser.add_argument("path", help="CSV file of WordPress users")
    parser.add_argument("--stale-days", type=int,
                        default=DEFAULT_STALE_DAYS,
                        help="days without a login before an account "
                             "counts as stale (default: 90)")
    parser.add_argument("--as-of", default=None,
                        help="reference date as YYYY-MM-DD "
                             "(default: today)")
    parser.add_argument("--max-admins", type=int,
                        default=DEFAULT_MAX_ADMINS,
                        help="maximum administrator accounts before "
                             "a warning (default: 3)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of text")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if any error is found")
    parser.add_argument("--strict", action="store_true",
                        help="with --check, also exit 1 on warnings")
    parser.add_argument("--out", help="write the report to a file")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    args = parser.parse_args(argv)
    try:
        as_of = parse_as_of(args.as_of) if args.as_of else None
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    try:
        report = analyze_file(args.path, as_of=as_of,
                              stale_days=args.stale_days,
                              max_admins=args.max_admins)
    except FileNotFoundError:
        print("error: file not found: %s" % args.path, file=sys.stderr)
        return 2
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.path, exc),
              file=sys.stderr)
        return 2
    if args.json:
        output = format_json(report)
    else:
        output = format_text(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")
    summary = report["summary"]
    if args.check:
        if summary["errors"]:
            return 1
        if args.strict and summary["warnings"]:
            return 1
    return 0


def main_entry():
    """Console script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
