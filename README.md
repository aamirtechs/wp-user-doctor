# wp-user-doctor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/aamirtechs/wp-user-doctor/blob/main/LICENSE) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/aamirtechs/wp-user-doctor/issues)

A zero-dependency Python CLI that audits a WordPress users CSV
export for the accounts that most often get a site hacked or
leave it unmanageable: orphaned administrator accounts nobody
has logged into for months, the default username admin,
administrators on personal email domains, stale accounts with
no login for N days, accounts that never logged in, accounts
with multiple roles, duplicate logins and emails, and too many
administrators.

Orphaned admin accounts are a top overlooked WordPress
security risk: an admin left behind by a departed developer or
agency keeps full access forever, and a site with four or five
admins rarely knows who they all are. WP-CLI lists users but
does not score them, and the audit guides are all manual
checklists. This tool is the offline audit of the exported
list.

## Install

Requires Python 3.10 or newer. No dependencies beyond the
standard library.

```bash
pip install wp-user-doctor
```

Or run it straight from the source checkout:

```bash
python3 wp_user_doctor.py examples/users.csv --as-of 2026-11-11
```

## Input format

A CSV export with a header row, as produced by
`wp user list --format=csv`, plus an optional `last_login`
column from a last-login plugin. Columns used: `user_login`,
`user_email`, `user_registered`, `user_role`, and `last_login`.
The aliases `login`, `email`, `registered`, `role`, and
`last_logged_in` are accepted too. A UTF-8 BOM header is
handled. Dates are accepted as YYYY-MM-DD, YYYY-MM-DD
HH:MM:SS, ISO datetime, YYYY/MM/DD, or DD/MM/YYYY.

```csv
ID,user_login,user_nicename,user_email,url,user_registered,user_status,display_name,user_role,last_login
1,admin,admin,admin@example.com,https://example.com,2020-01-15 08:00:00,0,Site Admin,administrator,2026-11-10 09:00:00
3,mike,mike,mike.chen@example.com,https://example.com,2022-05-20 11:00:00,0,Mike Chen,administrator,2026-06-01 08:30:00
4,oldboss,oldboss,oldboss@gmail.com,https://example.com,2019-08-11 09:00:00,0,Old Boss,administrator,
5,priya,priya,priya@example.com,https://example.com,2023-01-10 12:00:00,0,Priya Patel,administrator;editor,2026-11-10 10:00:00
```

Export it with WP-CLI:

```bash
wp user list --format=csv --fields=ID,user_login,user_nicename,user_email,url,user_registered,user_status,display_name,user_role > users.csv
```

## What it checks

Errors, the ones that are a live security risk or break the
audit:

* `orphaned-admin`: an administrator with no login for more
  than `--stale-days` (default 90), including one that has
  never logged in. The account looks abandoned but still holds
  full access.
* `default-admin`: the username is `admin`, the WordPress
  default, which every brute-force list tries first.
* `admin-personal-email`: an administrator on a personal email
  domain (gmail.com, yahoo.com, hotmail.com, outlook.com, and
  the rest of the built-in list). A company address is expected
  on an admin account.
* `duplicate-login`: a login that already appears in the
  export. The duplicate row is skipped, so one account cannot
  count twice.
* `duplicate-email`: an email already used by another account.
  The row is kept, because a shared mailbox is possible.
* `invalid-email`: an email that is missing or not a valid
  email address.
* `missing-login`: a row with no username, so the account
  cannot be identified.
* `missing-role`: an account with no role, so it cannot log in
  or do anything useful.
* `malformed-row`: a row with the wrong number of fields. The
  row is skipped and reported, never a crash.

Warnings, accounts worth following up:

* `stale-account`: a non-admin account with no login for more
  than `--stale-days`.
* `never-logged-in`: a non-admin account that has never logged
  in.
* `multiple-roles`: an account holding more than one role, for
  example `administrator;editor`. Roles may be separated by
  commas, semicolons, or pipes.
* `unknown-role`: a role that is not a standard WordPress role
  (administrator, editor, author, contributor, subscriber,
  shop_manager, customer, super_admin). It is a warning, not
  an error, because plugins add real roles.
* `invalid-date`: a registered or last-login date that is not a
  recognised date.
* `future-date`: a registered or last-login date in the future.
* `too-many-admins`: more administrator accounts than
  `--max-admins` (default 3).

## Usage

```bash
python3 wp_user_doctor.py examples/users.csv --as-of 2026-11-11
```

Captured output:

```
ERROR [default-admin] admin: username 'admin' is the WordPress default, rename it to a unique username
ERROR [orphaned-admin] mike: administrator has not logged in for 163 days, so the account looks orphaned
ERROR [orphaned-admin] oldboss: administrator has never logged in, so the account looks orphaned
ERROR [admin-personal-email] oldboss: administrator uses a personal email domain (gmail.com), use a company address
WARNING [multiple-roles] priya: account has multiple roles: administrator, editor
WARNING [stale-account] tom: account has not logged in for 679 days
WARNING [never-logged-in] newhire: account has never logged in
ERROR [duplicate-email] janedup: email jane@example.com is already used by another account
ERROR [invalid-email] badmail: email 'not-an-email' is missing or not a valid email address
ERROR [missing-role] norole: account has no role, so it cannot log in or do anything useful
WARNING [unknown-role] weird: role 'superuser' is not a standard WordPress role
ERROR [duplicate-login] sarah: login already appears in this export, so this duplicate row was skipped
ERROR [malformed-row] row 15: row has 3 fields but the header has 10, so the row was skipped
WARNING [future-date] future: registered date 2027-01-01 is in the future
WARNING [invalid-date] baddate: registered date 'not-a-date' is not a recognised date
WARNING [too-many-admins] (site): 4 administrator accounts is above the maximum of 3

Per role:
administrator: 4 users
author: 1 user
contributor: 1 user
editor: 2 users
subscriber: 5 users
superuser: 1 user

Users: 14, admins: 4, findings: 16, errors: 9, warnings: 7
```

The sample has 14 users after the duplicate login and the
malformed row are left out. Two administrators are orphaned:
mike has not logged in for 163 days, and oldboss never logged
in at all and is also on a personal gmail.com address. The
default username `admin` is still present, and there are 4
administrators where the default maximum is 3.

The reference date defaults to today. `--as-of` pins it, so the
stale day counts above are reproducible; without it the counts
move as time passes.

Use it as a CI gate: `--check` exits 1 when any error is
found, and 0 otherwise. On the sample above it exits 1:

```bash
python3 wp_user_doctor.py examples/users.csv --as-of 2026-11-11 --check
```

On `examples/clean.csv`, three clean users, it exits 0:

```
Per role:
administrator: 1 user
author: 1 user
editor: 1 user

Users: 3, admins: 1, findings: 0, errors: 0, warnings: 0
All users clean.
```

With `--strict`, `--check` also fails on warnings.
`examples/warnings-only.csv` has three warnings, a stale
subscriber, a never-logged-in contributor, and a multi-role
editor, so it passes `--check` (exit 0) and fails
`--check --strict` (exit 1).

`--json` emits the summary, per-role table, and findings as
JSON:

```bash
python3 wp_user_doctor.py examples/users.csv --as-of 2026-11-11 --json
```

Captured output (first findings and summary):

```json
[
  {
    "login": "admin",
    "rule": "default-admin",
    "severity": "error",
    "message": "username 'admin' is the WordPress default, rename it to a unique username"
  },
  {
    "login": "mike",
    "rule": "orphaned-admin",
    "severity": "error",
    "message": "administrator has not logged in for 163 days, so the account looks orphaned"
  },
  {
    "login": "oldboss",
    "rule": "orphaned-admin",
    "severity": "error",
    "message": "administrator has never logged in, so the account looks orphaned"
  }
]
```

```json
{
  "users": 14,
  "admins": 4,
  "roles": 6,
  "findings": 16,
  "errors": 9,
  "warnings": 7,
  "last_login_column": true
}
```

`--out` writes the report to a file instead of printing it.

## Options

| Flag | Meaning |
| --- | --- |
| `--stale-days` | Days without a login before an account counts as stale (default: 90) |
| `--as-of` | Reference date as YYYY-MM-DD (default: today) |
| `--max-admins` | Maximum administrator accounts before a warning (default: 3) |
| `--json` | Emit JSON instead of text |
| `--check` | Exit 1 if any error is found |
| `--strict` | With --check, also exit 1 on warnings |
| `--out` | Write the report to a file |

## Edge cases

* A plain `wp user list` export has no `last_login` column.
  The stale, never-logged-in, and orphaned-admin checks are
  then skipped and a note line says so; the other checks still
  run. Add the column from a last-login plugin to audit login
  activity.
* A duplicate login row is skipped from the analysis, so one
  account cannot count twice. A duplicate email row is kept,
  because a shared mailbox is possible.
* A user with multiple roles counts toward each of its roles
  in the per-role table.
* An account exactly `--stale-days` old is not stale; only
  older than that is flagged.
* A personal email on a non-admin account is not flagged.
  Only administrators are expected to use a company address.
* A blank line in the file is skipped silently. A row with too
  many or too few fields is a malformed-row error and is
  skipped; the rest of the file is still analyzed.
* Role matching is case-insensitive, and `Super Admin` is read
  as `super_admin`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

50 tests, all passing: date and role parsing, personal domain
detection, header aliases, every rule including the
stale-days boundary and the --stale-days and --max-admins
overrides, duplicate logins and emails, malformed rows,
invalid, missing, and future dates, BOM headers, the
no-last-login-column note, sample counts, JSON output shape,
and `--check` and `--strict` exit codes. The same 50 tests
pass under pytest.

## License

MIT. See [LICENSE](LICENSE).
