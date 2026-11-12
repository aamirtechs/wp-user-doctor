# Changelog

## 1.0.0 - 2026-11-11

Initial release.

* WordPress users audit over a CSV export from `wp user list`
  (plus an optional last_login column from a last-login
  plugin): orphaned administrator accounts, the default
  username admin, administrators on personal email domains,
  stale accounts with no login for N days, accounts that never
  logged in, accounts with multiple roles, duplicate logins and
  emails, and too many administrator accounts.
* Orphaned admins flagged as errors: an administrator with no
  login for more than --stale-days (default 90), including one
  that has never logged in. Stale and never-logged-in
  non-admin accounts flagged as warnings.
* Data errors reported and skipped, never a crash: invalid or
  missing emails, missing logins, missing roles, duplicate
  logins (the duplicate row is skipped), duplicate emails,
  malformed rows, and unknown roles. Unknown roles are
  warnings, because plugins add real roles.
* Dates accepted as YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, ISO
  datetime, YYYY/MM/DD, or DD/MM/YYYY; invalid, missing, and
  future registered and last-login dates are warnings.
* A per-role table counts users by role, and the summary
  reports users, admins, findings, errors, and warnings.
* Text and --json output, --out file output, and a --check CI
  gate that exits 1 on errors (and on warnings with --strict).
  --as-of pins the reference date, --stale-days and
  --max-admins tune the thresholds.
* Zero dependencies, Python 3.10 or newer.
