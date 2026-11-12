# Good first issues

Seeded issues for new contributors. File each one on GitHub with
the `good first issue` and `help wanted` labels.

## 1. Add a custom personal domains file

Title: Let teams supply their own personal email domains

Description: Add a --personal-domains flag that reads a file of
email domains (one per line) and uses it instead of the built-in
list, so a team can flag its own domains like a company alumni
domain without changing the code. Lines starting with # are
comments and are ignored.

Difficulty: Easy

Acceptance criteria: a file containing "alumni.example.com"
flags an admin on that domain and does not flag a gmail.com
admin; without the flag the built-in list still applies; a test
covers both cases; README documents the flag.

## 2. Add a per-user last login age column

Title: Show days since last login in the report

Description: Add a --ages flag that prints, after the per-role
table, one line per user with the days since their last login
(or "never" when they never logged in), sorted with the
stalest first, so a manager can see the whole picture at a
glance instead of only the flagged accounts. Users with no
last_login column in the export are left out with a note line.

Difficulty: Easy

Acceptance criteria: the ages for the sample file show mike at
163 days and oldboss as never; a test checks the ordering;
README documents the flag.

## 3. Support the wp user list JSON export

Title: Accept wp user list --format=json input

Description: Add a --format json option so the tool can read
the JSON output of `wp user list --format=json` directly, with
the same checks and the same output. The JSON objects carry
the same field names as the CSV columns.

Difficulty: Medium

Acceptance criteria: the sample users as JSON produce the same
16 findings as the CSV; a test round-trips both formats;
README documents the option.

## 4. Add a suggested-action line per finding

Title: Print what to do about each flagged account

Description: Each finding already says what is wrong. Add a
short suggested action to the text output, for example
"demote to subscriber" for an orphaned admin or "rename the
account" for the default admin, so a site owner who is not a
WordPress expert knows the next step. The JSON output gains an
"action" field per finding.

Difficulty: Medium

Acceptance criteria: the sample file shows an action for every
finding; the JSON findings carry the action field; a test
covers the mapping; README documents the actions.
