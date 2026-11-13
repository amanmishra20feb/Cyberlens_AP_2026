# Normalization: Cyberlens (Team T0028)

Cyberlens scans public GitHub repositories with three engines (Semgrep, Gitleaks, OSV-Scanner) and shows the
findings mapped to OWASP and CWE. This document takes the data of the app as it is stored today
(`backend/migrations/001_init.sql` after migrations 002 and 003) through 1NF, 2NF and 3NF, and checks BCNF.
At each step we show the tables, the keys and the functional dependencies (FDs).

## 0. The data as the app stores it today

| Table | Columns |
|---|---|
| **users** | id (uuid, PK), email (unique), name, password_hash, created_at |
| **scans** | id (PK), user_id (FK users), repo_url, branch, commit, status, error, **counts** (jsonb), **engines** (jsonb), **files** (jsonb), file_count, started_at, finished_at, created_at |
| **findings** | id (PK), scan_id (FK scans), user_id (FK users), **engines** (text[]), rule_id, title, message, severity, **cwe** (text[]), **owasp** (text[]), file, line, end_line, snippet, snippet_line, fingerprint, status, ignore_reason, created_at, updated_at; UNIQUE (scan_id, fingerprint) |

The bold columns hold several values in one cell (arrays and JSON). Illustrative rows (values made up to show the shape):

| findings.id | scan_id | user_id | engines | rule_id | cwe | owasp | file | line | severity |
|---|---|---|---|---|---|---|---|---|---|
| f1 | s1 | u1 | {semgrep, gitleaks} | gitleaks.generic-api-key | {CWE-798} | {A07} | config.js | 12 | critical |

| scans.id | user_id | counts | engines | files |
|---|---|---|---|---|
| s1 | u1 | {"critical":1,"high":0,"medium":2,"low":0} | [{"name":"semgrep","ok":true,"count":3,"ms":41200}, {"name":"gitleaks","ok":true,"count":1,"ms":2300}, {"name":"osv","ok":false,"error":"timed out","ms":120000}] | [{"path":"config.js","loc":40}, {"path":"src/app.js","loc":120}] |

A successful engine entry has no `error` key, and a failed one has no `count` key (see `runEngine` in `scan.js`).

## 1. First normal form (1NF)

Rule: every column holds one atomic value, with no repeating groups and no lists inside a cell.

| Column | Why it is not atomic |
|---|---|
| findings.engines | list of engines that reported the same problem (the scanner merges duplicates into one finding) |
| findings.cwe | list of CWE ids of one finding |
| findings.owasp | list of OWASP categories of one finding |
| scans.engines | list of objects, one per engine: name, ok, count, error, ms |
| scans.files | list of objects, one per file: path, loc (largest 1,500 files, for the Repo Map) |
| scans.counts | four counters in one cell (critical, high, medium, low): a repeating group of columns |

Fix: every repeating group moves to its own table, one row per value, with the parent key as a foreign key.
`scans.counts` is handled in step 3, as derived data.

New tables (key in brackets):

```
finding_engines (finding_id, engine)                          -- from findings.engines
finding_cwe     (finding_id, cwe)                             -- from findings.cwe
finding_owasp   (finding_id, owasp)                           -- from findings.owasp
scan_engines    (scan_id, engine, ok, finding_count, error, ms)   -- from scans.engines
scan_files      (scan_id, path, loc)                          -- from scans.files
```

Result of the example above: finding f1 becomes 2 rows in `finding_engines` (semgrep, gitleaks), 1 row in `finding_cwe`
and 1 row in `finding_owasp`.

FDs of the new tables: `scan_engines`: (scan_id, engine) -> ok, finding_count, error, ms. `scan_files`: (scan_id, path) -> loc.
In `scan_engines`, `finding_count` and `error` can be NULL: a successful engine has no error, and a failed one has no count.
The three `finding_*` tables have only the key columns, so they have no non-key attributes.

## 2. Second normal form (2NF)

Rule: 1NF, and no non-key attribute depends on only part of a candidate key.

`findings` has two candidate keys: the surrogate `id`, and the natural key (**scan_id, fingerprint**). The fingerprint
is a hash the scanner computes so the same problem is not saved twice in one scan (`merge()` in `normalise.js`: sha256
of `file|line|first CWE`, or of `file|rule_id|title` when the finding has no line). FDs of `findings`:

| # | FD |
|---|---|
| F1 | id -> every other column |
| F2 | (scan_id, fingerprint) -> every other column |
| F3 | **scan_id -> user_id** (the owner of a finding is the owner of its scan) |
| F4 | **fingerprint -> file, line** (the same fingerprint always means the same file and line, because it is a hash of them; many scans can share one fingerprint) |

F3 and F4 are both **partial dependencies** on the composite candidate key (scan_id, fingerprint): `user_id` depends
on `scan_id` alone, and `file` and `line` depend on `fingerprint` alone. So `findings` is not in 2NF. Fixes:
- remove `findings.user_id`; the owner stays reachable through `scans.user_id`;
- treat `fingerprint` as derived data: it is computed from other columns, so it is removed from the design and `id`
  becomes the only candidate key (section 6 says what the app uses it for).

The new junction tables are in 2NF: `scan_engines` and `scan_files` depend on their whole composite key, and the
`finding_*` tables have no non-key columns. `users` and `scans` have a single-column key.

## 3. Third normal form (3NF)

Rule: 2NF, and no non-key attribute depends on another non-key attribute.

| Table | Check | Result |
|---|---|---|
| findings | id -> scan_id -> user_id | the transitive form of F3, already removed in step 2 |
| findings | rule_id -> title, cwe, owasp, severity? | **Not an FD in this data**, so no `rules` table. Gitleaks and Semgrep titles are built from the rule id, but OSV-Scanner findings use the CVE as `rule_id` and build the title from the **package name and version**, and Semgrep messages can contain matched values. When two engines report the same line, the merge also keeps the worst severity. So the same `rule_id` can have different titles and severities. |
| scans | id -> user_id, repo_url, branch, commit, status, error, file_count, started_at, finished_at, created_at | all depend on the key only |
| findings | snippet_line, line | **Not an FD**: `snippet_line` equals `line` for Gitleaks snippets and `max(1, line - 2)` for the others, so `line` alone does not determine it. |
| scans | **counts** | **Not a 3NF violation** (it depends only on `scans.id`), but it is redundant: it repeats the number of findings per severity of that scan. Redundant data can cause update anomalies, so we remove it from the design. In the app it cannot go stale: triage only changes `status` and `ignore_reason`, and deleting a scan deletes all its findings. See section 6. |
| users | id -> email, name, password_hash | all depend on the key only |

After step 3 there is no transitive dependency left.

## 4. BCNF check

BCNF: the left side of every FD must be a candidate key.

| Table | Determinants | Candidate keys? |
|---|---|---|
| users | id, email | yes, both |
| scans | id | yes |
| findings | id | yes (the only candidate key once `fingerprint` is removed) |
| scan_engines | (scan_id, engine) | yes |
| scan_files | (scan_id, path) | yes |
| finding_engines / finding_cwe / finding_owasp | the whole row | yes (no non-key columns) |

In the table as built, F4 (`fingerprint -> file, line`) would break BCNF: `fingerprint` is a determinant but not a key,
because many scans share one fingerprint. Removing it as derived data (step 2) fixes this.

**All 8 tables are in BCNF.**

## 5. Final tables (3NF / BCNF)

| Table | Primary key | Other columns | Foreign keys |
|---|---|---|---|
| **users** | id | email (UNIQUE), name, password_hash, created_at | |
| **scans** | id | user_id, repo_url, branch, commit, status, error, file_count, started_at, finished_at, created_at | user_id -> users |
| **scan_engines** | (scan_id, engine) | ok, finding_count, error, ms | scan_id -> scans |
| **scan_files** | (scan_id, path) | loc | scan_id -> scans |
| **findings** | id | scan_id, rule_id, title, message, severity, file, line, end_line, snippet, snippet_line, status, ignore_reason, created_at, updated_at | scan_id -> scans |
| **finding_engines** | (finding_id, engine) | | finding_id -> findings |
| **finding_cwe** | (finding_id, cwe) | | finding_id -> findings |
| **finding_owasp** | (finding_id, owasp) | | finding_id -> findings |

Relationships: user 1:N scans; scan 1:N findings; scan 1:N scan_engines; scan 1:N scan_files; finding 1:N each of
finding_engines, finding_cwe and finding_owasp.

No data about a scan or a finding is lost: joining the child tables back to `findings` and `scans` rebuilds every array
and JSON value (`array_agg` or `json_agg`), and `scans.counts` is `count(*)` of the scan's findings grouped by severity.
The only value not stored is `fingerprint`, which is computed when a scan is saved.

## 6. Where the running app differs from the 3NF design, and why

The app was built for speed of development and for how the screens read the data, not for strict normal forms:

| Running app | 3NF design | Why the app does it this way | What it costs |
|---|---|---|---|
| `findings.engines`, `cwe`, `owasp` as `text[]` | three child tables | one INSERT of all findings from a single JSON parameter (`jsonb_to_recordset`); the findings page always reads the whole list of a scan | no foreign keys or integrity on the values; "findings per CWE" needs `unnest` |
| `scans.engines`, `scans.files` as `jsonb` | `scan_engines`, `scan_files` | the scan page shows the engines and the Repo Map exactly as stored, and nothing queries inside them | cannot index or constrain individual files or engines |
| `scans.counts` as `jsonb` | computed with `count(*)` | the scan list shows the totals without counting findings | duplicate data (kept in sync because findings never change severity) |
| `findings.fingerprint` and `UNIQUE (scan_id, fingerprint)` | not stored | a hash the scanner uses to merge duplicate findings and to stop the same finding being saved twice in one scan | duplicate data (a hash of file, line and CWE); without it the 3NF design has no key that blocks duplicate findings, so the app would have to check this itself |
| `findings.user_id` | removed (reach the owner through `scans`) | every findings query checks `user_id = $n`, so a user can never read another user's finding, without a join | duplicate data; must always equal `scans.user_id` |

## 7. How this relates to the running app

Cyberlens runs on the 3-table schema in section 0, and no migration to the 8-table design is planned. The next
deliverables (ER diagram, schema file and queries) therefore describe the real tables, and section 6 records which
columns are deliberately denormalized and why. If the team later moves to the 8-table design, it needs a new
migration (`004_...sql`) and updated backend queries.
