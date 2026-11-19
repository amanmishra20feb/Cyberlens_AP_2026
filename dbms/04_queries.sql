-- Cyberlens: every SQL query the application sends to PostgreSQL (team T0028).
-- Source: backend/src (db.js, auth.js, routes/auth.js, routes/scans.js, routes/findings.js, scanner/worker.js).
-- Tables: users, scans, findings (see 03_schema.sql). $1, $2, ... are bind parameters, filled in by the app;
-- the comment after each query says what they are.
-- Each query has an id (R1, R2, ... for reads, W1, W2, ... for writes) and is marked -- READ (SELECT) or -- WRITE
-- (INSERT, UPDATE, DELETE or DDL) on the line below its id.
-- Where the app builds the text in JavaScript (the shared column lists), the text is written out in full here.
--
-- Part 1: the queries exactly as the app runs them (R1 to R8 and W1 to W15).
-- Part 2: JOIN versions (R9, R10 and W16). The app does not run these today: it uses single-table queries and keeps the
--         owner in findings.user_id and the severity totals in scans.counts. They show the JOIN form of the same
--         requests, which is what the 3NF design in 01_normalization.md would need.

-- =====================================================================
-- Part 1: queries as the app runs them
-- =====================================================================

-- ---------- Sessions and accounts (auth.js, routes/auth.js) ----------

-- R1: every signed-in request loads the user from the session cookie.
-- READ
SELECT id, email, name, created_at
FROM users
WHERE id = $1;                       -- $1 = user id from the JWT

-- W1: sign up.
-- WRITE
INSERT INTO users (email, name, password_hash)
VALUES ($1, $2, $3)
RETURNING id, email, name, created_at;   -- $1 = email (trimmed, lower case), $2 = name, $3 = bcrypt hash

-- R2: log in: find the account by email (the only query that reads password_hash).
-- READ
SELECT id, email, name, created_at, password_hash
FROM users
WHERE email = $1;                    -- $1 = email (trimmed, lower case)

-- ---------- Scans (routes/scans.js) ----------

-- R3: before starting a scan: does this user already have an unfinished scan?
-- READ
SELECT 1
FROM scans
WHERE user_id = $1
  AND status NOT IN ('done', 'failed', 'cancelled');   -- $1 = user id

-- R4: daily limit: scans started today by this user (scans that failed before any engine ran do not count).
-- READ
SELECT count(*)::int AS used
FROM scans
WHERE user_id = $1
  AND created_at >= $2
  AND NOT (status IN ('failed', 'cancelled') AND jsonb_array_length(engines) = 0);   -- $1 = user id, $2 = today 00:00 UTC

-- W2: start a scan.
-- WRITE
INSERT INTO scans (user_id, repo_url, branch)
VALUES ($1, $2, $3)
RETURNING id, user_id, repo_url, branch, commit, status, error, counts, engines, file_count, started_at, finished_at, created_at;
-- $1 = user id, $2 = repo URL, $3 = branch or NULL

-- R5: the scan list page: the user's 50 newest scans (the large files column is left out).
-- READ
SELECT id, user_id, repo_url, branch, commit, status, error, counts, engines, file_count, started_at, finished_at, created_at
FROM scans
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT 50;                            -- $1 = user id

-- R6: one scan of this user (scan page, cancel, delete and the findings list all start here).
-- READ
SELECT *
FROM scans
WHERE id = $1 AND user_id = $2;      -- $1 = scan id, $2 = user id

-- W3: cancel a scan that is not finished.
-- WRITE
UPDATE scans
SET status = 'cancelled', finished_at = now()
WHERE id = $1
  AND status NOT IN ('done', 'failed', 'cancelled')
RETURNING id, user_id, repo_url, branch, commit, status, error, counts, engines, file_count, started_at, finished_at, created_at;
-- $1 = scan id

-- W4: delete a finished scan (its findings are deleted with it, ON DELETE CASCADE).
-- WRITE
DELETE FROM scans
WHERE id = $1 AND user_id = $2;      -- $1 = scan id, $2 = user id

-- R7: the findings page: every finding of a scan, worst first, then by file and line.
-- READ
SELECT *
FROM findings
WHERE scan_id = $1
ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low'], severity), file, line NULLS FIRST;
-- $1 = scan id (already checked to belong to the user by R6)

-- ---------- Findings (routes/findings.js) ----------

-- W5: triage a finding: open, fixed or ignored (with a reason).
-- WRITE
UPDATE findings
SET status = $1, ignore_reason = $2, updated_at = now()
WHERE id = $3 AND user_id = $4
RETURNING *;                         -- $1 = status, $2 = ignore reason or NULL, $3 = finding id, $4 = user id

-- ---------- The scan worker (scanner/worker.js) ----------

-- W6: a worker picks up a queued scan.
-- WRITE
UPDATE scans
SET status = 'cloning', started_at = now()
WHERE id = $1 AND status = 'queued'
RETURNING *;                         -- $1 = scan id

-- W7: the scan moves to its next stage (scanning, saving).
-- WRITE
UPDATE scans
SET status = $2
WHERE id = $1
  AND status NOT IN ('done', 'failed', 'cancelled')
RETURNING id;                        -- $1 = scan id, $2 = new status

-- W8: an engine finished: add its entry to the scan's engines list.
-- WRITE
UPDATE scans
SET engines = engines || $2::jsonb
WHERE id = $1
  AND status NOT IN ('done', 'failed', 'cancelled')
RETURNING id;                        -- $1 = scan id, $2 = JSON array with one engine entry

-- W9: all engines finished: save the commit, the file list for the Repo Map and the file count.
-- WRITE
UPDATE scans
SET status = 'saving', commit = $2, files = $3::jsonb, file_count = $4
WHERE id = $1
  AND status NOT IN ('done', 'failed', 'cancelled')
RETURNING id;                        -- $1 = scan id, $2 = commit hash, $3 = JSON array of {path, loc}, $4 = file count

-- W10: mark the scan done and store the severity totals (runs in one transaction with W11).
-- WRITE
UPDATE scans
SET status = 'done', counts = $2::jsonb, finished_at = now()
WHERE id = $1
  AND status NOT IN ('done', 'failed', 'cancelled')
RETURNING id;                        -- $1 = scan id, $2 = JSON {"critical":n,"high":n,"medium":n,"low":n}

-- W11: save all findings of the scan with one INSERT; they arrive as a single JSON parameter.
-- WRITE
INSERT INTO findings (scan_id, user_id, engines, rule_id, title, message, severity, cwe, owasp, file, line, end_line, snippet, snippet_line, fingerprint)
SELECT $1, $2, f.engines, f."ruleId", f.title, f.message, f.severity, f.cwe, f.owasp, f.file, f.line, f."endLine", f.snippet, f."snippetLine", f.fingerprint
FROM jsonb_to_recordset($3::jsonb) AS f(engines text[], "ruleId" text, title text, message text, severity text, cwe text[], owasp text[],
                                         file text, line int, "endLine" int, snippet text, "snippetLine" int, fingerprint text);
-- $1 = scan id, $2 = user id, $3 = JSON array of findings

-- W12: the scan failed: store the error message.
-- WRITE
UPDATE scans
SET status = 'failed', error = $2, finished_at = now()
WHERE id = $1
  AND status NOT IN ('done', 'failed', 'cancelled')
RETURNING id;                        -- $1 = scan id, $2 = error message shown to the user

-- W13: on server start: every scan that was still running was cut off, so mark it failed.
-- WRITE
UPDATE scans
SET status = 'failed', error = 'The server restarted during this scan. Run it again.', finished_at = now()
WHERE status NOT IN ('done', 'failed', 'cancelled')
RETURNING id;

-- ---------- Migrations (db.js, run at every start) ----------

-- W14: the table that remembers which migration files have run.
-- WRITE
CREATE TABLE IF NOT EXISTS migrations (
    name   text PRIMARY KEY,
    run_at timestamptz NOT NULL DEFAULT now()
);

-- R8: which migrations have already run?
-- READ
SELECT name
FROM migrations;

-- W15: remember that a migration ran (in the same transaction as the migration itself).
-- WRITE
INSERT INTO migrations (name)
VALUES ($1);                         -- $1 = file name, e.g. 003_drop_roles.sql

-- =====================================================================
-- Part 2: the same requests as JOINs (not run by the app today)
-- =====================================================================

-- R9: findings page in one query: the JOIN to scans checks that the scan belongs to the user, so R6 + R7 become one
-- round trip. It returns no rows both for "not your scan" and for "scan without findings"; the app needs R6 to
-- answer 404 for the first case.
-- READ
SELECT f.*
FROM findings f
JOIN scans s ON s.id = f.scan_id
WHERE s.id = $1 AND s.user_id = $2
ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low'], f.severity), f.file, f.line NULLS FIRST;
-- $1 = scan id, $2 = user id

-- W16: triage a finding when the owner is found through its scan. This is the form W5 needs once findings.user_id is
-- removed (the 3NF design); today findings.user_id makes the check possible without a JOIN.
-- WRITE
UPDATE findings f
SET status = $1, ignore_reason = $2, updated_at = now()
FROM scans s
WHERE f.id = $3
  AND s.id = f.scan_id
  AND s.user_id = $4
RETURNING f.*;                       -- $1 = status, $2 = ignore reason or NULL, $3 = finding id, $4 = user id

-- R10: scan list with the severity totals counted from the findings (instead of the stored scans.counts column).
-- It gives the same numbers as the stored counts, because findings never change severity once saved.
-- READ
SELECT s.id, s.repo_url, s.branch, s.status, s.created_at,
       count(f.id) FILTER (WHERE f.severity = 'critical') AS critical,
       count(f.id) FILTER (WHERE f.severity = 'high')     AS high,
       count(f.id) FILTER (WHERE f.severity = 'medium')   AS medium,
       count(f.id) FILTER (WHERE f.severity = 'low')      AS low
FROM scans s
LEFT JOIN findings f ON f.scan_id = s.id
WHERE s.user_id = $1
GROUP BY s.id
ORDER BY s.created_at DESC
LIMIT 50;                            -- $1 = user id