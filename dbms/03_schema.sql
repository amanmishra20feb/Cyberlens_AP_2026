-- Cyberlens database schema (team T0028).
-- Final state of backend/migrations 001_init.sql + 002_drop_large_repo_columns.sql + 003_drop_roles.sql.
-- Runs on PostgreSQL 13 or newer (gen_random_uuid() is built in). Re-runnable: drops and recreates the three tables.
-- Deletes all data in these tables. Run it only on an empty or test database, never on the production database.

DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS scans CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text        NOT NULL UNIQUE,
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scans (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    repo_url    text        NOT NULL,
    branch      text,
    commit      text,
    status      text        NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'cloning', 'scanning', 'saving', 'done', 'failed', 'cancelled')),
    error       text,
    -- findings per severity, kept next to the scan so the scan list needs no count query
    counts      jsonb       NOT NULL DEFAULT '{"critical":0,"high":0,"medium":0,"low":0}',
    -- one entry per engine: {name, ok, count | error, ms}
    engines     jsonb       NOT NULL DEFAULT '[]',
    -- largest files of the repo for the Repo Map: [{path, loc}]
    files       jsonb       NOT NULL DEFAULT '[]',
    file_count  integer,
    started_at  timestamptz,
    finished_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    engines       text[]      NOT NULL DEFAULT '{}',
    rule_id       text,
    title         text,
    message       text,
    severity      text        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    cwe           text[]      NOT NULL DEFAULT '{}',
    owasp         text[]      NOT NULL DEFAULT '{}',
    file          text        NOT NULL,
    line          integer,
    end_line      integer,
    snippet       text,
    snippet_line  integer,
    fingerprint   text        NOT NULL,
    status        text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored')),
    ignore_reason text        CHECK (ignore_reason IN ('false_positive', 'acceptable_risk', 'no_time')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_id, fingerprint)
);

-- Indexes used by the app
CREATE INDEX scans_user_created ON scans (user_id, created_at DESC);
-- a user can have only one scan in progress
CREATE UNIQUE INDEX scans_one_running_per_user ON scans (user_id)
    WHERE status IN ('queued', 'cloning', 'scanning', 'saving');
CREATE INDEX findings_user ON findings (user_id);
