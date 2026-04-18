from __future__ import annotations

import sqlite3
from datetime import datetime

from flask import current_app, g
from werkzeug.security import generate_password_hash


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('security', 'user')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    remote_user TEXT,
    transport TEXT NOT NULL CHECK(transport IN ('local', 'ssh', 'compose')),
    shell_type TEXT NOT NULL CHECK(shell_type IN ('posix', 'powershell')),
    use_sudo INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    last_discovery_status TEXT,
    last_discovery_at TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS discovery_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    initiated_by INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    metadata_json TEXT,
    raw_output TEXT,
    error_message TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(initiated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS discovery_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    app_key TEXT NOT NULL,
    detected INTEGER NOT NULL,
    evidence TEXT,
    FOREIGN KEY(run_id) REFERENCES discovery_runs(id)
);

CREATE TABLE IF NOT EXISTS host_app_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    app_key TEXT NOT NULL,
    detected_paths_json TEXT NOT NULL DEFAULT '{}',
    manual_paths_json TEXT NOT NULL DEFAULT '{}',
    last_detected_at TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(host_id, app_key),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS assessment_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    app_key TEXT NOT NULL,
    initiated_by INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    executed_script_path TEXT,
    executed_shell TEXT,
    framework_scope TEXT,
    raw_result_json TEXT,
    summary_json TEXT,
    execution_log TEXT,
    error_message TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(initiated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS assessment_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    category TEXT,
    title TEXT,
    importance TEXT,
    source TEXT,
    framework_tags TEXT,
    diagnosis TEXT,
    detail TEXT,
    command TEXT,
    current_state TEXT,
    remediation TEXT,
    script_status TEXT NOT NULL,
    final_status TEXT,
    status_note TEXT,
    FOREIGN KEY(run_id) REFERENCES assessment_runs(id)
);

CREATE TABLE IF NOT EXISTS exception_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_result_id INTEGER NOT NULL,
    requested_by INTEGER NOT NULL,
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    approver_id INTEGER,
    decided_at TEXT,
    approver_comment TEXT,
    FOREIGN KEY(assessment_result_id) REFERENCES assessment_results(id),
    FOREIGN KEY(requested_by) REFERENCES users(id),
    FOREIGN KEY(approver_id) REFERENCES users(id)
);
"""


def utcnow() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat(sep=" ")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    connection = get_db()
    connection.executescript(SCHEMA)
    _migrate_hosts_transport_constraint(connection)
    connection.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)


def execute(query: str, params: tuple = ()) -> sqlite3.Cursor:
    cursor = get_db().execute(query, params)
    get_db().commit()
    return cursor


def fetch_one(query: str, params: tuple = ()):
    return get_db().execute(query, params).fetchone()


def fetch_all(query: str, params: tuple = ()):
    return get_db().execute(query, params).fetchall()


def ensure_schema() -> None:
    connection = sqlite3.connect(current_app.config["DATABASE"])
    connection.executescript(SCHEMA)
    _migrate_hosts_transport_constraint(connection)
    connection.commit()
    connection.close()


def _migrate_hosts_transport_constraint(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'hosts'"
    ).fetchone()
    if row is None or row[0] is None or "'compose'" in row[0]:
        return
    connection.executescript(
        """
        PRAGMA foreign_keys=OFF;
        ALTER TABLE hosts RENAME TO hosts_old;
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            remote_user TEXT,
            transport TEXT NOT NULL CHECK(transport IN ('local', 'ssh', 'compose')),
            shell_type TEXT NOT NULL CHECK(shell_type IN ('posix', 'powershell')),
            use_sudo INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            last_discovery_status TEXT,
            last_discovery_at TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        INSERT INTO hosts (
            id, name, address, port, remote_user, transport, shell_type, use_sudo,
            notes, last_discovery_status, last_discovery_at, created_by, created_at
        )
        SELECT
            id, name, address, port, remote_user, transport, shell_type, use_sudo,
            notes, last_discovery_status, last_discovery_at, created_by, created_at
        FROM hosts_old;
        DROP TABLE hosts_old;
        PRAGMA foreign_keys=ON;
        """
    )


def create_user(username: str, password: str, role: str) -> None:
    execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, generate_password_hash(password), role, utcnow()),
    )
