#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard import create_app
from dashboard.db import create_user


APP_TARGETS = [
    {
        "service": "apache-lab",
        "app_key": "Apache",
        "manual_paths": {"APACHE_CONF": "/usr/local/apache2/conf/httpd.conf"},
    },
    {
        "service": "nginx-lab",
        "app_key": "Nginx",
        "manual_paths": {"NGINX_CONF": "/opt/cce/nginx/nginx.conf"},
    },
    {
        "service": "tomcat-lab",
        "app_key": "Tomcat",
        "manual_paths": {},
    },
    {
        "service": "php-lab",
        "app_key": "PHP",
        "manual_paths": {"PHP_INI": "/opt/cce/php/php.ini"},
    },
    {
        "service": "nodejs-lab",
        "app_key": "NodeJS",
        "manual_paths": {},
    },
    {
        "service": "mysql-lab",
        "app_key": "MY-SQL",
        "manual_paths": {"MYSQL_CONF": "/opt/cce/mysql/my.cnf"},
    },
    {
        "service": "postgresql-lab",
        "app_key": "PostgreSQL",
        "manual_paths": {
            "PG_DATA": "/opt/cce/postgresql/data",
            "PG_CONF": "/opt/cce/postgresql/data/postgresql.conf",
        },
    },
    {
        "service": "redis-lab",
        "app_key": "Redis",
        "manual_paths": {"REDIS_CONF": "/opt/cce/redis/redis.conf"},
    },
    {
        "service": "mongodb-lab",
        "app_key": "MongoDB",
        "manual_paths": {"MONGOD_CONF": "/opt/cce/mongodb/mongod.conf"},
    },
    {
        "service": "elasticsearch-lab",
        "app_key": "Elasticsearch",
        "manual_paths": {
            "ES_CONF": "/usr/share/elasticsearch/config/elasticsearch.yml",
            "ES_URL": "http://localhost:9200",
        },
    },
]


def wait_for_status(
    database: Path,
    table: str,
    run_id: int,
    timeout: int,
) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(f"SELECT * FROM {table} WHERE id = ?", (run_id,)).fetchone()
            if row and row["status"] not in {"queued", "running"}:
                return dict(row)
        time.sleep(1)
    raise TimeoutError(f"{table} #{run_id} did not finish within {timeout}s")


def latest_run_id(database: Path, table: str, host_id: int, app_key: str | None = None) -> int:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if app_key is None:
            row = connection.execute(
                f"SELECT id FROM {table} WHERE host_id = ? ORDER BY id DESC LIMIT 1",
                (host_id,),
            ).fetchone()
        else:
            row = connection.execute(
                f"SELECT id FROM {table} WHERE host_id = ? AND app_key = ? ORDER BY id DESC LIMIT 1",
                (host_id, app_key),
            ).fetchone()
    if row is None:
        raise RuntimeError(f"no {table} run found for host {host_id}")
    return int(row["id"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Register compose lab hosts and run discovery/assessment via dashboard routes")
    parser.add_argument("--database", default="/tmp/dashboard-compose-lab.sqlite3")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--startup-wait", type=int, default=10)
    args = parser.parse_args()

    database = Path(args.database)
    database.unlink(missing_ok=True)
    app = create_app({"TESTING": True, "DATABASE": str(database), "SECRET_KEY": "compose-lab-test"})

    with app.app_context():
        create_user("security", "security123!", "security")

    client = app.test_client()
    login_response = client.post(
        "/login",
        data={"username": "security", "password": "security123!"},
        follow_redirects=True,
    )
    if login_response.status_code != 200:
        raise RuntimeError("login failed")

    time.sleep(args.startup_wait)

    report: list[dict] = []
    for target in APP_TARGETS:
        host_name = f"{target['service']}-{target['app_key']}"
        response = client.post(
            "/hosts",
            data={
                "name": host_name,
                "address": target["service"],
                "port": "22",
                "remote_user": "",
                "transport": "compose",
                "notes": "compose lab api smoke",
            },
            follow_redirects=False,
        )
        if response.status_code != 302:
            raise RuntimeError(f"host registration failed for {host_name}: {response.status_code}")
        host_id = int(response.headers["Location"].rstrip("/").split("/")[-1])

        if target["manual_paths"]:
            response = client.post(
                f"/hosts/{host_id}/settings/{quote(target['app_key'], safe='')}",
                data=target["manual_paths"],
                follow_redirects=True,
            )
            if response.status_code != 200:
                raise RuntimeError(f"manual path save failed for {host_name}")

        response = client.post(f"/hosts/{host_id}/discover", follow_redirects=False)
        if response.status_code != 302:
            raise RuntimeError(f"discovery launch failed for {host_name}")
        discovery_run_id = latest_run_id(database, "discovery_runs", host_id)
        discovery_run = wait_for_status(database, "discovery_runs", discovery_run_id, args.timeout)

        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            discovery_result = connection.execute(
                """
                SELECT * FROM discovery_results
                WHERE run_id = ? AND app_key = ?
                """,
                (discovery_run_id, target["app_key"]),
            ).fetchone()
            settings_row = connection.execute(
                """
                SELECT detected_paths_json, manual_paths_json
                FROM host_app_settings
                WHERE host_id = ? AND app_key = ?
                """,
                (host_id, target["app_key"]),
            ).fetchone()

        if discovery_result is None or not int(discovery_result["detected"]):
            report.append(
                {
                    "service": target["service"],
                    "app_key": target["app_key"],
                    "host_id": host_id,
                    "discovery_status": discovery_run["status"],
                    "detected": False,
                    "discovery_error": discovery_run.get("error_message"),
                }
            )
            continue

        response = client.post(
            f"/hosts/{host_id}/assess/{quote(target['app_key'], safe='')}",
            follow_redirects=False,
        )
        if response.status_code != 302:
            raise RuntimeError(f"assessment launch failed for {host_name}")
        assessment_run_id = latest_run_id(database, "assessment_runs", host_id, target["app_key"])
        assessment_run = wait_for_status(database, "assessment_runs", assessment_run_id, args.timeout)

        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            summary_row = connection.execute(
                "SELECT summary_json, error_message, execution_log FROM assessment_runs WHERE id = ?",
                (assessment_run_id,),
            ).fetchone()
            result_count = connection.execute(
                "SELECT COUNT(*) AS count FROM assessment_results WHERE run_id = ?",
                (assessment_run_id,),
            ).fetchone()["count"]
            sample_rows = connection.execute(
                """
                SELECT code, script_status, final_status
                FROM assessment_results
                WHERE run_id = ?
                ORDER BY id
                LIMIT 5
                """,
                (assessment_run_id,),
            ).fetchall()

        report.append(
            {
                "service": target["service"],
                "app_key": target["app_key"],
                "host_id": host_id,
                "discovery_status": discovery_run["status"],
                "detected": True,
                "discovery_evidence": discovery_result["evidence"],
                "detected_paths": json.loads(settings_row["detected_paths_json"]) if settings_row and settings_row["detected_paths_json"] else {},
                "manual_paths": json.loads(settings_row["manual_paths_json"]) if settings_row and settings_row["manual_paths_json"] else {},
                "assessment_status": assessment_run["status"],
                "result_count": int(result_count),
                "summary": json.loads(summary_row["summary_json"]) if summary_row and summary_row["summary_json"] else {},
                "assessment_error": summary_row["error_message"] if summary_row else None,
                "sample_results": [dict(row) for row in sample_rows],
            }
        )

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
