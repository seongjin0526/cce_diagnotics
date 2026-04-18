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


LIVE_NOTE = "live compose lab seed"

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
    {
        "service": "mssql-lab",
        "app_key": "MS-SQL",
        "manual_paths": {
            "MSSQL_CONF": "/var/opt/mssql/mssql.conf",
        },
    },
    {
        "service": "docker-lab",
        "app_key": "Docker",
        "manual_paths": {
            "DOCKER_CONF": "/opt/cce/docker/daemon.json",
        },
    },
    {
        "service": "k3s-server-lab",
        "app_key": "K8s(Master)",
        "manual_paths": {},
    },
    {
        "service": "k3s-agent-lab",
        "app_key": "K8s(Worker)",
        "manual_paths": {},
    },
]


def wait_for_status(database: Path, table: str, run_id: int, timeout: int) -> dict:
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


def cleanup_previous_hosts(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        host_rows = connection.execute(
            "SELECT id FROM hosts WHERE notes = ?",
            (LIVE_NOTE,),
        ).fetchall()
        host_ids = [row["id"] for row in host_rows]
        if not host_ids:
            return
        placeholders = ",".join("?" for _ in host_ids)

        assessment_run_ids = [
            row["id"]
            for row in connection.execute(
                f"SELECT id FROM assessment_runs WHERE host_id IN ({placeholders})",
                tuple(host_ids),
            ).fetchall()
        ]
        if assessment_run_ids:
            assessment_placeholders = ",".join("?" for _ in assessment_run_ids)
            assessment_result_ids = [
                row["id"]
                for row in connection.execute(
                    f"SELECT id FROM assessment_results WHERE run_id IN ({assessment_placeholders})",
                    tuple(assessment_run_ids),
                ).fetchall()
            ]
            if assessment_result_ids:
                result_placeholders = ",".join("?" for _ in assessment_result_ids)
                connection.execute(
                    f"DELETE FROM exception_requests WHERE assessment_result_id IN ({result_placeholders})",
                    tuple(assessment_result_ids),
                )
                connection.execute(
                    f"DELETE FROM assessment_results WHERE id IN ({result_placeholders})",
                    tuple(assessment_result_ids),
                )
            connection.execute(
                f"DELETE FROM assessment_runs WHERE id IN ({assessment_placeholders})",
                tuple(assessment_run_ids),
            )

        discovery_run_ids = [
            row["id"]
            for row in connection.execute(
                f"SELECT id FROM discovery_runs WHERE host_id IN ({placeholders})",
                tuple(host_ids),
            ).fetchall()
        ]
        if discovery_run_ids:
            discovery_placeholders = ",".join("?" for _ in discovery_run_ids)
            connection.execute(
                f"DELETE FROM discovery_results WHERE run_id IN ({discovery_placeholders})",
                tuple(discovery_run_ids),
            )
            connection.execute(
                f"DELETE FROM discovery_runs WHERE id IN ({discovery_placeholders})",
                tuple(discovery_run_ids),
            )

        connection.execute(
            f"DELETE FROM host_app_settings WHERE host_id IN ({placeholders})",
            tuple(host_ids),
        )
        connection.execute(
            f"DELETE FROM hosts WHERE id IN ({placeholders})",
            tuple(host_ids),
        )
        connection.commit()


def login_client(client, username: str, password: str) -> None:
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    if response.status_code != 200 or response.request.path != "/":
        raise RuntimeError("login failed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed live dashboard DB with compose lab hosts and test runs")
    parser.add_argument("--database", default=str(REPO_ROOT / "instance" / "dashboard.sqlite3"))
    parser.add_argument("--username", default="security")
    parser.add_argument("--password", default="security123!")
    parser.add_argument("--startup-wait", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    database = Path(args.database)
    app = create_app({"TESTING": True, "DATABASE": str(database)})
    cleanup_previous_hosts(database)

    client = app.test_client()
    login_client(client, args.username, args.password)

    time.sleep(args.startup_wait)

    report: list[dict] = []
    for target in APP_TARGETS:
        host_form = {
            "name": f"[LAB] {target['app_key']}",
            "address": target["service"],
            "port": "22",
            "remote_user": "",
            "transport": "compose",
            "notes": LIVE_NOTE,
        }
        response = client.post("/hosts", data=host_form, follow_redirects=False)
        if response.status_code == 302 and response.headers.get("Location", "").endswith("/login"):
            login_client(client, args.username, args.password)
            response = client.post("/hosts", data=host_form, follow_redirects=False)
        if response.status_code != 302:
            raise RuntimeError(f"host registration failed for {target['service']}: {response.status_code}")
        host_id = int(response.headers["Location"].rstrip("/").split("/")[-1])

        if target["manual_paths"]:
            response = client.post(
                f"/hosts/{host_id}/settings/{quote(target['app_key'], safe='')}",
                data=target["manual_paths"],
                follow_redirects=True,
            )
            if response.request.path == "/login":
                login_client(client, args.username, args.password)
                response = client.post(
                    f"/hosts/{host_id}/settings/{quote(target['app_key'], safe='')}",
                    data=target["manual_paths"],
                    follow_redirects=True,
                )
            if response.status_code != 200:
                raise RuntimeError(f"path save failed for host {host_id}")

        response = client.post(f"/hosts/{host_id}/discover", follow_redirects=False)
        if response.status_code == 302 and response.headers.get("Location", "").endswith("/login"):
            login_client(client, args.username, args.password)
            response = client.post(f"/hosts/{host_id}/discover", follow_redirects=False)
        if response.status_code != 302:
            raise RuntimeError(f"discovery launch failed for host {host_id}")
        discovery_run_id = latest_run_id(database, "discovery_runs", host_id)
        discovery_run = wait_for_status(database, "discovery_runs", discovery_run_id, args.timeout)

        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            discovery_result = connection.execute(
                "SELECT * FROM discovery_results WHERE run_id = ? AND app_key = ?",
                (discovery_run_id, target["app_key"]),
            ).fetchone()
            settings_row = connection.execute(
                "SELECT detected_paths_json, manual_paths_json FROM host_app_settings WHERE host_id = ? AND app_key = ?",
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
        if response.status_code == 302 and response.headers.get("Location", "").endswith("/login"):
            login_client(client, args.username, args.password)
            response = client.post(
                f"/hosts/{host_id}/assess/{quote(target['app_key'], safe='')}",
                follow_redirects=False,
            )
        if response.status_code != 302:
            raise RuntimeError(f"assessment launch failed for host {host_id}")
        assessment_run_id = latest_run_id(database, "assessment_runs", host_id, target["app_key"])
        assessment_run = wait_for_status(database, "assessment_runs", assessment_run_id, args.timeout)

        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            summary_row = connection.execute(
                "SELECT summary_json, error_message FROM assessment_runs WHERE id = ?",
                (assessment_run_id,),
            ).fetchone()
            result_count = connection.execute(
                "SELECT COUNT(*) FROM assessment_results WHERE run_id = ?",
                (assessment_run_id,),
            ).fetchone()[0]
            sample_results = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT code, script_status, final_status
                    FROM assessment_results
                    WHERE run_id = ?
                    ORDER BY id
                    LIMIT 5
                    """,
                    (assessment_run_id,),
                ).fetchall()
            ]

        report.append(
            {
                "service": target["service"],
                "app_key": target["app_key"],
                "host_id": host_id,
                "discovery_status": discovery_run["status"],
                "detected": True,
                "discovery_evidence": discovery_result["evidence"],
                "detected_paths": json.loads(settings_row["detected_paths_json"]) if settings_row else {},
                "manual_paths": json.loads(settings_row["manual_paths_json"]) if settings_row else {},
                "assessment_status": assessment_run["status"],
                "result_count": result_count,
                "summary": json.loads(summary_row["summary_json"]) if summary_row and summary_row["summary_json"] else {},
                "assessment_error": summary_row["error_message"] if summary_row else "",
                "sample_results": sample_results,
            }
        )

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
