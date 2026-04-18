from __future__ import annotations

import json
import threading

from code_scheme import to_preferred_code_text


def launch_discovery(app, host_id: int, run_id: int) -> None:
    thread = threading.Thread(
        target=_discovery_worker,
        args=(app, host_id, run_id),
        name=f"discovery-{run_id}",
        daemon=True,
    )
    thread.start()


def launch_assessment(app, host_id: int, run_id: int, app_key: str) -> None:
    thread = threading.Thread(
        target=_assessment_worker,
        args=(app, host_id, run_id, app_key),
        name=f"assessment-{run_id}",
        daemon=True,
    )
    thread.start()


def _discovery_worker(app, host_id: int, run_id: int) -> None:
    from .catalog import list_app_definitions
    from .db import execute, fetch_one, utcnow
    from .execution import discover_host, host_from_row

    with app.app_context():
        execute("UPDATE discovery_runs SET status = ? WHERE id = ?", ("running", run_id))
        execute(
            "UPDATE hosts SET last_discovery_status = ?, last_discovery_at = ? WHERE id = ?",
            ("running", utcnow(), host_id),
        )
        host = fetch_one("SELECT * FROM hosts WHERE id = ?", (host_id,))

        try:
            payload = discover_host(host_from_row(host))
            execute(
                """
                UPDATE discovery_runs
                   SET completed_at = ?, status = ?, metadata_json = ?, raw_output = ?, error_message = ?
                 WHERE id = ?
                """,
                (
                    utcnow(),
                    "completed" if not payload["error"] else "completed_with_warning",
                    json.dumps(payload["metadata"], ensure_ascii=False),
                    payload["raw_output"],
                    payload["error"],
                    run_id,
                ),
            )
            for item in payload["applications"]:
                execute(
                    "INSERT INTO discovery_results (run_id, app_key, detected, evidence) VALUES (?, ?, ?, ?)",
                    (run_id, item["app_key"], 1 if item["detected"] else 0, item["evidence"]),
                )
            discovered_at = utcnow()
            path_hints = payload.get("paths", {})
            for app_definition in list_app_definitions():
                if not app_definition.path_settings:
                    continue
                existing = fetch_one(
                    "SELECT manual_paths_json FROM host_app_settings WHERE host_id = ? AND app_key = ?",
                    (host_id, app_definition.key),
                )
                execute(
                    """
                    INSERT INTO host_app_settings
                        (host_id, app_key, detected_paths_json, manual_paths_json, last_detected_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(host_id, app_key) DO UPDATE SET
                        detected_paths_json = excluded.detected_paths_json,
                        manual_paths_json = excluded.manual_paths_json,
                        last_detected_at = excluded.last_detected_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        host_id,
                        app_definition.key,
                        json.dumps(path_hints.get(app_definition.key, {}), ensure_ascii=False),
                        existing["manual_paths_json"] if existing else "{}",
                        discovered_at,
                        discovered_at,
                    ),
                )
            execute(
                "UPDATE hosts SET last_discovery_status = ?, last_discovery_at = ? WHERE id = ?",
                ("completed", utcnow(), host_id),
            )
        except Exception as exc:  # noqa: BLE001
            execute(
                "UPDATE discovery_runs SET completed_at = ?, status = ?, error_message = ? WHERE id = ?",
                (utcnow(), "failed", str(exc), run_id),
            )
            execute(
                "UPDATE hosts SET last_discovery_status = ?, last_discovery_at = ? WHERE id = ?",
                ("failed", utcnow(), host_id),
            )


def _assessment_worker(app, host_id: int, run_id: int, app_key: str) -> None:
    from .auto_judgement import apply_auto_judgement_harness
    from .catalog import get_control, serialize_frameworks
    from .db import execute, fetch_one, utcnow
    from .execution import run_assessment, host_from_row

    with app.app_context():
        execute("UPDATE assessment_runs SET status = ? WHERE id = ?", ("running", run_id))
        host = fetch_one("SELECT * FROM hosts WHERE id = ?", (host_id,))
        settings_row = fetch_one(
            "SELECT detected_paths_json, manual_paths_json FROM host_app_settings WHERE host_id = ? AND app_key = ?",
            (host_id, app_key),
        )

        try:
            detected_paths = json.loads(settings_row["detected_paths_json"]) if settings_row and settings_row["detected_paths_json"] else {}
            manual_paths = json.loads(settings_row["manual_paths_json"]) if settings_row and settings_row["manual_paths_json"] else {}
            env_overrides = {key: value for key, value in {**detected_paths, **manual_paths}.items() if value}
            payload = run_assessment(host_from_row(host), app_key, env_overrides=env_overrides)
            adjusted_results = apply_auto_judgement_harness(app_key, payload["parsed"].get("results", []))
            summary = {
                "total": len(adjusted_results),
                "양호": sum(1 for result in adjusted_results if result.get("status") == "양호"),
                "취약": sum(1 for result in adjusted_results if result.get("status") == "취약"),
                "N/A": sum(1 for result in adjusted_results if result.get("status") == "N/A"),
                "수동점검": sum(1 for result in adjusted_results if result.get("status") == "수동점검"),
            }
            execute(
                """
                UPDATE assessment_runs
                   SET completed_at = ?, status = ?, executed_script_path = ?, executed_shell = ?,
                       framework_scope = ?, raw_result_json = ?, summary_json = ?, execution_log = ?, error_message = ?
                 WHERE id = ?
                """,
                (
                    utcnow(),
                    "completed" if payload["status_code"] == 0 else "completed_with_warning",
                    payload["script_path"],
                    payload["shell"],
                    "공공CSAP + ISMS-P",
                    payload["raw_json"],
                    json.dumps(summary, ensure_ascii=False),
                    payload["execution_log"],
                    payload["stderr"],
                    run_id,
                ),
            )
            for result in adjusted_results:
                result_code = to_preferred_code_text(result.get("code", ""))
                control = get_control(app_key, result_code) or get_control(app_key, result.get("code", "")) or {}
                execute(
                    """
                    INSERT INTO assessment_results
                        (run_id, code, category, title, importance, source, framework_tags, diagnosis,
                         detail, command, current_state, remediation, script_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        result_code,
                        result.get("category"),
                        result.get("title"),
                        result.get("importance"),
                        result.get("source"),
                        serialize_frameworks(control.get("frameworks", [])),
                        control.get("diagnosis", ""),
                        result.get("detail"),
                        result.get("command"),
                        result.get("current_state"),
                        result.get("remediation"),
                        result.get("status"),
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            execute(
                "UPDATE assessment_runs SET completed_at = ?, status = ?, error_message = ? WHERE id = ?",
                (utcnow(), "failed", str(exc), run_id),
            )
