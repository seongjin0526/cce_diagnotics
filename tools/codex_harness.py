#!/usr/bin/env python3
"""Lightweight repository harness for Codex-driven maintenance."""

from __future__ import annotations

import json
import py_compile
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


REPO_ROOT = Path(__file__).resolve().parents[1]
TRACKED_TEXT_FORBIDDEN = (
    re.compile("cl" + "aude", re.IGNORECASE),
    re.compile("anth" + "ropic", re.IGNORECASE),
)
HARD_CODED_PATHS = (
    re.compile(r"/home/seongjin0526/cce_vuln_check"),
)


@dataclass
class CheckResult:
    name: str
    ok: bool = True
    skipped: bool = False
    details: list[str] = field(default_factory=list)


def repository_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=False,
    )
    raw_paths = [chunk.decode("utf-8") for chunk in completed.stdout.split(b"\0") if chunk]
    return [REPO_ROOT / raw_path for raw_path in raw_paths]


def is_text_file(path: Path) -> bool:
    try:
        path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    return True


def scan_patterns(name: str, patterns: tuple[re.Pattern[str], ...]) -> CheckResult:
    result = CheckResult(name=name)
    for path in repository_files():
        if not path.is_file() or not is_text_file(path):
            continue
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if path.relative_to(REPO_ROOT) == Path("tools/codex_harness.py") and "re.compile(" in line:
                continue
            for pattern in patterns:
                if pattern.search(line):
                    result.ok = False
                    result.details.append(f"{path.relative_to(REPO_ROOT)}:{line_number}: {line.strip()}")
    return result


def compile_python_sources() -> CheckResult:
    result = CheckResult(name="Python compile")
    python_files = sorted(
        path
        for path in REPO_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts and ".git" not in path.parts and path.is_file()
    )
    for path in python_files:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            result.ok = False
            result.details.append(f"{path.relative_to(REPO_ROOT)}: {exc.msg}")
    if result.ok:
        result.details.append(f"{len(python_files)} files compiled")
    return result


def smoke_dashboard_import() -> CheckResult:
    result = CheckResult(name="Dashboard smoke")
    try:
        from dashboard import create_app
        from dashboard.db import create_user, fetch_one

        app = create_app({"TESTING": True, "DATABASE": str(REPO_ROOT / "instance" / "dashboard-smoke.sqlite3")})
        with app.app_context():
            if fetch_one("SELECT id FROM users WHERE username = ?", ("smoke-security",)) is None:
                create_user("smoke-security", "smoke-password", "security")
        with app.test_client() as client:
            response = client.get("/login")
            login_response = client.post(
                "/login",
                data={"username": "smoke-security", "password": "smoke-password"},
                follow_redirects=False,
            )
        if response.status_code != 200:
            result.ok = False
            result.details.append(f"/login returned {response.status_code}")
        elif login_response.status_code not in (302, 303):
            result.ok = False
            result.details.append(f"login POST returned {login_response.status_code}")
        else:
            result.details.append("/login rendered and authenticated")
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.details.append(str(exc))
    return result


def load_json_files() -> CheckResult:
    result = CheckResult(name="JSON load")
    for relative in (Path("cloud_items.json"), Path("main_items.json")):
        path = REPO_ROOT / relative
        try:
            with path.open("r", encoding="utf-8") as handle:
                json.load(handle)
        except Exception as exc:  # noqa: BLE001
            result.ok = False
            result.details.append(f"{relative}: {exc}")
    if result.ok:
        result.details.append("cloud_items.json, main_items.json")
    return result


def run_syntax_check(command: list[str], path: Path) -> tuple[bool, str]:
    completed = subprocess.run(
        command + [str(path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output


def check_shell_scripts() -> CheckResult:
    result = CheckResult(name="Shell syntax")
    shell_targets = [(REPO_ROOT / "linux_cce_check.sh", "bash")]
    sh_compatible = {"esxi_cce_check.sh", "docker_cce_check.sh", "k8s_master_cce_check.sh", "k8s_worker_cce_check.sh"}
    for path in sorted((REPO_ROOT / "scripts").glob("*.sh")):
        shell_targets.append((path, "sh" if path.name in sh_compatible else "bash"))

    for path, shell in shell_targets:
        ok, output = run_syntax_check([shell, "-n"], path)
        if not ok:
            result.ok = False
            result.details.append(f"{path.relative_to(REPO_ROOT)}: {output or 'syntax check failed'}")
    if result.ok:
        result.details.append(f"{len(shell_targets)} shell scripts checked")
    return result


def check_powershell_script() -> CheckResult:
    result = CheckResult(name="PowerShell syntax")
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    script_path = REPO_ROOT / "scripts" / "windows_cce_check.ps1"
    if powershell is None:
        result.skipped = True
        result.details.append("pwsh/powershell not installed")
        return result

    command = [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-Command",
        (
            "$errors = $null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{script_path}', [ref]$null, [ref]$errors) > $null; "
            "if ($errors.Count -gt 0) { "
            "$errors | ForEach-Object { Write-Output $_.Message }; "
            "exit 1 "
            "}"
        ),
    ]
    completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True)
    if completed.returncode != 0:
        result.ok = False
        result.details.append((completed.stdout + completed.stderr).strip() or "syntax check failed")
    else:
        result.details.append("scripts/windows_cce_check.ps1")
    return result


def check_auto_judgement_harness() -> CheckResult:
    result = CheckResult(name="Auto judgement harness")
    try:
        from dashboard.auto_judgement import apply_auto_judgement_harness

        scenarios = [
            (
                "NodeJS",
                [
                    {
                        "code": "CSAP-NodeJS-01",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "root 1 0 0 00:00:00 node /srv/app/server.js",
                    }
                ],
                "CSAP-NodeJS-01",
                "취약",
            ),
            (
                "Docker",
                [
                    {
                        "code": "CSAP-Docker-01",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "Client: Version: 27.5.1 Server: Docker Engine - Community Version: 27.5.1",
                    },
                    {
                        "code": "CSAP-Docker-02",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "docker:x:2375:",
                    },
                    {
                        "code": "CSAP-Docker-11",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "dockerd --config-file=/etc/docker/daemon.json",
                    },
                ],
                "CSAP-Docker-02",
                "양호",
            ),
            (
                "Docker",
                [
                    {
                        "code": "CSAP-Docker-01",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "Client: Version: 27.5.1 Server: Docker Engine - Community Version: 27.5.1",
                    },
                    {
                        "code": "CSAP-Docker-11",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "dockerd --config-file=/etc/docker/daemon.json",
                    },
                ],
                "CSAP-Docker-11",
                "양호",
            ),
            (
                "Elasticsearch",
                [
                    {
                        "code": "CSAP-Elasticsearch-01",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": '{"name":"es","cluster_name":"demo"}',
                    }
                ],
                "CSAP-Elasticsearch-01",
                "취약",
            ),
            (
                "Linux",
                [
                    {
                        "code": "CSAP-Linux-03 / ISMS-U-03",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "auth required pam_faillock.so deny=5 unlock_time=120",
                    },
                    {
                        "code": "CSAP-Linux-06 / ISMS-U-14",
                        "status": "수동점검",
                        "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                        "current_state": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:.",
                    },
                ],
                "CSAP-Linux-03 / ISMS-U-03",
                "양호",
            ),
        ]

        for app_key, payload, code, expected_status in scenarios:
            adjusted = apply_auto_judgement_harness(app_key, payload)
            actual = next(item for item in adjusted if item["code"] == code)
            if actual["status"] != expected_status:
                result.ok = False
                result.details.append(f"{app_key}:{code} => {actual['status']} (expected {expected_status})")

        linux_adjusted = apply_auto_judgement_harness(
            "Linux",
            [
                {
                    "code": "CSAP-Linux-06 / ISMS-U-14",
                    "status": "수동점검",
                    "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                    "current_state": "/usr/local/sbin:.:/usr/bin",
                }
            ],
        )[0]
        if linux_adjusted["status"] != "취약":
            result.ok = False
            result.details.append("Linux PATH dot rule did not mark vulnerable case")

        if result.ok:
            result.details.append("manual-to-auto fixture cases passed")
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.details.append(str(exc))
    return result


def check_mongodb_observation_harness() -> CheckResult:
    result = CheckResult(name="MongoDB observation harness")
    script_path = REPO_ROOT / "scripts" / "mongodb_cce_check.sh"
    text = script_path.read_text(encoding="utf-8")

    required_snippets = (
        'cmd="run_mongo_query \\"db.adminCommand({listDatabases:1})\\" admin; run_mongo_query \\"db.getSiblingDB(...).getCollectionNames()\\" admin"',
        'cmd="run_mongo_query \\"db.getSiblingDB(\\\'admin\\\').runCommand({usersInfo:1})\\" admin"',
        'cmd="grep -En \\"authorization|auth\\" ${MONGOD_CONF:-/etc/mongod.conf}"',
        'cmd="grep -En \\"bindIp|bindIpAll\\" ${MONGOD_CONF:-/etc/mongod.conf}"',
        'cmd="grep -En \\"systemLog|path|destination\\" ${MONGOD_CONF:-/etc/mongod.conf}"',
    )
    for snippet in required_snippets:
        if snippet not in text:
            result.ok = False
            result.details.append(f"missing expected observation command: {snippet}")

    if result.ok:
        result.details.append("manual observation commands present for MongoDB 01-04/07/08")
    return result


def check_execution_trace_harness() -> CheckResult:
    result = CheckResult(name="Execution trace harness")
    required_shell_files = [
        REPO_ROOT / "linux_cce_check.sh",
        REPO_ROOT / "scripts" / "docker_cce_check.sh",
        REPO_ROOT / "scripts" / "k8s_master_cce_check.sh",
        REPO_ROOT / "scripts" / "mongodb_cce_check.sh",
    ]
    for path in required_shell_files:
        text = path.read_text(encoding="utf-8")
        if "log_result_trace()" not in text:
            result.ok = False
            result.details.append(f"{path.relative_to(REPO_ROOT)} missing log_result_trace()")
        if "[TRACE] code=" not in text:
            result.ok = False
            result.details.append(f"{path.relative_to(REPO_ROOT)} missing [TRACE] code output")

    ps_text = (REPO_ROOT / "scripts" / "windows_cce_check.ps1").read_text(encoding="utf-8")
    if "Write-ResultTrace" not in ps_text or "[TRACE] code=" not in ps_text:
        result.ok = False
        result.details.append("scripts/windows_cce_check.ps1 missing execution trace output")

    execution_text = (REPO_ROOT / "dashboard" / "execution.py").read_text(encoding="utf-8")
    if "[실행 스크립트]" not in execution_text or "[실행 셸]" not in execution_text:
        result.ok = False
        result.details.append("dashboard/execution.py missing execution log header")

    if result.ok:
        result.details.append("trace logging present in scripts and dashboard execution header")
    return result


def print_result(result: CheckResult) -> None:
    if result.skipped:
        status = "SKIP"
    else:
        status = "OK" if result.ok else "FAIL"
    print(f"[{status}] {result.name}")
    for detail in result.details:
        print(f"  - {detail}")


def main() -> int:
    checks = [
        compile_python_sources(),
        smoke_dashboard_import(),
        load_json_files(),
        check_shell_scripts(),
        check_powershell_script(),
        check_auto_judgement_harness(),
        check_mongodb_observation_harness(),
        check_execution_trace_harness(),
        scan_patterns("Legacy AI residue scan", TRACKED_TEXT_FORBIDDEN),
        scan_patterns("Hard-coded path scan", HARD_CODED_PATHS),
    ]

    failed = False
    for check in checks:
        print_result(check)
        if not check.ok and not check.skipped:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
