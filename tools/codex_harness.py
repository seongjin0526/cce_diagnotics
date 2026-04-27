#!/usr/bin/env python3
"""Lightweight repository harness for Codex-driven maintenance."""

from __future__ import annotations

import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
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

        docker_root_only = apply_auto_judgement_harness(
            "Docker",
            [
                {
                    "code": "CSAP-Docker-02",
                    "status": "수동점검",
                    "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                    "current_state": "docker:x:2375:root\nroot:x:0:",
                }
            ],
        )[0]
        if docker_root_only["status"] != "양호":
            result.ok = False
            result.details.append("Docker group root-only rule did not mark good case")

        docker_extra_member = apply_auto_judgement_harness(
            "Docker",
            [
                {
                    "code": "CSAP-Docker-02",
                    "status": "수동점검",
                    "detail": "명령 실행 결과 확인. 수동 검증 필요.",
                    "current_state": "docker:x:2375:alice\nroot:x:0:",
                }
            ],
        )[0]
        if docker_extra_member["status"] != "취약":
            result.ok = False
            result.details.append("Docker group extra-member rule did not mark vulnerable case")

        if result.ok:
            result.details.append("manual-to-auto fixture cases passed")
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.details.append(str(exc))
    return result


def check_docker_generation_harness() -> CheckResult:
    result = CheckResult(name="Docker generation harness")
    script_path = REPO_ROOT / "scripts" / "docker_cce_check.sh"
    text = script_path.read_text(encoding="utf-8")

    required_snippets = (
        'cmd="cat /etc/group | grep docker; cat /etc/group | grep root"',
        'extra_members=$(printf',
        'audit_target="/usr/bin/docker"',
        'audit_target="/var/lib/docker"',
        'audit_target="/etc/docker"',
        'audit_target="/lib/systemd/system/docker.service"',
        'audit_target="/lib/systemd/system/docker.socket"',
        'audit_target="/etc/default/docker"',
        'cur_state="${output:-감사 규칙 없음}"',
    )
    for snippet in required_snippets:
        if snippet not in text:
            result.ok = False
            result.details.append(f"missing expected Docker generated logic: {snippet}")

    if result.ok:
        result.details.append("Docker group and audit auto-verdict logic present")
    return result


def check_k8s_runtime_harness() -> CheckResult:
    result = CheckResult(name="Kubernetes runtime harness")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            manifests = base / "manifests"
            manifests.mkdir()
            encryption_config = base / "encryption.yaml"
            encryption_config.write_text(
                "\n".join(
                    [
                        "resources:",
                        "- resources: [secrets]",
                        "  providers:",
                        "  - aescbc:",
                        "      keys:",
                        "      - name: key1",
                        "        secret: abc",
                    ]
                ),
                encoding="utf-8",
            )
            (manifests / "kube-apiserver.yaml").write_text(
                "\n".join(
                    [
                        "spec:",
                        "  containers:",
                        "  - command:",
                        "    - kube-apiserver",
                        "    - --anonymous-auth=false",
                        "    - --service-account-lookup=true",
                        "    - --authorization-mode=Node,RBAC",
                        "    - --enable-admission-plugins=NodeRestriction,PodSecurity",
                        "    - --secure-port=6443",
                        "    - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt",
                        "    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt",
                        "    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key",
                        "    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt",
                        "    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key",
                        "    - --client-ca-file=/etc/kubernetes/pki/ca.crt",
                        "    - --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "    - --audit-log-path=/var/log/kubernetes/audit.log",
                        "    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml",
                        "    - --audit-log-maxage=30",
                        "    - --audit-log-maxbackup=10",
                        "    - --audit-log-maxsize=100",
                        f"    - --encryption-provider-config={encryption_config}",
                        "    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt",
                        "    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key",
                        "    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt",
                    ]
                ),
                encoding="utf-8",
            )
            (manifests / "kube-scheduler.yaml").write_text(
                "spec:\n  containers:\n  - command:\n    - kube-scheduler\n    - --bind-address=127.0.0.1\n",
                encoding="utf-8",
            )
            (manifests / "kube-controller-manager.yaml").write_text(
                "\n".join(
                    [
                        "spec:",
                        "  containers:",
                        "  - command:",
                        "    - kube-controller-manager",
                        "    - --bind-address=127.0.0.1",
                        "    - --use-service-account-credentials=true",
                        "    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key",
                        "    - --root-ca-file=/etc/kubernetes/pki/ca.crt",
                        "    - --feature-gates=RotateKubeletServerCertificate=true",
                    ]
                ),
                encoding="utf-8",
            )
            (manifests / "etcd.yaml").write_text(
                "\n".join(
                    [
                        "spec:",
                        "  containers:",
                        "  - command:",
                        "    - etcd",
                        "    - --client-cert-auth=true",
                        "    - --peer-client-cert-auth=true",
                        "    - --cert-file=/etc/kubernetes/pki/etcd/server.crt",
                        "    - --key-file=/etc/kubernetes/pki/etcd/server.key",
                        "    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
                        "    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
                        "    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                        "    - --auto-tls=false",
                        "    - --peer-auto-tls=false",
                    ]
                ),
                encoding="utf-8",
            )

            master_output = base / "master.json"
            master_env = os.environ.copy()
            master_env["K8S_MANIFEST_DIR"] = str(manifests)
            master_run = subprocess.run(
                ["sh", str(REPO_ROOT / "scripts" / "k8s_master_cce_check.sh"), str(master_output)],
                cwd=REPO_ROOT,
                env=master_env,
                capture_output=True,
                text=True,
            )
            if master_run.returncode != 0:
                result.ok = False
                result.details.append(f"k8s master fixture failed: {(master_run.stdout + master_run.stderr).strip()}")
            else:
                master_data = json.loads(master_output.read_text(encoding="utf-8"))
                master_status = {
                    item["code"]: item["status"]
                    for item in master_data["results"]
                    if item["code"].startswith("CSAP-K8sMaster-")
                }
                for number in range(1, 12):
                    code = f"CSAP-K8sMaster-{number:02d}"
                    if master_status.get(code) != "양호":
                        result.ok = False
                        result.details.append(f"{code} => {master_status.get(code)} (expected 양호)")

            kubelet_config = base / "kubelet-config.yaml"
            kubelet_service = base / "10-kubeadm.conf"
            kubelet_config.write_text(
                "\n".join(
                    [
                        "anonymous:",
                        "  enabled: false",
                        "readOnlyPort: 0",
                        "authorization:",
                        "  mode: Webhook",
                        "clientCAFile: /etc/kubernetes/pki/ca.crt",
                        "serverTLSBootstrap: true",
                        "rotateCertificates: true",
                        "tlsCipherSuites:",
                        "- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "protectKernelDefaults: true",
                    ]
                ),
                encoding="utf-8",
            )
            kubelet_service.write_text('Environment="KUBELET_EXTRA_ARGS=--read-only-port=0"\n', encoding="utf-8")
            worker_output = base / "worker.json"
            worker_env = os.environ.copy()
            worker_env["KUBELET_CONF"] = str(kubelet_config)
            worker_env["KUBELET_SERVICE_CONF"] = str(kubelet_service)
            worker_run = subprocess.run(
                ["sh", str(REPO_ROOT / "scripts" / "k8s_worker_cce_check.sh"), str(worker_output)],
                cwd=REPO_ROOT,
                env=worker_env,
                capture_output=True,
                text=True,
            )
            if worker_run.returncode != 0:
                result.ok = False
                result.details.append(f"k8s worker fixture failed: {(worker_run.stdout + worker_run.stderr).strip()}")
            else:
                worker_data = json.loads(worker_output.read_text(encoding="utf-8"))
                worker_status = {
                    item["code"]: item["status"]
                    for item in worker_data["results"]
                    if item["code"].startswith("CSAP-K8sWorker-")
                }
                for number in range(1, 5):
                    code = f"CSAP-K8sWorker-{number:02d}"
                    if worker_status.get(code) != "양호":
                        result.ok = False
                        result.details.append(f"{code} => {worker_status.get(code)} (expected 양호)")

        if result.ok:
            result.details.append("K8s master 01-11 and worker 01-04 fixture runs passed")
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
        'grep -Ein "authorization|auth" "$MONGOD_CONF"',
        'grep -Ein "bindIp|bindIpAll" "$MONGOD_CONF"',
        'grep -Ein "systemLog|path|destination" "$MONGOD_CONF"',
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


def _decode_generated_assignment(raw: str, *, powershell: bool = False) -> str:
    if powershell:
        decoded = raw.replace('`"', '"').replace('`$', '$').replace('``', '`')
    else:
        decoded = raw.replace('\\"', '"').replace('\\$', '$').replace('\\\\', '\\')
    return re.sub(r"\s+", " ", decoded).strip()


def _normalize_generated_command(command: str) -> str:
    from generate_scripts import normalize_guide_command_for_display

    return normalize_guide_command_for_display(command.replace("\\$", "$"))


def _extract_generated_command_assignments(path: Path, *, powershell: bool = False) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    commands: dict[str, str] = {}
    current_code = ""
    assignments: list[str] = []

    comment_re = re.compile(r"^#\s+([^:\n]+):") if not powershell else re.compile(r"^#\s+([^:\n]+):")
    assignment_re = (
        re.compile(r'^\s*\$cmd\s*=\s*"((?:[^"`]|`.)*)"')
        if powershell
        else re.compile(r'^\s*(?:local\s+)?cmd="((?:[^"\\]|\\.)*)"')
    )
    end_re = re.compile(r"^\s*}\s*$")

    for line in text.splitlines():
        comment_match = comment_re.match(line)
        if comment_match:
            current_code = comment_match.group(1).strip()
            assignments = []
            continue
        if current_code:
            assignment_match = assignment_re.match(line)
            if assignment_match:
                assignments.append(_decode_generated_assignment(assignment_match.group(1), powershell=powershell))
            if "add_result " in line or "Add-Result " in line or end_re.match(line):
                if assignments:
                    commands[current_code] = assignments[-1]
                if end_re.match(line):
                    current_code = ""
                    assignments = []

    return commands


def check_guide_command_source_harness() -> CheckResult:
    result = CheckResult(name="Guide command source harness")
    try:
        from generate_scripts import (
            APP_DEFS,
            extract_commands_from_diagnosis,
            is_state_changing_command,
            read_excel_items,
        )

        items_by_target = read_excel_items()
        checked_scripts = 0
        checked_items = 0
        guide_command_items = 0

        for app_key, app_def in APP_DEFS.items():
            script_path = REPO_ROOT / "scripts" / app_def["script"]
            if not script_path.exists():
                continue
            checked_scripts += 1
            generated = _extract_generated_command_assignments(script_path, powershell=bool(app_def.get("powershell")))
            for item in items_by_target.get(app_key, []):
                code = item["code"]
                actual = generated.get(code)
                if actual is None:
                    result.ok = False
                    result.details.append(f"{script_path.relative_to(REPO_ROOT)}:{code}: generated command field missing")
                    continue

                checked_items += 1
                normalized_actual = _normalize_generated_command(actual)
                if is_state_changing_command(normalized_actual):
                    result.ok = False
                    result.details.append(
                        f"{script_path.relative_to(REPO_ROOT)}:{code}: diagnostic command contains remediation/state-changing work: {actual}"
                    )

                guide_commands = extract_commands_from_diagnosis(item["diagnosis"])
                if not guide_commands:
                    continue
                guide_command_items += 1
                expected = _normalize_generated_command("; ".join(guide_commands[:3]))
                if normalized_actual != expected:
                    result.ok = False
                    result.details.append(
                        f"{script_path.relative_to(REPO_ROOT)}:{code}: generated command differs from guide command. "
                        f"expected={expected!r} actual={normalized_actual!r}"
                    )

        if result.ok:
            result.details.append(
                "Guide command source of truth enforced: generated command fields match workbook guide diagnosis commands."
            )
            result.details.append(
                "Guide command source of truth enforced again: remediation/state-changing commands are rejected as diagnostics."
            )
            result.details.append(
                f"Guide command source of truth rechecked across {checked_scripts} generated scripts, "
                f"{checked_items} items, {guide_command_items} guide-command items."
            )
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.details.append(str(exc))
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
        check_docker_generation_harness(),
        check_k8s_runtime_harness(),
        check_mongodb_observation_harness(),
        check_execution_trace_harness(),
        check_guide_command_source_harness(),
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
