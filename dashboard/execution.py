from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass

from .catalog import get_app_definition, list_app_definitions
from project_paths import REPO_ROOT


class ExecutionError(RuntimeError):
    pass


@dataclass
class HostTarget:
    id: int
    name: str
    address: str
    port: int
    remote_user: str | None
    transport: str
    shell_type: str
    use_sudo: bool


def host_from_row(row) -> HostTarget:
    return HostTarget(
        id=row["id"],
        name=row["name"],
        address=row["address"],
        port=row["port"],
        remote_user=row["remote_user"],
        transport=row["transport"],
        shell_type=row["shell_type"],
        use_sudo=bool(row["use_sudo"]),
    )


def _build_remote_command(target: HostTarget) -> list[str]:
    if target.transport == "local":
        return ["bash", "-s", "--"]
    if target.transport == "compose":
        return [
            "docker",
            "compose",
            "-f",
            str(REPO_ROOT / "docker" / "test-lab" / "compose.yml"),
            "exec",
            "-T",
            target.address,
            "sh",
            "-lc",
            'tmp_script=$(mktemp /tmp/cce-remote.XXXXXX) && cat > "$tmp_script" && chmod +x "$tmp_script" && if command -v bash >/dev/null 2>&1; then runner=bash; else runner=sh; fi && "$runner" "$tmp_script"; status=$?; rm -f "$tmp_script"; exit $status',
        ]
    remote = target.address
    if target.remote_user:
        remote = f"{target.remote_user}@{remote}"
    return [
        "ssh",
        "-p",
        str(target.port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        remote,
        "bash",
        "-s",
        "--",
    ]


def _run_posix_script(target: HostTarget, script: str, timeout: int = 180) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        _build_remote_command(target),
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed


def _probe_script() -> str:
    lines = [
        "#!/bin/bash",
        "set +e",
        "emit_meta() { printf 'META\\t%s\\t%s\\n' \"$1\" \"$2\"; }",
        "emit_app() { printf 'APP\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }",
        "emit_path() { printf 'PATH\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }",
        "hostname_value=$(hostname 2>/dev/null || echo unknown)",
        "os_value=$(uname -s 2>/dev/null || echo unknown)",
        "kernel_value=$(uname -r 2>/dev/null || echo unknown)",
        "if [ -f /etc/os-release ]; then . /etc/os-release; os_value=${PRETTY_NAME:-$os_value}; fi",
        "emit_meta hostname \"$hostname_value\"",
        "emit_meta os \"$os_value\"",
        "emit_meta kernel \"$kernel_value\"",
    ]

    for app in list_app_definitions():
        if app.shell_family != "posix":
            continue
        lines.append('evidence=""')
        for label, command in app.probe_rules:
            lines.append(f'if {command}; then evidence="${{evidence}}{label}; "; fi')
        lines.append(f'if [ -n "$evidence" ]; then emit_app "{app.key}" "detected" "$evidence"; else emit_app "{app.key}" "not_detected" ""; fi')
        for path_setting in app.path_settings:
            lines.append("value=$(")
            for command_line in path_setting.probe_command.splitlines():
                lines.append(f"  {command_line}")
            lines.append(")")
            lines.append("value=$(printf '%s' \"$value\" | head -n 1 | tr '\\t\\r\\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//')")
            lines.append(
                f'if [ -n "$value" ]; then emit_path "{app.key}" "{path_setting.env_var}" "$value"; fi'
            )
    return "\n".join(lines) + "\n"


def discover_host(target: HostTarget) -> dict:
    if target.shell_type != "posix":
        return {
            "metadata": {"shell_type": target.shell_type},
            "applications": [],
            "raw_output": "",
            "error": "현재 구현은 POSIX 셸 탐지만 지원합니다.",
        }

    completed = _run_posix_script(target, _probe_script(), timeout=120)
    if completed.returncode != 0 and not completed.stdout:
        raise ExecutionError(completed.stderr.strip() or "원격 탐지 명령 실행 실패")

    metadata: dict[str, str] = {}
    applications: list[dict] = []
    path_hints: dict[str, dict[str, str]] = {}
    for line in completed.stdout.splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 3:
            continue
        if parts[0] == "META":
            metadata[parts[1]] = parts[2]
        elif parts[0] == "APP":
            applications.append(
                {
                    "app_key": parts[1],
                    "detected": parts[2] == "detected",
                    "evidence": parts[3] if len(parts) > 3 else "",
                }
            )
        elif parts[0] == "PATH":
            value = parts[3] if len(parts) > 3 else ""
            if value:
                path_hints.setdefault(parts[1], {})[parts[2]] = value

    return {
        "metadata": metadata,
        "applications": applications,
        "paths": path_hints,
        "raw_output": completed.stdout,
        "error": completed.stderr.strip(),
    }


def _assessment_wrapper(
    script_text: str,
    shell: str,
    use_sudo: bool,
    env_overrides: dict[str, str] | None = None,
) -> str:
    sudo_prefix = "sudo " if use_sudo else ""
    env_lines: list[str] = []
    for env_var, value in sorted((env_overrides or {}).items()):
        if value:
            env_lines.append(f"export {env_var}={shlex.quote(value)}")
    export_block = "\n".join(env_lines)
    return f"""#!/bin/bash
set +e
tmp_script=$(mktemp /tmp/cce-script.XXXXXX)
tmp_json=$(mktemp /tmp/cce-result.XXXXXX)
tmp_log=$(mktemp /tmp/cce-log.XXXXXX)
trap 'rm -f "$tmp_script" "$tmp_json" "$tmp_log"' EXIT
cat <<'__CCE_SCRIPT__' > "$tmp_script"
{script_text}
__CCE_SCRIPT__
chmod +x "$tmp_script"
{export_block}
{sudo_prefix}{shell} "$tmp_script" "$tmp_json" >"$tmp_log" 2>&1
status=$?
printf '__CCE_STATUS__=%s\\n' "$status"
printf '__CCE_LOG_BEGIN__\\n'
cat "$tmp_log"
printf '\\n__CCE_LOG_END__\\n'
printf '__CCE_JSON_BEGIN__\\n'
if [ -f "$tmp_json" ]; then cat "$tmp_json"; fi
printf '\\n__CCE_JSON_END__\\n'
exit 0
"""


def _extract_section(raw: str, start_marker: str, end_marker: str) -> str:
    start = raw.find(start_marker)
    end = raw.find(end_marker)
    if start == -1 or end == -1 or end <= start:
        return ""
    return raw[start + len(start_marker):end].strip()


def _sanitize_json_text(raw: str) -> str:
    return "".join(ch if (ord(ch) >= 32 or ch in "\t\r\n") else " " for ch in raw)


def run_assessment(
    target: HostTarget,
    app_key: str,
    env_overrides: dict[str, str] | None = None,
) -> dict:
    app = get_app_definition(app_key)
    if app is None:
        raise ExecutionError(f"알 수 없는 애플리케이션입니다: {app_key}")
    if target.shell_type != "posix" or app.shell_family != "posix":
        raise ExecutionError("현재 구현은 POSIX 대상 스크립트 실행만 지원합니다.")

    script_text = app.script_path.read_text(encoding="utf-8")
    clean_env = {key: value for key, value in (env_overrides or {}).items() if value}
    completed = _run_posix_script(
        target,
        _assessment_wrapper(script_text, app.shell, target.use_sudo, clean_env),
        timeout=900,
    )
    status_line = next((line for line in completed.stdout.splitlines() if line.startswith("__CCE_STATUS__=")), "__CCE_STATUS__=1")
    status_code = int(status_line.split("=", 1)[1])
    execution_log = _extract_section(completed.stdout, "__CCE_LOG_BEGIN__", "__CCE_LOG_END__")
    raw_json = _extract_section(completed.stdout, "__CCE_JSON_BEGIN__", "__CCE_JSON_END__")
    header_lines = [
        "[실행 스크립트]",
        str(app.script_path),
        "",
        "[실행 셸]",
        app.shell,
    ]
    if clean_env:
        header_lines.extend(["", "[환경 오버라이드]"])
        header_lines.extend(f"{key}={value}" for key, value in sorted(clean_env.items()))
    header = "\n".join(header_lines).strip()
    execution_log = f"{header}\n\n{execution_log}".strip()

    if not raw_json:
        raise ExecutionError(execution_log or completed.stderr.strip() or "진단 결과 JSON을 수신하지 못했습니다.")

    sanitized_json = _sanitize_json_text(raw_json)

    try:
        parsed = json.loads(sanitized_json)
    except json.JSONDecodeError as exc:
        raise ExecutionError(f"진단 결과 JSON 파싱 실패: {exc}") from exc

    return {
        "status_code": status_code,
        "execution_log": execution_log,
        "raw_json": sanitized_json,
        "parsed": parsed,
        "app_key": app_key,
        "script_path": str(app.script_path),
        "shell": app.shell,
        "env_overrides": clean_env,
        "stderr": completed.stderr.strip(),
    }
