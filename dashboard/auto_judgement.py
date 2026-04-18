from __future__ import annotations

import re
from copy import deepcopy

MANUAL_STATUS = "수동점검"


def _normalize_text(value: str | None) -> str:
    return (value or "").replace("\\(", "(").replace("\\)", ")").strip()


def _parse_version(text: str | None) -> tuple[int, ...] | None:
    if not text:
        return None
    match = re.search(r"(?:Version:|version[:= ]+|db version v)(\d+(?:\.\d+){1,3})", text, re.IGNORECASE)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _extract_first_number(text: str | None, pattern: str) -> int | None:
    if not text:
        return None
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def _build_context(results: list[dict]) -> dict:
    context = {
        "by_code": {},
        "docker_version": None,
    }
    for result in results:
        normalized_code = _normalize_text(result.get("code"))
        context["by_code"][normalized_code] = result
        if normalized_code == "CSAP-Docker-01":
            context["docker_version"] = _parse_version(result.get("current_state"))
    return context


def _auto_decision(status: str, reason: str, detail: str | None) -> tuple[str, str]:
    detail_text = (detail or "").strip()
    if detail_text:
        detail_text = f"{detail_text} 자동판정: {reason}"
    else:
        detail_text = f"자동판정: {reason}"
    return status, detail_text


def _decide_node_process(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state"))
    if not current_state:
        return None
    if "node" not in current_state.lower():
        return None
    if re.search(r"(^|\s)root\s+\d+", current_state):
        return _auto_decision("취약", "node 프로세스가 root 권한으로 실행 중입니다.", result.get("detail"))
    if re.search(r"(^|\n)\S+\s+\d+.*\bnode\b", current_state):
        return _auto_decision("양호", "node 프로세스가 root 이외 계정으로 실행 중입니다.", result.get("detail"))
    return None


def _decide_docker_group(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state"))
    if not current_state.startswith("docker:"):
        return None
    parts = current_state.split(":", 3)
    if len(parts) < 4:
        return None
    members = parts[3].strip()
    if not members:
        return _auto_decision("양호", "docker 그룹에 추가 사용자가 없습니다.", result.get("detail"))
    return _auto_decision("취약", f"docker 그룹에 사용자({members})가 포함되어 있습니다.", result.get("detail"))


def _decide_docker_bridge(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state")).lower()
    if not current_state:
        return None
    if "--icc=false" in current_state or "enable_icc':false" in current_state or "enable_icc\":false" in current_state or "enable_icc=false" in current_state:
        return _auto_decision("양호", "컨테이너 간 통신 제한 옵션이 적용되어 있습니다.", result.get("detail"))
    if "--icc=true" in current_state or "enable_icc':true" in current_state or "enable_icc\":true" in current_state or "enable_icc=true" in current_state:
        return _auto_decision("취약", "컨테이너 간 통신 제한 옵션이 비활성화되어 있습니다.", result.get("detail"))
    return None


def _decide_docker_legacy_registry(result: dict, context: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state")).lower()
    if "--disable-legacy-registry=false" in current_state:
        return _auto_decision("취약", "legacy registry v1 사용 옵션이 명시적으로 활성화되어 있습니다.", result.get("detail"))
    if "--disable-legacy-registry" in current_state:
        return _auto_decision("양호", "legacy registry v1 비활성화 옵션이 확인되었습니다.", result.get("detail"))
    version = context.get("docker_version")
    if version and version >= (17, 12):
        return _auto_decision("양호", f"Docker 버전 {'.'.join(str(part) for part in version)}에서는 legacy registry v1을 사용할 수 없습니다.", result.get("detail"))
    return None


def _decide_path_dot(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state"))
    if not current_state or ":" not in current_state:
        return None
    entries = [part.strip() for part in current_state.split(":") if part.strip()]
    dot_indexes = [index for index, part in enumerate(entries) if part == "."]
    if not dot_indexes:
        return _auto_decision("양호", "PATH 환경변수에 현재 디렉터리(.)가 포함되어 있지 않습니다.", result.get("detail"))
    if any(index < len(entries) - 1 for index in dot_indexes):
        return _auto_decision("취약", "PATH 환경변수의 앞 또는 중간에 현재 디렉터리(.)가 포함되어 있습니다.", result.get("detail"))
    return _auto_decision("양호", "PATH 환경변수의 마지막에만 현재 디렉터리(.)가 존재합니다.", result.get("detail"))


def _decide_account_lock(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state"))
    deny_values = [int(value) for value in re.findall(r"deny\s*=\s*(\d+)", current_state, re.IGNORECASE)]
    if not deny_values:
        return None
    if min(deny_values) <= 10:
        return _auto_decision("양호", f"계정 잠금 임계값이 {min(deny_values)}회로 설정되어 있습니다.", result.get("detail"))
    return _auto_decision("취약", f"계정 잠금 임계값이 {min(deny_values)}회로 기준을 초과합니다.", result.get("detail"))


def _decide_unauthenticated_api(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state"))
    if not current_state.startswith("{"):
        return None
    current_state_lower = current_state.lower()
    if '"status":401' in current_state_lower or '"status":403' in current_state_lower or "security_exception" in current_state_lower:
        return _auto_decision("양호", "인증 없이 API 접근이 거부됩니다.", result.get("detail"))
    if '"cluster_name"' in current_state_lower or '"tagline"' in current_state_lower or '"name"' in current_state_lower:
        return _auto_decision("취약", "인증 없이 API 응답이 반환되어 인증 설정이 적용되지 않았습니다.", result.get("detail"))
    return None


def _decide_k8s_encryption(result: dict) -> tuple[str, str] | None:
    current_state = _normalize_text(result.get("current_state"))
    current_state_lower = current_state.lower()
    if not current_state:
        return None
    if "encryption-provider-config" in current_state_lower:
        return _auto_decision("양호", "kube-apiserver에 etcd 암호화 설정 경로가 지정되어 있습니다.", result.get("detail"))
    if "grep kube-apiserver" in current_state_lower or "kube-apiserver" not in current_state_lower:
        return _auto_decision("취약", "kube-apiserver 실행 인자에서 etcd 암호화 설정을 확인하지 못했습니다.", result.get("detail"))
    return None


def _apply_single_rule(app_key: str, code: str, result: dict, context: dict) -> tuple[str, str] | None:
    if app_key == "NodeJS" and code == "CSAP-NodeJS-01":
        return _decide_node_process(result)
    if app_key == "Docker" and code == "CSAP-Docker-02":
        return _decide_docker_group(result)
    if app_key == "Docker" and code == "CSAP-Docker-09":
        return _decide_docker_bridge(result)
    if app_key == "Docker" and code == "CSAP-Docker-11":
        return _decide_docker_legacy_registry(result, context)
    if app_key == "Elasticsearch" and code in {"CSAP-Elasticsearch-01", "CSAP-Elasticsearch-02"}:
        return _decide_unauthenticated_api(result)
    if app_key == "K8s(Master)" and code == "CSAP-K8sMaster-10":
        return _decide_k8s_encryption(result)
    if app_key == "Linux" and code == "CSAP-Linux-03 / ISMS-U-03":
        return _decide_account_lock(result)
    if app_key == "Linux" and code == "CSAP-Linux-06 / ISMS-U-14":
        return _decide_path_dot(result)
    return None


def apply_auto_judgement_harness(app_key: str, results: list[dict]) -> list[dict]:
    context = _build_context(results)
    adjusted: list[dict] = []

    for original in results:
        result = deepcopy(original)
        if result.get("status") != MANUAL_STATUS:
            adjusted.append(result)
            continue

        code = _normalize_text(result.get("code"))
        decision = _apply_single_rule(app_key, code, result, context)
        if decision is not None:
            result["status"], result["detail"] = decision
        adjusted.append(result)

    return adjusted
