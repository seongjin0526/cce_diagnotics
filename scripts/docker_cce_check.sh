#!/bin/sh
###############################################################################
# Docker CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash docker_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_docker_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

TEMP_DIR="/tmp/cce_check_$$"
mkdir -p "$TEMP_DIR"
trap "rm -rf $TEMP_DIR" EXIT

# --- JSON helper functions (ESXi BusyBox compatible) ---
RESULTS_FILE="$TEMP_DIR/results.txt"
: > "$RESULTS_FILE"

sanitize_json_value() {
    printf '%s' "$1" | LC_ALL=C tr '\000-\010\013\014\016-\037' ' ' | tr '\t\r\n' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g; s/  */ /g; s/^ //; s/ $//'
}

normalize_trace_value() {
    printf '%s' "$1" | LC_ALL=C tr '\000-\010\013\014\016-\037' ' ' | tr '\t\r\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//'
}

summarize_output() {
    printf '%s' "$1" | LC_ALL=C tr '\000-\010\013\014\016-\037' ' ' | head -n 5 | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'
}

output_has_negative_marker() {
    printf '%s\n' "$1" | grep -Eiq '(^|[^[:alnum:]_-])(0|false|off|disabled|inactive|none|no|n|deny|denied|prohibit-password|without-password|never)([^[:alnum:]_-]|$)|계정 사용 안함|사용 안함|비활성'
}

output_has_positive_marker() {
    printf '%s\n' "$1" | grep -Eiq '(^|[^[:alnum:]_-])(1|true|on|enabled|enable|active|yes|y|allow|allowed)([^[:alnum:]_-]|$)|활성'
}

first_numeric_value() {
    printf '%s\n' "$1" | grep -Eo '[0-9]+' | head -1
}

log_result_trace() {
    code="$1"
    status="$2"
    title="$3"
    command="$4"
    current_state="$5"
    detail="$6"
    command_text=$(normalize_trace_value "$command")
    current_state_text=$(normalize_trace_value "$current_state")
    detail_text=$(normalize_trace_value "$detail")
    printf '\n[TRACE] code=%s status=%s title=%s\n' "$code" "$status" "$title"
    printf '[TRACE] command=%s\n' "${command_text:--}"
    printf '[TRACE] current_state=%s\n' "${current_state_text:--}"
    printf '[TRACE] detail=%s\n' "${detail_text:--}"
}

add_result() {
    code="$1"
    category="$2"
    title="$3"
    importance="$4"
    status="$5"
    detail="$6"
    source="$7"
    command="$8"
    current_state="$9"
    shift 9
    remediation="$1"
    raw_detail="$detail"
    raw_command="$command"
    raw_current_state="$current_state"

    # Escape strings for JSON
    detail=$(sanitize_json_value "$detail")
    title=$(sanitize_json_value "$title")
    command=$(sanitize_json_value "$command")
    current_state=$(sanitize_json_value "$current_state")
    remediation=$(sanitize_json_value "$remediation")

    printf '%s\n' "{\"code\":\"$code\",\"category\":\"$category\",\"title\":\"$title\",\"importance\":\"$importance\",\"status\":\"$status\",\"detail\":\"$detail\",\"source\":\"$source\",\"command\":\"$command\",\"current_state\":\"$current_state\",\"remediation\":\"$remediation\"}" >> "$RESULTS_FILE"
    log_result_trace "$code" "$status" "$title" "$raw_command" "$raw_current_state" "$raw_detail"
}

# --- Utility functions (ESXi compatible) ---
check_file_owner_perm() {
    file="$1"
    expected_owner="$2"
    max_perm="$3"

    if [ ! -e "$file" ]; then
        echo "NOT_FOUND"
        return
    fi

    owner=$(ls -ld "$file" 2>/dev/null | awk '{print $3}')
    perm_str=$(ls -ld "$file" 2>/dev/null | awk '{print $1}')
    perm=$(stat -c '%a' "$file" 2>/dev/null || echo "000")

    owner_ok="false"
    if [ -z "$expected_owner" ] || [ "$owner" = "$expected_owner" ]; then
        owner_ok="true"
    fi

    perm_ok="false"
    if [ "$perm" -le "$max_perm" ] 2>/dev/null; then
        perm_ok="true"
    fi

    if [ "$owner_ok" = "true" ] && [ "$perm_ok" = "true" ]; then
        echo "GOOD|owner=$owner,perm=$perm"
    else
        echo "VULN|owner=$owner,perm=$perm"
    fi
}

is_service_active() {
    svc="$1"
    if /etc/init.d/"$svc" status 2>/dev/null | grep -qi "running"; then
        echo "active"
    elif ps | grep -v grep | grep -q "$svc"; then
        echo "active"
    else
        echo "inactive"
    fi
}


# --- Docker helper ---
run_docker_cmd() {
    docker "$@" 2>/dev/null
}


# --- Pre-flight: Docker 설치 확인 및 경로 탐지 ---
DOCKER_BIN=""
DOCKER_CONF="${DOCKER_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    DOCKER_BIN=$(command -v docker 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$DOCKER_BIN" ]; then
        ps -ef 2>/dev/null | grep -q '[d]ockerd' && APP_FOUND="true"
    fi

    # 3) 공통 설정 파일 경로 탐색
    for f in /etc/docker/daemon.json ~/.docker/daemon.json; do
        if [ -f "$f" ]; then
            DOCKER_CONF="$f"
            break
        fi
    done

    # 4) 패키지 매니저 확인
    if [ -z "$DOCKER_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg >/dev/null 2>&1; then
            dpkg -l 2>/dev/null | grep -qi 'docker-ce\|docker.io' && APP_FOUND="true"
        elif command -v rpm >/dev/null 2>&1; then
            rpm -qa 2>/dev/null | grep -qi 'docker-ce\|docker' && APP_FOUND="true"
        fi
    fi

    # 5) Docker 소켓 확인
    if [ -S /var/run/docker.sock ]; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$DOCKER_BIN" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Docker 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Docker-01: 도커 최신 보안 패치 적용
check_CSAP_Docker_01() {
    local status="양호"
    local detail=""
    local cmd="docker version; dpkg -l | grep docker.io; rpm -qa | grep docker.io"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( docker version )
        ( get_process_snapshot "docker.io" )
        ( get_process_snapshot "docker.io" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        status="수동점검"
        detail="명령 결과는 수집했지만 운영 정책/최신 기준 대조가 필요합니다. "
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-01" "컨테이너 런타임" "도커 최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-02: 도커 그룹에 불필요한 사용자 제거
check_CSAP_Docker_02() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/group | grep docker; cat /etc/group | grep root"
    local cur_state=""
    local remediation="￭ 도커 그룹에서 불필요한 사용자 제거 1) # vi /etc/group 입력 후, 불필요한 사용자 계정 제거 ￭ 도커 그룹 이름이 dockerroot인 경우 1) root 그룹, dockerroot 그룹 모두 불필요한 사용자 계정 제거 # vi /etc/group"

    local group_output
    local extra_members
    group_output=$({ cat /etc/group 2>/dev/null | grep docker; cat /etc/group 2>/dev/null | grep root; } | awk -F: '!seen[$1]++' | head -20)
    cur_state="${group_output:-그룹 정보 없음}"
    extra_members=$(printf '%s\n' "$group_output" | awk -F: '$1=="docker" || $1=="dockerroot" || $1=="root" { n=split($4, members, ","); for (i=1; i<=n; i++) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", members[i]); if (members[i] != "" && members[i] != "root" && !seen[members[i]]++) { if (out != "") out=out ","; out=out members[i]; } } } END { print out }')
    if [ -n "$extra_members" ]; then
        status="취약"
        detail="docker/dockerroot/root 그룹에 불필요할 수 있는 사용자($extra_members)가 포함되어 있습니다."
    else
        status="양호"
        detail="docker/dockerroot/root 그룹에 root 이외 추가 사용자를 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-02" "Host 설정" "도커 그룹에 불필요한 사용자 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-03: Docker daemon audit 설정
check_CSAP_Docker_03() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /usr/bin/docker; cat [audit.rules 파일 위치] | grep /usr/bin/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1) auditd 설치 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3) audit 데몬 재시작 # service auditd restart"

    local audit_target="/usr/bin/docker"
    local output
    output=$({ auditctl -l 2>/dev/null | grep -F -- "$audit_target"; cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -F -- "$audit_target"; } | sed '/^$/d' | head -20)
    cur_state="${output:-감사 규칙 없음}"
    if [ -n "$output" ]; then
        status="양호"
        detail="/usr/bin/docker 파일에 감사 설정이 적용되어 있습니다."
    else
        status="취약"
        detail="/usr/bin/docker 파일에 감사 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-03" "Host 설정" "Docker daemon audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-04: /var/lib/docker audit 설정
check_CSAP_Docker_04() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /var/lib/docker; cat [audit.rules 파일 위치] | grep /var/lib/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1) auditd 설치 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3) audit 데몬 재시작 # service auditd restart"

    local audit_target="/var/lib/docker"
    local output
    output=$({ auditctl -l 2>/dev/null | grep -F -- "$audit_target"; cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -F -- "$audit_target"; } | sed '/^$/d' | head -20)
    cur_state="${output:-감사 규칙 없음}"
    if [ -n "$output" ]; then
        status="양호"
        detail="/var/lib/docker 디렉터리에 감사 설정이 적용되어 있습니다."
    else
        status="취약"
        detail="/var/lib/docker 디렉터리에 감사 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-04" "Host 설정" "/var/lib/docker audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-05: /etc/docker audit 설정
check_CSAP_Docker_05() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /etc/docker; cat [audit.rules 파일 위치] | grep /etc/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1) auditd 설치 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3) audit 데몬 재시작 # service auditd restart"

    local audit_target="/etc/docker"
    local output
    output=$({ auditctl -l 2>/dev/null | grep -F -- "$audit_target"; cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -F -- "$audit_target"; } | sed '/^$/d' | head -20)
    cur_state="${output:-감사 규칙 없음}"
    if [ -n "$output" ]; then
        status="양호"
        detail="/etc/docker 디렉터리에 감사 설정이 적용되어 있습니다."
    else
        status="취약"
        detail="/etc/docker 디렉터리에 감사 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-05" "Host 설정" "/etc/docker audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-06: docker.service audit 설정
check_CSAP_Docker_06() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /lib/systemd/system/docker.service; cat [audit.rules 파일 위치] | /lib/systemd/system/docker.service"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1) auditd 설치 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3) audit 데몬 재시작 # service auditd restart"

    local audit_target="/lib/systemd/system/docker.service"
    local output
    output=$({ auditctl -l 2>/dev/null | grep -F -- "$audit_target"; cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -F -- "$audit_target"; } | sed '/^$/d' | head -20)
    cur_state="${output:-감사 규칙 없음}"
    if [ -n "$output" ]; then
        status="양호"
        detail="docker.service 파일에 감사 설정이 적용되어 있습니다."
    else
        status="취약"
        detail="docker.service 파일에 감사 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-06" "Host 설정" "docker.service audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-07: docker.socket audit 설정
check_CSAP_Docker_07() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /lib/systemd/system/docker.socket; cat [audit.rules 파일 위치] | /lib/systemd/system/docker.socket"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1) auditd 설치 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3) audit 데몬 재시작 # service auditd restart"

    local audit_target="/lib/systemd/system/docker.socket"
    local output
    output=$({ auditctl -l 2>/dev/null | grep -F -- "$audit_target"; cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -F -- "$audit_target"; } | sed '/^$/d' | head -20)
    cur_state="${output:-감사 규칙 없음}"
    if [ -n "$output" ]; then
        status="양호"
        detail="docker.socket 파일에 감사 설정이 적용되어 있습니다."
    else
        status="취약"
        detail="docker.socket 파일에 감사 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-07" "Host 설정" "docker.socket audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-08: /etc/default/docker audit 설정
check_CSAP_Docker_08() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /etc/default/docker; cat [audit.rules 파일 위치] | /etc/default/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1) auditd 설치 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 (Debian 계열) 2) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 (RedHat 계열) -w /etc/default/docker –k docker 3) audit 데몬 재시작 # service auditd restart"

    local audit_target="/etc/default/docker"
    local output
    output=$({ auditctl -l 2>/dev/null | grep -F -- "$audit_target"; cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -F -- "$audit_target"; } | sed '/^$/d' | head -20)
    cur_state="${output:-감사 규칙 없음}"
    if [ -n "$output" ]; then
        status="양호"
        detail="/etc/default/docker 파일에 감사 설정이 적용되어 있습니다."
    else
        status="취약"
        detail="/etc/default/docker 파일에 감사 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-Docker-08" "Host 설정" "/etc/default/docker audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-09: default bridege를 통한 컨테이너간 네트워크 트래픽 제한
check_CSAP_Docker_09() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker; docker network ls --quiet | xargs docker network inspect --format '{{; docker 명령어를 통해 옵션 적용 여부를 확인할 수 있음"
    local cur_state=""
    local remediation="￭ 아래와 같은 옵션으로 데몬 재시작 1) # dockerd --icc=true ￭ /etc/default/docker 파일에 아래와 같은 옵션 추가 후 데몬 재시작 1) dockerd, docker.socket, docker.service 중지 2) /etc/default/docker에 DOCKER_OPTS=\"--icc=false\" 문구 추가 3) /lib/systemd/system/docker.service에 아래의 내용 추가 4) docker.socket, docker.service, dockerd 재시작 5) # ps –ef | grep docker 명령어 입력하여 --icc=false 옵션 적용 확인"

    local output
    output=$({
        ( get_process_snapshot "docker" )
        ( docker network ls --quiet | xargs docker network inspect --format {{ )
        ( docker )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="컨테이너 간 네트워크 통신이 가능하지 않은"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="컨테이너 간 네트워크 통신이 가능한 경우"
        else
            status="취약"
            detail="컨테이너 간 네트워크 통신이 가능한 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-09" "" "default bridege를 통한 컨테이너간 네트워크 트래픽 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-10: 도커 클라이언트 인증 활성화
check_CSAP_Docker_10() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker; docker plugin ls; docker search hello-world"
    local cur_state=""
    local remediation="￭ 인증 플러그인 설치 ￭ 다음과 같은 절차로 인증 설정 1) 인증 플러그인 설치 2) 인증 정책 설정 3) 아래와 같은 옵션으로 데몬 시작 (방법1) docker daemon --authorization-plugin=<PLUGIN_ID> (방법2) /etc/default/docker 파일에 아래와 같은 옵션 추가 후 데몬 재시작 DOCKER_OPTS=\" --authorization-plugin-<PLUGIN_ID>\" (방법3) /etc/docker/daemon.json 파일에 아래와 같은 옵션 추가 후 데몬 재시작 { \"authorization-plugins\": [ \"PLUGIN_ID\" ]}"

    local output
    output=$({
        ( get_process_snapshot "docker" )
        ( docker plugin ls )
        ( docker search hello-world )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="Docker 인증 플러그인이 적용되어 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="Docker 인증 플러그인이 적용되어 있지"
        else
            status="취약"
            detail="Docker 인증 플러그인이 적용되어 있지"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-10" "도커 데몬 설정" "도커 클라이언트 인증 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-11: legacty registry (v1) 비활성화
check_CSAP_Docker_11() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker"
    local cur_state=""
    local remediation="￭ 아래와 같은 옵션으로 데몬 시작 1) # docker daemon —disable-legacy-registry 2) /etc/default/docker 파일에 아래의 옵션 추가 후 데몬 재시작 Docker_OPTS=\"--disable-legacy-registry\""

    local output
    output=$({
        ( get_process_snapshot "docker" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="legacy registry v1이 비활성화되어 있는"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="legacy registry v1이 활성화되어 있는 경우"
        else
            status="취약"
            detail="legacy registry v1이 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-11" "" "legacty registry (v1) 비활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-12: 추가 권한 획득으로부터 컨테이너 제한
check_CSAP_Docker_12() {
    local status="양호"
    local detail=""
    local cmd="docker ps -quiet -all; docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}:"
    local cur_state=""
    local remediation="￭ 컨테이너 옵션 실행 1) # docker run --security-opt=no-new-privileges"

    local output
    output=$({
        ( docker ps -quiet -all )
        ( docker ps --quiet --all | xargs docker inspect --format {{ .Id }}: )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="컨테이너 추가 권한 획득 제한 설정이"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="컨테이너 추가 권한 획득 제한 설정이"
        else
            status="취약"
            detail="컨테이너 추가 권한 획득 제한 설정이"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-12" "도커 데몬 설정" "추가 권한 획득으로부터 컨테이너 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-13: docker.service 소유권 설정
check_CSAP_Docker_13() {
    local status="양호"
    local detail=""
    local cmd="ls -l /lib/systemd/system/docker.service; stat -c %U:%G /lib/systemd/system/docker.service"
    local cur_state=""
    local remediation="￭ docker.service 파일의 소유자 및 소유 그룹을 root:root로 변경 1) # chown root:root /lib/systemd/system/docker.service"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/lib/systemd/system/docker.service
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="docker.service 파일의 소유자 및" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-13" "도커 데몬 설정 파일" "docker.service 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-14: docker.service 파일 접근 권한 설정
check_CSAP_Docker_14() {
    local status="양호"
    local detail=""
    local cmd="systemctl show -p FragmentPath docker.service; ls -l /lib/systemd/system/docker.service"
    local cur_state=""
    local remediation="￭ docker.service 파일 접근 권한 수정 1) # chmod 644 /lib/systemd/system/docker.service"

    local svc_status
    svc_status=$(is_service_active "docker.service")
    cur_state="docker.service=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="docker.service 서비스 활성화 상태. "
    else
        detail="docker.service 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CSAP-Docker-14" "도커 데몬 설정 파일" "docker.service 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-15: docker.socket 소유권 설정
check_CSAP_Docker_15() {
    local status="양호"
    local detail=""
    local cmd="systemctl show -p FragmentPath docker.socket; ls -l /lib/systemd/system/docker.socket; stat -c %U:%G /lib/systemd/system/docker.socket"
    local cur_state=""
    local remediation="￭ docker.socket 파일 소유자 및 소유 그룹 수정 1) # chown root:root /lib/systemd/system/docker.socket"

    local svc_status
    svc_status=$(is_service_active "docker.socket")
    cur_state="docker.socket=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="docker.socket 서비스 활성화 상태. "
    else
        detail="docker.socket 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CSAP-Docker-15" "도커 데몬 설정 파일" "docker.socket 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-16: docker.socket 파일 접근 권한 설정
check_CSAP_Docker_16() {
    local status="양호"
    local detail=""
    local cmd="systemctl show -p FragmentPath docker.socket; ls -l /lib/systemd/system/docker.socket"
    local cur_state=""
    local remediation="￭ docker.socket 파일 접근 권한 수정 1) # chmod 644 /lib/systemd/system/docker.socket"

    local svc_status
    svc_status=$(is_service_active "docker.socket")
    cur_state="docker.socket=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="docker.socket 서비스 활성화 상태. "
    else
        detail="docker.socket 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CSAP-Docker-16" "도커 데몬 설정 파일" "docker.socket 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-17: /etc/docker 디렉터리 소유권 설정
check_CSAP_Docker_17() {
    local status="양호"
    local detail=""
    local cmd="ls -ld /etc/docker; stat -c %U:%G /etc/docker"
    local cur_state=""
    local remediation="￭ /etc/docker 디렉터리 소유자 및 소유 그룹 수정 1) # chown root:root /etc/docker"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/docker
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/docker 디렉터리의 소유자 및" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-17" "도커 데몬 설정 파일" "/etc/docker 디렉터리 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-18: /etc/docker 디렉터리 접근 권한 설정
check_CSAP_Docker_18() {
    local status="양호"
    local detail=""
    local cmd="ls -ld /etc/docker; stat -c %a /etc/docker"
    local cur_state=""
    local remediation="￭ /etc/docker 디렉터리 접근 권한 수정 1) # chmod 755 /etc/docker"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/docker
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "755")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/docker 디렉터리 접근 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-18" "" "/etc/docker 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-19: /var/run/docker.sock 파일 소유권 설정
check_CSAP_Docker_19() {
    local status="양호"
    local detail=""
    local cmd="ls -l /var/run/docker.sock; stat -c %U:%G /var/run/docker.sock"
    local cur_state=""
    local remediation="￭ /var/dun/docker.sock 파일 소유자 및 소유 그룹 수정 1) # chown root:docker /var/run/docker.sock (Debian 계열) 2) # chown root:docker /run/docker.sock (RedHat 계열)"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/var/run/docker.sock
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/var/run/docker.sock 파일의 소유자 및" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-19" "도커 데몬 설정 파일" "/var/run/docker.sock 파일 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-20: /var/run/docker.sock 파일 접근 권한 설정
check_CSAP_Docker_20() {
    local status="양호"
    local detail=""
    local cmd="ls -l /var/run/docker.sock; stat -c %a /var/run/docker.sock"
    local cur_state=""
    local remediation="￭ /var/dun/docker.sock 파일 접근 권한 수정 1) # chmod 660 /var/run/docker.sock"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/var/run/docker.sock
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "660")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/var/run/docker.sock 파일의 접근" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-20" "도커 데몬 설정 파일" "/var/run/docker.sock 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-21: daemon.json 파일 소유권 설정
check_CSAP_Docker_21() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/docker/daemon.json; stat -c %U:%G /etc/docker/daemon.json"
    local cur_state=""
    local remediation="￭ daemon.json 파일 소유자 및 소유 그룹 수정 1) # chown root:root /etc/docker/daemon.json"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/docker/daemon.json
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/docker/daemon.json 파일의" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-21" "도커 데몬 설정 파일" "daemon.json 파일 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-22: daemon.json 파일 접근 권한 설정
check_CSAP_Docker_22() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/docker/daemon.json; stat -c %a /etc/docker/daemon.json"
    local cur_state=""
    local remediation="￭ daemon.json 파일 접근 권한 수정 1) # chmod 644 /etc/docker/daemon.json"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/docker/daemon.json
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/docker/daemon.json 파일의 접근" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-22" "도커 데몬 설정 파일" "daemon.json 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-23: /etc/default/docker 파일 소유권 설정
check_CSAP_Docker_23() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/default/docker; stat -c %U:%G /etc/default/docker"
    local cur_state=""
    local remediation="￭ /etc/default/docker 파일 소유자 및 소유 그룹 수정 1) # chown root:root /etc/default/docker (Debian 계열) 2) # chown root:root /etc/sysconfig/docker (RedHat 계열)"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/default/docker
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/default/docker 파일의 소유자 및" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-23" "도커 데몬 설정 파일" "/etc/default/docker 파일 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-24: /etc/default/docker 파일 접근 권한 설정
check_CSAP_Docker_24() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/default/docker; stat -c %a /etc/default/docker"
    local cur_state=""
    local remediation="￭ /etc/default/docker 파일 접근 권한 수정 1) # chmod 644 /etc/default/docker (Debian 계열) 2) # chmod 644 /etc/sysconfig/docker (RedHat 계열)"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/default/docker
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/default/docker 파일의 접근 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Docker-24" "도커 데몬 설정 파일" "/etc/default/docker 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-25: root가 아닌 user로 컨테이너 실행
check_CSAP_Docker_25() {
    local status="양호"
    local detail=""
    local cmd="docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}:"
    local cur_state=""
    local remediation="￭ Dockerfile에 아래의 내용 추가 1) RUN useradd –d /home/username –m s /bin/bash username USER username"

    local output
    output=$({
        ( docker ps --quiet --all | xargs docker inspect --format {{ .Id }}: )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="컨테이너가 root 계정으로 실행되고 있지"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="컨테이너가 root 계정으로 실행되고 있는"
        else
            status="취약"
            detail="컨테이너가 root 계정으로 실행되고 있는"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-25" "컨테이너 이미지 및" "root가 아닌 user로 컨테이너 실행" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-26: 도커를 위한 컨텐츠 신뢰성 활성화
check_CSAP_Docker_26() {
    local status="양호"
    local detail=""
    local cmd="echo \$DOCKER_CONTENT_TRUST"
    local cur_state=""
    local remediation="￭ 사용하는 shell에 아래의 내용을 추가 1) # export DOCKER_CONTENT_TRUST=1"

    local output
    output=$({
        ( echo $DOCKER_CONTENT_TRUST )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="Docker 컨텐츠 신뢰성 설정이 활성화되어"
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="Docker 컨텐츠 신뢰성 설정이 활성화되어"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="Docker 컨텐츠 신뢰성 설정이 활성화되어"
        else
            status="취약"
            detail="Docker 컨텐츠 신뢰성 설정이 활성화되어"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-26" "컨테이너 이미지 및" "도커를 위한 컨텐츠 신뢰성 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-27: 컨테이너 SELinux 보안 옵션 설정
check_CSAP_Docker_27() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker | grep selinux-enabled; docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}:"
    local cur_state=""
    local remediation="￭ SELinux 활성화 1) /etc/default/docker 파일 내 DOCKER_OPTS=\"--selinux-enabled\" 설정 2) /lib/systemd/system/docker.service 파일에 아래의 내용 수정 3) docker 데몬 재시작 4) --selinux-enabled 옵션 활성화 확인"

    local output
    output=$({
        ( get_process_snapshot "docker" )
        ( docker ps --quiet --all | xargs docker inspect --format {{ .Id }}: )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="SELinux 보안 옵션이 활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="SELinux 보안 옵션이 활성화되어 있지 않은"
        else
            status="취약"
            detail="SELinux 보안 옵션이 활성화되어 있지 않은"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-27" "컨테이너 런타임" "컨테이너 SELinux 보안 옵션 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-28: 컨테이너에서 ssh 사용 금지
check_CSAP_Docker_28() {
    local status="양호"
    local detail=""
    local cmd="docker ps -quiet"
    local cur_state=""
    local remediation="￭ 컨테이너에서 ssh를 제거하고 docker exec, docker attach 명령어 통해 컨테이너 접속 1) # docker exec —interactive —tty \$INSTANCE_ID sh 2) # docker attach \$INSTANCE_ID"

    local output
    output=$({
        ( docker ps -quiet )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="컨테이너에 SSH가 비활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="컨테이너에 SSH가 활성화되어 있는 경우"
        else
            status="취약"
            detail="컨테이너에 SSH가 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-28" "컨테이너 런타임" "컨테이너에서 ssh 사용 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-29: 컨테이너에 PREVILEGED 포트 매핑 금지
check_CSAP_Docker_29() {
    local status="양호"
    local detail=""
    local cmd="docker ps -quiet -all; docker ps -a"
    local cur_state=""
    local remediation="￭ privileged가 아닌 포트로 매핑 1) 컨테이너 시작 시, 컨테이너 포트를 호스트의 privileged 포트가 아닌 포트로 매핑 2) Docker 파일에서 privileged 포트 매핑 선언을 호스팅하는 컨테이너가 없는지 확인"

    local output
    output=$({
        ( docker ps -quiet -all )
        ( docker ps -a )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="컨테이너 포트가 privileged 포트에"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="컨테이너 포트가 privileged 포트에 매핑된"
        else
            status="취약"
            detail="컨테이너 포트가 privileged 포트에 매핑된"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-29" "" "컨테이너에 PREVILEGED 포트 매핑 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-30: PIDs cgroup 제한
check_CSAP_Docker_30() {
    local status="양호"
    local detail=""
    local cmd="docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}:PidsLimit="
    local cur_state=""
    local remediation="￭ 컨테이너 시작 시 —pids-limit 플래그를 사용 (예시) 1) # docker run –it —pids-limit 100 <image_id>"

    local output
    output=$({
        ( docker ps --quiet --all | xargs docker inspect --format {{ .Id }}:PidsLimit= )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="PIDs cgroup 제한 설정이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="PIDs cgroup 제한 설정이 적용되어 있지"
        else
            status="취약"
            detail="PIDs cgroup 제한 설정이 적용되어 있지"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-30" "컨테이너 런타임" "PIDs cgroup 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-31: 도커의 default bridge docker() 사용 제한
check_CSAP_Docker_31() {
    local status="양호"
    local detail=""
    local cmd="ifconfig | grep docker; docker network ls --quiet | xargs xargs docker network inspect --format"
    local cur_state=""
    local remediation="￭ Default bridge docker() 비활성화 1) /etc/default/docker 파일 내 DOCKER_OPTS=\"--icc=false\" 설정 2) /lib/systemd/system/docker.service 파일에 아래의 내용 수정 3) docker 데몬 재시작 4) # docker network inspect bridge 5) 사용자 정의 네트워크 생성, 지정 (예시) / daemon.json 작성 시, \"icc=false\" 옵션 추가 # docker network create my-net 6) 아래 명령어를 입력하여 docker() 제거 확인 및 사용자 정의 네트워크 확인 # docker network ls"

    local config_file="/etc/app/config"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local content
        content=$(head -20 "$actual_config" 2>/dev/null)
        cur_state="설정 파일 존재: $actual_config"
        detail="설정 파일 확인 필요: $actual_config. "
        status="수동점검"
    fi

    add_result "CSAP-Docker-31" "컨테이너 런타임" "도커의 default bridge docker() 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Docker-32: 호스트의 user namespaces 공유 제한
check_CSAP_Docker_32() {
    local status="양호"
    local detail=""
    local cmd="docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}"
    local cur_state=""
    local remediation="￭ 호스트, 컨테이너 user namespaces 공유 제한 1) # docker run --rm -it --userns=host ubuntu bash (취약) 2) # docker run --rm -it ubuntu bash (양호)"

    local output
    output=$({
        ( docker ps --quiet --all | xargs docker inspect --format {{ .Id }} )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="N/A"
        detail="명령 실행 결과 없음 또는 대상 미설치. "
    else
        if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="해당 파일이 없으므로 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_GOOD|//p' | head -1)
            status="양호"
            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then
            local default_text
            default_text=$(printf '%s\n' "$output" | sed -n 's/^SETTING_DEFAULT_BAD|//p' | head -1)
            status="취약"
            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"
        elif printf '%s\n' "$output" | grep -q "^FILE_MISSING|"; then
            local missing_text
            missing_text=$(printf '%s\n' "$output" | sed -n 's/^FILE_MISSING|//p' | head -1)
            status="수동점검"
            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"
        else
        if output_has_negative_marker "$output"; then
            status="양호"
            detail="호스트의 user namespace를 컨테이너와"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="호스트의 user namespace를 컨테이너와"
        else
            status="취약"
            detail="호스트의 user namespace를 컨테이너와"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Docker-32" "" "호스트의 user namespaces 공유 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Docker CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/32] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Docker-01"; check_CSAP_Docker_01
progress "CSAP-Docker-02"; check_CSAP_Docker_02
progress "CSAP-Docker-03"; check_CSAP_Docker_03
progress "CSAP-Docker-04"; check_CSAP_Docker_04
progress "CSAP-Docker-05"; check_CSAP_Docker_05
progress "CSAP-Docker-06"; check_CSAP_Docker_06
progress "CSAP-Docker-07"; check_CSAP_Docker_07
progress "CSAP-Docker-08"; check_CSAP_Docker_08
progress "CSAP-Docker-09"; check_CSAP_Docker_09
progress "CSAP-Docker-10"; check_CSAP_Docker_10
progress "CSAP-Docker-11"; check_CSAP_Docker_11
progress "CSAP-Docker-12"; check_CSAP_Docker_12
progress "CSAP-Docker-13"; check_CSAP_Docker_13
progress "CSAP-Docker-14"; check_CSAP_Docker_14
progress "CSAP-Docker-15"; check_CSAP_Docker_15
progress "CSAP-Docker-16"; check_CSAP_Docker_16
progress "CSAP-Docker-17"; check_CSAP_Docker_17
progress "CSAP-Docker-18"; check_CSAP_Docker_18
progress "CSAP-Docker-19"; check_CSAP_Docker_19
progress "CSAP-Docker-20"; check_CSAP_Docker_20
progress "CSAP-Docker-21"; check_CSAP_Docker_21
progress "CSAP-Docker-22"; check_CSAP_Docker_22
progress "CSAP-Docker-23"; check_CSAP_Docker_23
progress "CSAP-Docker-24"; check_CSAP_Docker_24
progress "CSAP-Docker-25"; check_CSAP_Docker_25
progress "CSAP-Docker-26"; check_CSAP_Docker_26
progress "CSAP-Docker-27"; check_CSAP_Docker_27
progress "CSAP-Docker-28"; check_CSAP_Docker_28
progress "CSAP-Docker-29"; check_CSAP_Docker_29
progress "CSAP-Docker-30"; check_CSAP_Docker_30
progress "CSAP-Docker-31"; check_CSAP_Docker_31
progress "CSAP-Docker-32"; check_CSAP_Docker_32

echo ""
echo ""

###############################################################################
# Generate JSON output
###############################################################################

# System info
SYS_HOSTNAME=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr '
' '  ' | sed 's/  */ /g; s/^ //; s/ $//' )
SYS_OS="VMware ESXi"
SYS_KERNEL=$(uname -r 2>/dev/null)
SYS_DATE=$(date '+%Y-%m-%d %H:%M:%S')
SYS_IP=$(esxcli network ip interface ipv4 get 2>/dev/null | awk 'NR>1 {print $2}' | head -1)

# Count results
total_checks=0
good_count=0
vuln_count=0
na_count=0
manual_count=0

while IFS= read -r line; do
    total_checks=$((total_checks + 1))
    case "$line" in
        *'"status":"양호"'*) good_count=$((good_count + 1)) ;;
        *'"status":"취약"'*) vuln_count=$((vuln_count + 1)) ;;
        *'"status":"N/A"'*) na_count=$((na_count + 1)) ;;
        *'"status":"수동점검"'*) manual_count=$((manual_count + 1)) ;;
    esac
done < "$RESULTS_FILE"

# Build JSON
{
    echo '{'
    echo '  "scan_info": {'
    echo "    \"hostname\": \"$SYS_HOSTNAME\","
    echo "    \"os\": \"$SYS_OS\","
    echo "    \"kernel\": \"$SYS_KERNEL\","
    echo "    \"ip\": \"$SYS_IP\","
    echo "    \"scan_date\": \"$SYS_DATE\","
    echo '    "platform": "Docker",'
    echo '    "guide_sources": ['
    echo '      "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)",'
    echo '      "클라우드 취약점 점검 가이드 (2024)"'
    echo '    ]'
    echo '  },'
    echo '  "summary": {'
    echo "    \"total\": $total_checks,"
    echo "    \"양호\": $good_count,"
    echo "    \"취약\": $vuln_count,"
    echo "    \"N/A\": $na_count,"
    echo "    \"수동점검\": $manual_count"
    echo '  },'
    echo '  "results": ['

    first=true
    while IFS= read -r line; do
        if [ "$first" = "true" ]; then
            echo "    $line"
            first=false
        else
            echo "    ,$line"
        fi
    done < "$RESULTS_FILE"

    echo '  ]'
    echo '}'
} > "$OUTPUT_FILE"

echo "===== Docker CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
