#!/bin/bash
###############################################################################
# KVM CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash kvm_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_kvm_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# --- JSON helper functions ---
results=()

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
    local code="$1"
    local status="$2"
    local title="$3"
    local command="$4"
    local current_state="$5"
    local detail="$6"
    local command_text
    local current_state_text
    local detail_text
    command_text=$(normalize_trace_value "$command")
    current_state_text=$(normalize_trace_value "$current_state")
    detail_text=$(normalize_trace_value "$detail")
    printf '\n[TRACE] code=%s status=%s title=%s\n' "$code" "$status" "$title"
    printf '[TRACE] command=%s\n' "${command_text:--}"
    printf '[TRACE] current_state=%s\n' "${current_state_text:--}"
    printf '[TRACE] detail=%s\n' "${detail_text:--}"
}

add_result() {
    local code="$1"
    local category="$2"
    local title="$3"
    local importance="$4"
    local status="$5"
    local detail="$6"
    local source="$7"
    local command="$8"
    local current_state="$9"
    local remediation="${10}"
    local raw_detail="$detail"
    local raw_command="$command"
    local raw_current_state="$current_state"

    # Escape strings for JSON
    detail=$(sanitize_json_value "$detail")
    title=$(sanitize_json_value "$title")
    command=$(sanitize_json_value "$command")
    current_state=$(sanitize_json_value "$current_state")
    remediation=$(sanitize_json_value "$remediation")

    results+=("{\"code\":\"$code\",\"category\":\"$category\",\"title\":\"$title\",\"importance\":\"$importance\",\"status\":\"$status\",\"detail\":\"$detail\",\"source\":\"$source\",\"command\":\"$command\",\"current_state\":\"$current_state\",\"remediation\":\"$remediation\"}")
    log_result_trace "$code" "$status" "$title" "$raw_command" "$raw_current_state" "$raw_detail"
}

# --- Utility functions ---
check_file_owner_perm() {
    local file="$1"
    local expected_owner="$2"
    local max_perm="$3"

    if [ ! -e "$file" ]; then
        echo "NOT_FOUND"
        return
    fi

    local owner
    owner=$(stat -c '%U' "$file" 2>/dev/null)
    local perm
    perm=$(stat -c '%a' "$file" 2>/dev/null)

    local owner_ok="false"
    if [ -z "$expected_owner" ] || [ "$owner" = "$expected_owner" ]; then
        owner_ok="true"
    fi

    local perm_ok="false"
    if [ "$perm" -le "$max_perm" ] 2>/dev/null; then
        perm_ok="true"
    fi

    if [ "$owner_ok" = "true" ] && [ "$perm_ok" = "true" ]; then
        echo "GOOD|owner=$owner,perm=$perm"
    else
        echo "VULN|owner=$owner,perm=$perm"
    fi
}

get_process_snapshot() {
    local pattern="$1"
    local snapshot=""

    if command -v ps >/dev/null 2>&1; then
        snapshot=$(ps -ef 2>/dev/null | grep -v grep | grep -E "$pattern" || true)
        if [ -n "$snapshot" ]; then
            printf '%s
' "$snapshot"
            return 0
        fi
    fi

    if command -v pgrep >/dev/null 2>&1; then
        snapshot=$(pgrep -af "$pattern" 2>/dev/null || true)
        if [ -n "$snapshot" ]; then
            printf '%s
' "$snapshot"
            return 0
        fi
    fi

    local pid_dir
    for pid_dir in /proc/[0-9]*; do
        [ -r "$pid_dir/cmdline" ] || continue
        local cmdline
        cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
        [ -z "$cmdline" ] && continue
        if printf '%s
' "$cmdline" | grep -Eiq "$pattern"; then
            local uid="unknown"
            if [ -r "$pid_dir/status" ]; then
                uid=$(awk '/^Uid:/ {print $2; exit}' "$pid_dir/status" 2>/dev/null || printf 'unknown')
                if command -v id >/dev/null 2>&1; then
                    uid=$(id -nu "$uid" 2>/dev/null || printf '%s' "$uid")
                fi
            fi
            printf '%s %s
' "$uid" "$cmdline"
        fi
    done
}

is_service_active() {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" &>/dev/null; then
        echo "active"
    elif command -v service >/dev/null 2>&1 && service "$svc" status >/dev/null 2>&1; then
        echo "active"
    elif command -v pgrep >/dev/null 2>&1 && pgrep -f "$svc" >/dev/null 2>&1; then
        echo "active"
    elif [ -n "$(get_process_snapshot "$svc")" ]; then
        echo "active"
    else
        echo "inactive"
    fi
}


# --- KVM helper ---
run_virsh() {
    virsh "$@" 2>/dev/null
}


# --- Pre-flight: KVM 설치 확인 및 경로 탐지 ---
VIRSH_BIN=""
LIBVIRT_CONF="${LIBVIRT_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    VIRSH_BIN=$(command -v virsh 2>/dev/null)

    # 2) 프로세스에서 libvirtd/qemu 탐지
    if ps -ef 2>/dev/null | grep -qE '[l]ibvirtd|[q]emu'; then
        APP_FOUND="true"
    fi

    # 3) 공통 설정 경로 탐색
    if [ -d "/etc/libvirt" ]; then
        LIBVIRT_CONF="/etc/libvirt"
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$VIRSH_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'libvirt\|qemu-kvm' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'libvirt\|qemu-kvm' && APP_FOUND="true"
        fi
    fi

    # 5) KVM 모듈 확인
    if lsmod 2>/dev/null | grep -q kvm; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$VIRSH_BIN" ] || [ -n "$LIBVIRT_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] KVM 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-KVM-01: 불필요한 계정 제거
check_CSAP_KVM_01() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:"
    local cur_state=""
    local remediation="￭ 계정 삭제 1\) 계정 목록 확인 후, 불필요한 계정\(인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 담당자가 실제 업무에 필요 없다고 판단하는 계정\)은 삭제 또는 잠금/만료 설정"

    local output
    output=$({
        ( get_process_snapshot "/bin/bash" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 계정이 존재하지 않는 경우"
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

    add_result "CSAP-KVM-01" "보안 설정" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-KVM-02: Session Timeout 설정
check_CSAP_KVM_02() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/profile | grep TMOUT"
    local cur_state=""
    local remediation="￭ Sesstion Timeout 설정 1\) \$ vi /etc/profile 2\) readonly TMOUT=600; export TMOUT ￭ 설정 적용 1\) source /etc/profile"

    local output
    output=$({
        ( get_process_snapshot "tmout" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="Session Timeout이 10분\(600초\) 이내로"
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
        local numeric_value
        numeric_value=$(first_numeric_value "$output")
        if [ -z "$numeric_value" ] || [ "$numeric_value" -eq 0 ] 2>/dev/null; then
            status="취약"
            detail="Session Timeout이 10분\(600초\) 이내로"
        else
            if [ "$numeric_value" -le 600 ] 2>/dev/null; then
                status="양호"
                detail="Session Timeout이 10분\(600초\) 이내로"
            else
                status="취약"
                detail="Session Timeout이 10분\(600초\) 이내로"
            fi
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-KVM-02" "보안 설정" "Session Timeout 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-KVM-03: IP 접근 제한 설정
check_CSAP_KVM_03() {
    local status="양호"
    local detail=""
    local cmd="iptables -L -n -v; iptables -t -nat -L; iptables -L FORWARD"
    local cur_state=""
    local remediation="￭ iptables 기본 정책을 DROP 설정 후, 접근 허용 IP 등록 1\) iptables –P 명령어를 입력하여 기본 정책 변경\(DROP\) # iptables –P INPUT DROP 2\) iptables –A 명령어를 입력하여 특정 서비스에 대한 접근 허용 IP 등록 # iptables –A INPUT –p tcp –s [접근 허용 IP] --dport [포트 번호] -j ACCEPT 3\) 설정 내용 저장 # service iptables save"

    local output
    output=$({
        ( iptables -L -n -v )
        ( iptables -t -nat -L )
        ( iptables -L FORWARD )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="접속을 허용할 특정 호스트에 대한 IP 주소 및"
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
            detail="접속을 허용할 특정 호스트에 대한 IP 주소 및"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="접속을 허용할 특정 호스트에 대한 IP 주소 및"
        else
            status="취약"
            detail="접속을 허용할 특정 호스트에 대한 IP 주소 및"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-KVM-03" "보안 설정" "IP 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-KVM-04: Default Bridge 제거
check_CSAP_KVM_04() {
    local status="양호"
    local detail=""
    local cmd="virsh net-list"
    local cur_state=""
    local remediation="￭ Default Bridge 제거 후, 별도 네트워크 브릿지 생성하여 사용 1\) virsh net-destroy default 2\) virsh net-undefine default 3\) service libvirtd restart"

    local output
    output=$({
        ( virsh net-list )
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
            detail="Default Bridge를 사용하고 있지 않고"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="Default Bridge를 사용하고 있는 경우"
        else
            status="취약"
            detail="Default Bridge를 사용하고 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-KVM-04" "보안 설정" "Default Bridge 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-KVM-05: 로그의 정기적 관리 및 백업
check_CSAP_KVM_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 로그 기록 및 백업 1\) 로그를 기록하고 있지 않을 경우 로그 기록 및 백업 정책을 세워 로그를 주기적으로 남겨야 하며 로그 파일 또한 주기적으로 백업을 진행해야 함"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그를 기록하고 있으며 로그 파일 백업이"
    cur_state="수동점검 필요"

    add_result "CSAP-KVM-05" "보안 설정" "로그의 정기적 관리 및 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-KVM-06: 최신 보안 패치 적용
check_CSAP_KVM_06() {
    local status="양호"
    local detail=""
    local cmd="libvirtd -version; virsh version; virsh version -daemon"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 적용 ￭ 인터뷰를 통해 주기적으로 최신 보안 패치 적용 여부 확인"

    local output
    output=$({
        ( libvirtd -version )
        ( virsh version )
        ( virsh version -daemon )
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

    add_result "CSAP-KVM-06" "보안 설정" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-01: 계정 로그오프/세션 관리
check_ISMS_HV_01() {
    local status="양호"
    local detail=""
    local cmd="echo \$TMOUT"
    local cur_state=""
    local remediation="600초\(10분\) 동안 입력이 없을 경우 접속된 클라이언트 세션을 끊도록 설정 [상세 조치 사례] l XenServer, KVM [사용자 Shell Session Timeout 설정] Step 1\) 호스트에 접속 Step 2\) echo \$TMOUT 명령어를 이용하여 사용자 Shell Session Timeout 설정 확인 \$ echo \$TMOUT Step 3\) Session Timeout 10분을 초과하는 경우 아래 두 라인 추가 \$ vi /etc/profile readonly TMOUT=600; export TMOUT Step 4\) 변경된 설정 적용 \$ source /etc/profile"

    local output
    output=$({
        ( echo $TMOUT )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="웹 콘솔 및 사용자 Shell Session Timeout 설정이 600초\(10분\)를 초과하여 설정된 경우"
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
        local numeric_value
        numeric_value=$(first_numeric_value "$output")
        if [ -z "$numeric_value" ] || [ "$numeric_value" -eq 0 ] 2>/dev/null; then
            status="취약"
            detail="웹 콘솔 및 사용자 Shell Session Timeout 설정이 600초\(10분\)를 초과하여 설정된 경우"
        else
            if [ "$numeric_value" -le 600 ] 2>/dev/null; then
                status="양호"
                detail="웹 콘솔 및 사용자 Shell Session Timeout 설정이 600초\(10분\) 이하로 설정된 경우"
            else
                status="취약"
                detail="웹 콘솔 및 사용자 Shell Session Timeout 설정이 600초\(10분\)를 초과하여 설정된 경우"
            fi
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-01" "가상화 장비 > 1. 계정 관리" "계정 로그오프/세션 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-02: 가상화 장비 외부접속 차단
check_ISMS_HV_02() {
    local status="양호"
    local detail=""
    local cmd="iptables -nL --line-number; IPTables IP; iptables -I RH-Firewall-1-INPUT 1 -p tcp -s --dport 22 -j"
    local cur_state=""
    local remediation="호스트에서 제공하는 방화벽 애플리케이션을 이용하여 서비스 접속 허용 IP 등록 설정 [상세 조치 사례] l XenServer, KVM [IPTables를 통한 접근 통제] Step 1\) 호스트 접속 \$ iptables -nL --line-number Chain INPUT \(policy ACCEPT\) num target prot opt source destination 1 xapi_nbd_input_chain tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:10809 2 ACCEPT 47 -- 0.0.0.0/0 0.0.0.0/0 3 RH-Firewall-1-INPUT all -- 0.0.0.0/0 0.0.0.0/0 … 중간 생략 … Chain RH-Firewall-1-INPUT \(2 references\) num target prot opt source destination 1 ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 2 ACCEPT icmp -- 0.0.0.0/0 0.0.0.0/0 icmptype 255 3 ACCEPT udp -- 0.0.0.0/0 0.0.0.0/0 udp dpt:67 4 ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 ctstate RELATED,ESTABLISHED 5 ACCEPT udp -- 0.0.0.0/0 0.0.0.0/0 ctstate NEW udp dpt:694 11. 가상화 장비 Step 2\) IPTables 정책 목록을 통해 접속 IP 제한 설정 확인 Step 3\) SSH 원격 접속을 허용된 IP로만 제한 \$ iptables -I RH-Firewall-1-INPUT 1 -p tcp -s <허용 IP> --dport 22 -j ACCEPT \$ iptables -I RH-Firewall-1-INPUT 2 -p tcp -s 0.0.0.0/0 --dport 22 -j DROP Step 4\) IPTables의 변경된 정책 저장 및 서비스 재시작 \$ service iptables save \$ service iptables restart"

    status="수동점검"
    detail="서비스 상태 수동 확인 필요. 허용된 IP에서만 관리 콘솔 및 원격 접속이 가능하도록 제한된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-02" "가상화 장비 > 1. 계정 관리" "가상화 장비 외부접속 차단" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-04: 가상화 장비 계정 권한 관리
check_ISMS_HV_04() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:; userdel -r"
    local cur_state=""
    local remediation="불필요한 공용 계정 및 퇴사자 계정 제거 [상세 조치 사례] l XenServer, KVM Step 1\) 호스트 접속 Step 2\) 등록되어 있는 계정 확인 \$ grep /bin/bash /etc/passwd | cut -f1 -d: root user1 Step 3\) 불필요한 계정이 존재하는 경우 해당 계정 삭제 \$ userdel -r <계정명>"

    local output
    output=$({
        ( get_process_snapshot "/bin/bash" )
        ( userdel -r )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 공용 계정 및 퇴사자 계정이 존재하지 않은 경우"
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

    add_result "ISMS-HV-04" "가상화 장비 > 1. 계정 관리" "가상화 장비 계정 권한 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-05: 가상화 장비 사용자 인증 강화
check_ISMS_HV_05() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:; gpasswd -d user1 users"
    local cur_state=""
    local remediation="불필요한 권한이 부여된 계정에 대한 권한 제거 [상세 조치 사례] l KVM Step 1\) 호스트에 접속 Step 2\) bash 계정 목록 확인 \$ grep /bin/bash /etc/passwd | cut -f1 -d: root user1 Step 3\) 불필요한 계정 제거 \$ gpasswd -d user1 users"

    local output
    output=$({
        ( get_process_snapshot "/bin/bash" )
        ( gpasswd -d user1 users )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="계정별 불필요한 권한이 부여되지 않은 경우"
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

    add_result "ISMS-HV-05" "가상화 장비 > 1. 계정 관리" "가상화 장비 사용자 인증 강화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-06: 비밀번호 관리정책 설정
check_ISMS_HV_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="로그인 계정 비밀번호를 관리 정책에 맞게 설정 [상세 조치 사례] l KVM [RHEL 8 이후 버전 기반 리눅스] Step 1\) 아래 경로 설정 파일 확인 /etc/security/faillock.conf 11. 가상화 장비 /etc/security/pwquality.conf Step 2\) 비밀번호 정책 설정이 되어 있지 않으면 적용 설정 비밀번호 정책 설정 예시\(UNIX 기반\) 예시\)password requisite pam_cracklib.so try_first_pass retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1"

    local config_file="/etc/security/faillock.conf"
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

    add_result "ISMS-HV-06" "가상화 장비 > 1. 계정 관리" "비밀번호 관리정책 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-07: 계정 잠금 임계값 설정
check_ISMS_HV_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="로그인 시도 실패 횟수 제한 설정 [상세 조치 사례] l KVM Step 1\) 예시\) RHEL 8 이후 버전 기반 리눅스 아래 경로 설정 파일 확인 /etc/security/faillock.conf /etc/security/pwquality.conf Step 2\) 비밀번호 정책 설정이 되어있지 않으면 적용 설정 비밀번호 정책 설정 예시 # vi /etc/pam.d/system-auth auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root account required /lib/security/pam_tally.so no_magic_root reset 812"

    local config_file="/etc/security/faillock.conf"
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

    add_result "ISMS-HV-07" "가상화 장비 > 1. 계정 관리" "계정 잠금 임계값 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-08: 시스템 사용 주의사항 출력 설정
check_ISMS_HV_08() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/ssh/sshd_config | grep Banner; echo ptp_kvm > /etc/modules-load.d/ptp_kvm.conf; echo refclock PHC /dev/ptp0 poll 2 >> /etc/chrony.conf"
    local cur_state=""
    local remediation="시스템 사용 주의사항 출력 설정 [상세 조치 사례] l KVM Step 1\) 배너 설정 여부 확인 # cat /etc/ssh/sshd_config | grep \"Banner\" Step 2\) /etc/sshd/sshd_config 파일에 배너 내용 삽입 # vi /etc/sshd/sshd_config Banner /etc/issue.net \(예시\) This system is for the use of authorized users only. l KVM Step 1\) PHC 사용 여부 확인 Step 2\) 사용하지 않으면 활성화 적용 # echo ptp_kvm > /etc/modules-load.d/ptp_kvm.conf Step 3\) /dev/ptp0 시계를 chrony 구성에 대한 참조로 추가 설정 # echo \"refclock PHC /dev/ptp0 poll 2\" >> /etc/chrony.conf Step 4\) chrony 데몬 다시 시작 # systemctl restart chronyd"

    local config_file="/etc/modules-load.d/ptp_kvm.conf"
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

    add_result "ISMS-HV-08" "가상화 장비 > 2. 시스템 서비스 관리" "시스템 사용 주의사항 출력 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-10: SNMP Community String 복잡성 적용
check_ISMS_HV_10() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="SNMP Community String을 복잡도를 만족하는 값으로 설정 [상세 조치 사례] l KVM Step 1\) SNMP 파일에서 Community String 값 확인 sudo vi /etc/snmp/snmpd.conf Step 2\) Community String 설정 후 snmp 서비스 재시작 sudo systemctl enable snmpd sudo systemctl start snmpd"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. SNMP Community String이 복잡도를 만족하는 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-10" "가상화 장비 > 2. 시스템 서비스 관리" "SNMP Community String 복잡성 적용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-14: 원격 로그 서버 이용
check_ISMS_HV_14() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="원격 로그 서버 또는 스토리지 연동 설정 [상세 조치 사례] l KVM Step 1\) 원격 로그 서버 사용 확인 Step 2\) \(호스트 서버\) /etc/rsyslog.conf 파일 확인 Step 3\) 원격 로그 서버 전송 지시어 확인 Step 4\) logger 명령어를 통해 전송 여부 확인"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 원격 로그 서버 또는 스토리지가 연동 설정된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-14" "가상화 장비 > 2. 시스템 서비스 관리" "원격 로그 서버 이용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-15: 시스템 주요 이벤트 로그 설정
check_ISMS_HV_15() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/libvirt/libvirtd.conf; log_level ="
    local cur_state=""
    local remediation="로그 기록 정책을 내부 정책에 부합하게 설정 [상세 조치 사례] l KVM Step 1\) 호스트에 접속 Step 2\) libvirt 설정파일을 확인하여 로그 레벨 확인 \$ cat /etc/libvirt/libvirtd.conf Step 3\) libvirt 설정파일의 log_level 설정 구문 수정 \$ log_level = Step 4\) 변경 사항 적용을 위해 libvirt 데몬 재시작 \$ systemctl restart libvirtd.service ※ log.level 설정값 레벨 로깅 수준 설명 ERROR 오류 메시지만 기록함 WARNING 경고 및 오류를 기록함 INFO 디버그 항목이 아닌 모든 항목을 기록함 DEBUG 디버그 항목 및 모든 항목을 기록함 836"

    local output
    output=$({
        ( cat /etc/libvirt/libvirtd.conf )
        ( log_level = )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="로그 기록 정책이 내부 정책에 부합하게 설정된 경우"
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
            detail="로그 기록 정책이 내부 정책에 부합하게 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="로그 기록 정책이 내부 정책에 부합하게 설정되지 않은 경우"
        else
            status="취약"
            detail="로그 기록 정책이 내부 정책에 부합하게 설정되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-15" "가상화 장비 > 2. 시스템 서비스 관리" "시스템 주요 이벤트 로그 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== KVM CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/16] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-KVM-01"; check_CSAP_KVM_01
progress "CSAP-KVM-02"; check_CSAP_KVM_02
progress "CSAP-KVM-03"; check_CSAP_KVM_03
progress "CSAP-KVM-04"; check_CSAP_KVM_04
progress "CSAP-KVM-05"; check_CSAP_KVM_05
progress "CSAP-KVM-06"; check_CSAP_KVM_06
progress "ISMS-HV-01"; check_ISMS_HV_01
progress "ISMS-HV-02"; check_ISMS_HV_02
progress "ISMS-HV-04"; check_ISMS_HV_04
progress "ISMS-HV-05"; check_ISMS_HV_05
progress "ISMS-HV-06"; check_ISMS_HV_06
progress "ISMS-HV-07"; check_ISMS_HV_07
progress "ISMS-HV-08"; check_ISMS_HV_08
progress "ISMS-HV-10"; check_ISMS_HV_10
progress "ISMS-HV-14"; check_ISMS_HV_14
progress "ISMS-HV-15"; check_ISMS_HV_15

echo ""
echo ""

###############################################################################
# Generate JSON output
###############################################################################

# System info
SYS_HOSTNAME=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr '
' '  ' | sed 's/  */ /g; s/^ //; s/ $//' )
SYS_OS=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d'"' -f2)
SYS_KERNEL=$(uname -r 2>/dev/null)
SYS_DATE=$(date '+%Y-%m-%d %H:%M:%S')
SYS_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

# Count results
total_checks=${#results[@]}
good_count=0
vuln_count=0
na_count=0
manual_count=0

for r in "${results[@]}"; do
    case "$r" in
        *'"status":"양호"'*) good_count=$((good_count + 1)) ;;
        *'"status":"취약"'*) vuln_count=$((vuln_count + 1)) ;;
        *'"status":"N/A"'*) na_count=$((na_count + 1)) ;;
        *'"status":"수동점검"'*) manual_count=$((manual_count + 1)) ;;
    esac
done

# Build JSON
{
    echo '{'
    echo '  "scan_info": {'
    echo "    \"hostname\": \"$SYS_HOSTNAME\","
    echo "    \"os\": \"$SYS_OS\","
    echo "    \"kernel\": \"$SYS_KERNEL\","
    echo "    \"ip\": \"$SYS_IP\","
    echo "    \"scan_date\": \"$SYS_DATE\","
    echo '    "platform": "KVM",'
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
    for r in "${results[@]}"; do
        if [ "$first" = true ]; then
            echo "    $r"
            first=false
        else
            echo "    ,$r"
        fi
    done

    echo '  ]'
    echo '}'
} > "$OUTPUT_FILE"

echo "===== KVM CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
