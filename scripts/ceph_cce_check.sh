#!/bin/bash
###############################################################################
# Ceph CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash ceph_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_ceph_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Ceph helper ---
CEPH_CONF="${CEPH_CONF:-/etc/ceph/ceph.conf}"

run_ceph_cmd() {
    ceph "$@" 2>/dev/null
}


# --- Pre-flight: Ceph 설치 확인 및 경로 탐지 ---
CEPH_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    CEPH_BIN=$(command -v ceph 2>/dev/null)
    local rados_bin
    rados_bin=$(command -v rados 2>/dev/null)

    # 2) 프로세스에서 ceph-mon/ceph-osd 탐지
    if ps -ef 2>/dev/null | grep -qE '[c]eph-mon|[c]eph-osd|[c]eph-mgr'; then
        APP_FOUND="true"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ ! -f "$CEPH_CONF" ]; then
        for f in /etc/ceph/ceph.conf /usr/local/etc/ceph/ceph.conf; do
            if [ -f "$f" ]; then
                CEPH_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$CEPH_BIN" ] && [ -z "$rados_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'ceph-common\|ceph-mon' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'ceph' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$CEPH_BIN" ] || [ -n "$rados_bin" ] || [ -f "$CEPH_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Ceph 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Ceph-01: Keyring 파일 소유자 및 권한 확인
check_CSAP_Ceph_01() {
    local status="양호"
    local detail=""
    local cmd="ls /keyring; ls -l /etc/ceph/*.keyring"
    local cur_state=""
    local remediation="￭ Keyring 소유자 및 파일 권한 변경 1\) # chown root:root [keyring 파일 디렉터리]/keyring 파일 2\) # chmod 400 [keyring 파일 디렉터리]/keyring 파일"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/keyring
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "400")
                cur_state+="$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_2
    target_spec_2=/etc/ceph/*.keyring
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "400")
                cur_state+="$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_2). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_2). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
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
    [ -z "$detail" ] && detail="Keyring 파일 소유자가 root 또는 관리자" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Ceph-01" "패치 관리" "Keyring 파일 소유자 및 권한 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Ceph-02: SSH 인증키 파일 관리
check_CSAP_Ceph_02() {
    local status="양호"
    local detail=""
    local cmd="ls -ld ~/.ssh; ls -l ~/.ssh"
    local cur_state=""
    local remediation="￭ .ssh 디렉터리 권한 변경 1\) # chmod 700 ~/.ssh ￭ ssh 키 파일 권한 변경 1\) # chmod 600 ~/.ssh/키 파일"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/.ssh
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "700")
                cur_state+="$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
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
    [ -z "$detail" ] && detail=".ssh 디렉터리 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Ceph-02" "파일 및 디렉터리" "SSH 인증키 파일 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Ceph-03: Ceph 설정 파일 소유자 및 권한 확인
check_CSAP_Ceph_03() {
    local status="양호"
    local detail=""
    local cmd="ls -l /ceph.conf"
    local cur_state=""
    local remediation="￭ Ceph 설정 파일 권한 변경 1\) # chmod o-w [Ceph 설정 디렉터리]/ceph.conf"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/ceph.conf
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
                cur_state+="$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
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
    [ -z "$detail" ] && detail="Ceph 설정 파일 Other 권한에 쓰기 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Ceph-03" "파일 및 디렉터리" "Ceph 설정 파일 소유자 및 권한 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Ceph-04: Ceph 인증 프로토콜 적용
check_CSAP_Ceph_04() {
    local status="양호"
    local detail=""
    local cmd="cat /ceph.conf"
    local cur_state=""
    local remediation="￭ 설정 파일에서 [global] 영역에 CEPHX 프로토콜 적용 1\) # vi [Ceph 설정 디렉터리]/ceph.conf"

    local output
    output=$({
        ( cat /ceph.conf )
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
            detail="Ceph 인증 프로토콜을 사용하는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="Ceph 인증 프로토콜을 사용하지 않는 경우"
        else
            status="취약"
            detail="Ceph 인증 프로토콜을 사용하지 않는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Ceph-04" "보안 설정" "Ceph 인증 프로토콜 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Ceph-05: root 이외의 관리자 계정 사용
check_CSAP_Ceph_05() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/sudoers"
    local cur_state=""
    local remediation="￭ 별도의 관리자 계정 생성 예시\) 1\) 계정 생성 # useradd admin 2\) 생성된 계정에 관리자 계정 부여 # chmod 660 /etc/sudoers 명령어를 통해 sudoers 파일 쓰기 권한 부여 # vi /etc/sudoers 명령어 입력 후 아래와 같이 작성 # chmod 440 /etc/sudoers 명령어를 통해 sudoers 파일 쓰기 권한 제거"

    local output
    output=$({
        ( cat /etc/sudoers )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="root 계정을 통해 Ceph를 관리하는 경우"
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
            status="취약"
            detail="root 계정을 통해 Ceph를 관리하는 경우"
        else
            status="양호"
            detail="별도의 관리자 계정을 사용하는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Ceph-05" "보안 설정" "root 이외의 관리자 계정 사용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Ceph-06: Selinux 활성화
check_CSAP_Ceph_06() {
    local status="양호"
    local detail=""
    local cmd="getenforce"
    local cur_state=""
    local remediation="￭ SELinux 활성화 1\) # vi /etc/selinux/config"

    local output
    output=$({
        ( getenforce )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="SELinux가 활성화된 경우"
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
            detail="SELinux가 활성화된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="SELinux가 비활성화된 경우"
        else
            status="취약"
            detail="SELinux가 비활성화된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Ceph-06" "" "Selinux 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Ceph-07: 최신 보안 패치 적용
check_CSAP_Ceph_07() {
    local status="양호"
    local detail=""
    local cmd="ceph -v"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 적용 1\) 최신 보안 패치 업데이트가 발표되었을 경우, 시스템 영향도를 파악하여 충분한 테스트를 진행한 후 적용 권고 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( ceph -v )
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

    add_result "CSAP-Ceph-07" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Ceph CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/7] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Ceph-01"; check_CSAP_Ceph_01
progress "CSAP-Ceph-02"; check_CSAP_Ceph_02
progress "CSAP-Ceph-03"; check_CSAP_Ceph_03
progress "CSAP-Ceph-04"; check_CSAP_Ceph_04
progress "CSAP-Ceph-05"; check_CSAP_Ceph_05
progress "CSAP-Ceph-06"; check_CSAP_Ceph_06
progress "CSAP-Ceph-07"; check_CSAP_Ceph_07

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
    echo '    "platform": "Ceph",'
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

echo "===== Ceph CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
