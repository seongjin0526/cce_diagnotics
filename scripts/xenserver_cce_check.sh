#!/bin/bash
###############################################################################
# Xenserver CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash xenserver_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_xenserver_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Xenserver helper ---
run_xe() {
    xe "$@" 2>/dev/null
}


# --- Pre-flight: Xenserver 설치 확인 및 경로 탐지 ---
XE_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    XE_BIN=$(command -v xe 2>/dev/null)

    # 2) 프로세스에서 xapi 탐지
    if ps -ef 2>/dev/null | grep -q '[x]api'; then
        APP_FOUND="true"
    fi

    # 3) Xenserver 환경 파일 확인
    if [ -f "/etc/xensource-inventory" ]; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$XE_BIN" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Xenserver 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Xenserver-02 / ISMS-HV-04: 일반계정 root 권한 관리
check_CSAP_Xenserver_02() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/passwd; grep /bin/bash /etc/passwd | cut -f1 -d:; userdel -r"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ root 및 시스템 계정 외 UID가 0인 계정의 UID 값 변경 \(예시\) test 계정의 UID 를 2002로 바꿀 경우 # usermod -u 2002 test [주요기반시설 가이드] 불필요한 공용 계정 및 퇴사자 계정 제거 [상세 조치 사례] l XenServer, KVM Step 1\) 호스트 접속 Step 2\) 등록되어 있는 계정 확인 \$ grep /bin/bash /etc/passwd | cut -f1 -d: root user1 Step 3\) 불필요한 계정이 존재하는 경우 해당 계정 삭제 \$ userdel -r <계정명>"

    local output
    output=$({
        ( cat /etc/passwd )
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

    add_result "CSAP-Xenserver-02 / ISMS-HV-04" "계정 관리" "일반계정 root 권한 관리" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-01: Default 계정 관리
check_CSAP_Xenserver_01() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/passwd | egrep lp:|uucp:|nuucp:"
    local cur_state=""
    local remediation="￭ 불필요한 계정 삭제 # userdel lp # userdel uucp # userdel nuucp ※ 로그인 쉘을 /bin/false로 수정하는 것은 보안상 문제가 발생할 수 있으므로 삭제를 권고함 ※ /nologin 설정은 양호로 처리함"

    local output
    output=$({
        ( get_process_snapshot "lp:" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="OS 나 Package 설치 시 기본으로 생성되는"
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

    add_result "CSAP-Xenserver-01" "패치 및 로그 관리" "Default 계정 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-03: passwd 파일 권한 설정
check_CSAP_Xenserver_03() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/passwd"
    local cur_state=""
    local remediation="￭ /etc/passwd 파일의 권한 변경 # chmod 644 /etc/passwd # chown root /etc/passwd"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/passwd
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="패스워드 파일의 소유자가 root이고, 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-03" "계정 관리" "passwd 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-04: group 파일 권한 설정
check_CSAP_Xenserver_04() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/group"
    local cur_state=""
    local remediation="￭ /etc/group 파일의 권한 변경 # chmod 644 /etc/group # chown root /etc/group"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/group
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/group 파일의 소유자가 root\(또는" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-04" "계정 관리" "group 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-05: 패스워드 사용규칙 적용
check_CSAP_Xenserver_05() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/login.defs | grep -i PASS_MAX_DAYS; cat /etc/login.defs | grep -i PASS_MIN_DAYS; cat /etc/login.defs | grep -i PASS_MIN_LEN"
    local cur_state=""
    local remediation="￭ /etc/login.defs에서 아래와 같은 설정으로 변경 \(단위: 일\) #vi /etc/login.defs PASS_MIN_LEN 8 PASS_MAX_DAYS 70 PASS_MIN_DAYS 7"

    local output
    output=$({
        ( get_process_snapshot "pass_max_days" )
        ( get_process_snapshot "pass_min_days" )
        ( get_process_snapshot "pass_min_len" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="패스워드 정책에 따른 설정이 적용된 경우"
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
            detail="패스워드 정책에 따른 설정이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="패스워드 정책에 따라 설정이 적용되어 있지"
        else
            status="취약"
            detail="패스워드 정책에 따라 설정이 적용되어 있지"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-05" "계정 관리" "패스워드 사용규칙 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-06: 로그인이 불필요한 계정 shell 제한
check_CSAP_Xenserver_06() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/passwd"
    local cur_state=""
    local remediation="￭ 로그인이 필요 없는 계정의 shell 설정 변경 #vi /etc/passwd를 실행하여 아래와 같은 설정으로 변경 \(단위: 주\) 예\) daemon 계정이 로그인하지 못하도록 설정 # vi /etc/passwd daemon:x:1:1::/:/sbin/ksh \(수정 전\) daemon:x:1:1::/:/bin/false \(수정 후\)"

    local output
    output=$({
        ( cat /etc/passwd )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="시스템 계정 중 로그인이 불필요한 계정에"
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

    add_result "CSAP-Xenserver-06" "계정 관리" "로그인이 불필요한 계정 shell 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-07: SU(Select User) 사용 제한
check_CSAP_Xenserver_07() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/pam.d/su | grep -v trust | grep pam_wheel.so | grep use_uid"
    local cur_state=""
    local remediation="￭ SU 사용 제한 설정 1. /etc/pam.d/su 파일을 아래와 같이 설정. auth sufficient /lib/security/pam_rootok.so auth required /lib/security/pam_wheel.so use_uid 2. wheel group 생성 # groupadd wheel 3. /etc/group 파일에서 wheel 그룹에 su 명령어를 사용할 사용자를 추가 # usermod -G wheel username"

    local output
    output=$({
        ( get_process_snapshot "trust" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="/etc/pam.d/su 파일에 auth required"
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
            detail="/etc/pam.d/su 파일에 auth required"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="/etc/pam.d/su 파일에 auth required"
        else
            status="취약"
            detail="/etc/pam.d/su 파일에 auth required"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-07" "계정 관리" "SU\(Select User\) 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-08: 사용자 UMASK(User Mask) 설정
check_CSAP_Xenserver_08() {
    local status="양호"
    local detail=""
    local cmd="umask; cat /etc/profile | grep -i umask"
    local cur_state=""
    local remediation="￭ UMASK 변경 1. /etc/pam.d/su 파일을 아래와 같이 설정. # umask 022 # vi /etc/profile umask 022 행 추가 ※ 계정의 Start Profile\(/etc/profile, /etc/default/login, .cshrc, .kshrc, .bashrc, .login, .profile 등\)에 명령을 추가하면, 사용자가 로그인 후에도 변경된 UMASK 값을 적용받음"

    local output
    output=$({
        ( umask )
        ( get_process_snapshot "umask" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="현재 시스템의 UMASK가 022 또는 027로"
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
        numeric_value=$(printf '%s\n' "$output" | grep -Eo "[0-7]{3}" | head -1)
        if [ -z "$numeric_value" ]; then
            status="수동점검"
            detail="현재 시스템의 UMASK가 022 또는 027로"
        else
            if [ $((8#$numeric_value)) -ge $((8#27)) ] 2>/dev/null; then
                status="양호"
                detail="현재 시스템의 UMASK가 022 또는 027로"
            else
                status="취약"
                detail="현재 시스템의 UMASK가 설정되어 있지"
            fi
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-08" "파일 시스템" "사용자 UMASK\(User Mask\) 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-09: SUID(Set User-Id), SGID(Set Group-Id)
check_CSAP_Xenserver_09() {
    local status="양호"
    local detail=""
    local cmd="find / -user root -type f \\\( -perm -4000 -o -perm -2000 \\\) -exec ls -lg {} \\;"
    local cur_state=""
    local remediation="￭ 불필요한 SUID, SGID 제거 # chmod -s [파일명]"

    local output
    output=$({
        ( find / -user root -type f \( -perm -4000 -o -perm -2000 \) -exec ls -lg {} \; )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 SUID, SGID가 설정되어 있지"
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
        local uid_zero_count
        uid_zero_count=$(printf '%s\n' "$output" | grep -Ec "^[^:]+:[^:]*:0:|uid=0")
        if [ "${uid_zero_count:-0}" -le 1 ] 2>/dev/null; then
            status="양호"
            detail="불필요한 SUID, SGID가 설정되어 있지"
        else
            status="취약"
            detail="불필요한 SUID, SGID가 설정되어 있는"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-09" "파일 시스템" "SUID\(Set User-Id\), SGID\(Set Group-Id\)" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-10: xsconsole 파일 권한 설정
check_CSAP_Xenserver_10() {
    local status="양호"
    local detail=""
    local cmd="ls -al /usr/bin/xsconsole"
    local cur_state=""
    local remediation="￭ xsconsole 파일 소유자를 root로 변경 및 타사용자 권한 제거 1. xsconsole 파일 소유자를 root로 변경 # chown root /usr/bin/xsconsole 2. xsconsole 파일에 타사용자 권한을 제거 # chmod o-w /usr/bin/xsconsole ※ 해당 파일에 링크가 설정되어 있다면 링크된 원본 파일 소유자를 변경함"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/unknown_config_file
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/usr/bin/xsconsole 파일의 소유자가" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-10" "파일 시스템" "xsconsole 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-11: Crontab 파일 권한 설정 및 관리
check_CSAP_Xenserver_11() {
    local status="양호"
    local detail=""
    local cmd="ls -al /backup/OS_backup.sh; ls -al /opt/sfm/vacuum"
    local cur_state=""
    local remediation="￭ Crontab 관련 파일에 타사용자 쓰기 권한 제거 # chmod o-w /etc/crontab # chmod o-w /etc/cron.daily/* # chmod o-w /etc/cron.hourly/* # chmod o-w /etc/cron.monthly/* # chmod o-w /etc/cron.weekly/* # chmod o-w /var/spool/cron/* ￭ Crontab 예약 파일 소유자 # ls -al [file] # chmod 744 [file]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/backup/OS_backup.sh
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
    target_spec_2=/opt/sfm/vacuum
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
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
    local target_spec_3
    target_spec_3=/cron
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_3). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/etc/crontab
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_4). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_4). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_5
    target_spec_5=/etc/cron.daily/*
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_5). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_5). " ;;
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
    [ -z "$detail" ] && detail="cron 파일 소유자가 root이며, 타사용자의" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-11" "파일 시스템" "Crontab 파일 권한 설정 및 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-12: /etc/profile 파일 권한 설정
check_CSAP_Xenserver_12() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/profile"
    local cur_state=""
    local remediation="￭ /etc/profile 파일 소유자 변경 및 타사용자 쓰기 권한 제거 1. /etc/profile 파일 소유자 변경 # chown root /etc/profile 2. /etc/profile 타사용자 쓰기 권한 제거 # chmod o-w /etc/profile"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/profile
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/profile의 소유자가 root\(또는" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-12" "파일 시스템" "/etc/profile 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-13: /etc/hosts 파일 권한 설정
check_CSAP_Xenserver_13() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/hosts"
    local cur_state=""
    local remediation="￭ /etc/hosts 파일 소유자 변경 및 타사용자 쓰기 권한 제거 1. /etc/hosts 파일 소유자 변경 # chown root /etc/hosts 2. /etc/hosts 타사용자 쓰기 권한 제거 # chmod o-w /etc/hosts"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/hosts
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/hosts 파일의 소유자가 root\(또는" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-13" "파일 시스템" "/etc/hosts 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-14: /etc/issue 파일 권한 설정
check_CSAP_Xenserver_14() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/issue"
    local cur_state=""
    local remediation="￭ /etc/issue 파일 소유자 변경 및 타사용자 쓰기 권한 제거 1. /etc/issue 파일 소유자 변경 # chown root /etc/issue 2. /etc/issue 타사용자 쓰기 권한 제거 # chmod o-w /etc/issue"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/issue
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="/etc/issue 파일의 소유자가 root \(또는" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-14" "파일 시스템" "/etc/issue 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-15: 사용자 홈 디렉터리 및 파일 관리
check_CSAP_Xenserver_15() {
    local status="양호"
    local detail=""
    local cmd="ls -al"
    local cur_state=""
    local remediation="￭ 사용자 홈 디렉터리 안의 설정 파일에 타사용자 쓰기 권한 제거 # chmod o-w [홈 디렉터리 경로] [파일명]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/passwd
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
    [ -z "$detail" ] && detail="User 별 홈 디렉터리의 타 사용자의 쓰기" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-15" "파일 시스템" "사용자 홈 디렉터리 및 파일 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-16: 주요 디렉터리 파일 권한 설정
check_CSAP_Xenserver_16() {
    local status="양호"
    local detail=""
    local cmd="ls -ldb /usr/bin/xsconsole /usr/lib/xsconsole /opt /sbin /etc/ /bin /usr/bin/"
    local cur_state=""
    local remediation="￭ 디렉터리 소유자 변경 및 타 사용자 쓰기 권한 제거 1. 디렉터리 소유자 변경 # chown root [디렉터리명] 2. 디렉터리 권한 변경 # chmod o-w [디렉터리명]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/usr/lib/xsconsole
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
    target_spec_2=/sbin
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
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
    local target_spec_3
    target_spec_3=/etc/
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_3). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/usr/sbin
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_4). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_4). " ;;
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
    [ -z "$detail" ] && detail="디렉터리의 권한을 root\(또는 bin\) 소유의 타" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-16" "파일 시스템" "주요 디렉터리 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-17: PATH 환경변수 설정
check_CSAP_Xenserver_17() {
    local status="양호"
    local detail=""
    local cmd="echo \$PATH"
    local cur_state=""
    local remediation="￭ root 계정의 환경변수 설정파일\(.profile, .cshrc등\)과 \"/etc/profile\" 등에서 PATH 환경변수에 포함된 현재 디렉터리를 나타내는 \".\"을 제거"

    local output
    output=$({
        ( echo $PATH )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="현재 위치를 의미하는 \".\"이 없거나, PATH"
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
        if printf '%s\n' "$output" | grep -Eq "(^|[:=])\.(:|$)"; then
            status="취약"
            detail="현재 위치를 의미하는 \".\"이 앞이나 중간에"
        else
            status="양호"
            detail="현재 위치를 의미하는 \".\"이 없거나, PATH"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-17" "파일 시스템" "PATH 환경변수 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-18: /etc/service 파일 권한 설정
check_CSAP_Xenserver_18() {
    local status="양호"
    local detail=""
    local cmd="ls -alL /etc/services"
    local cur_state=""
    local remediation="￭ /etc/services 소유자 변경 및 타사용자 쓰기 권한 제거 1. /etc/service 파일 소유자 변경 # chown root /etc/service 2. /etc/service 파일 타사용자 쓰기 권한 제거 # chmod o-w /etc/service"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/services
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
    target_spec_2=/etc/service
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
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
    [ -z "$detail" ] && detail="/etc/service 파일의 소유자가 root \(또는" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-18" "파일 시스템" "/etc/service 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-19: 부팅스크립트 파일 권한 설정
check_CSAP_Xenserver_19() {
    local status="양호"
    local detail=""
    local cmd="ls -alL /opt/*/*"
    local cur_state=""
    local remediation="￭ 기타 중요 파일 소유자 변경 및 타사용자 쓰기 권한 제거 1. 기타 중요 파일 소유자 변경 # chown root [기타 중요 파일] 2. 기타 중요 파일 타사용자 쓰기 권한 제거 # chmod o-w [기타 중요 파일]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/opt/*/*
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
    target_spec_2=/etc/rc*.d
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
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
    local target_spec_3
    target_spec_3=/etc/inittab
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_3). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/etc/syslog.conf
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_4). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_4). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_5
    target_spec_5=/etc/snmp/snmpd.conf
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_5). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_5). " ;;
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
    [ -z "$detail" ] && detail="기타 중요 파일의 소유자가 root \(또는" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-19" "파일 시스템" "부팅스크립트 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-20: 서비스 Banner 관리
check_CSAP_Xenserver_20() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/ssh/sshd_config | grep Banner"
    local cur_state=""
    local remediation="￭ Banner 설정 1. /etc/ssh/sshd_config 파일에 Banner 설정 # vi /etc/ssh/sshd_config Banner /etc/issue.net 2. /etc/issue.net 파일을 생성하고 경고 메시지 삽입 \(예시\) ################################################################# This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel. In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored. Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials. #################################################################"

    local config_file="/etc/ssh/sshd_config"
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

    add_result "CSAP-Xenserver-20" "네트워크 서비스 및" "서비스 Banner 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-21: session timeout 설정
check_CSAP_Xenserver_21() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/profile | grep TMOUT"
    local cur_state=""
    local remediation="￭ /etc/profile 파일에서 설정 /etc/profile 파일 안에 time out 설정 # vi /etc/profile TMOUT=300 export TMOUT ￭ xsconsole에서 설정 1. xsconsole → Authentication → Change Auto-Logout Time → 로그인 2. Timeout \(minutes\)에서 설정"

    local output
    output=$({
        ( get_process_snapshot "tmout" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="/etc/profile\"과 \"xsconsole\"에 time"
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
            detail="/etc/profile\"나 \"xsconsole\" 한쪽에만"
        else
            status="양호"
            detail="/etc/profile\"과 \"xsconsole\"에 time"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-21" "네트워크 서비스 및" "session timeout 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-22: root 계정의 ssh 및 sftp 접근 제한
check_CSAP_Xenserver_22() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/pam.d/login | grep pam_securetty.so; cat /etc/ssh/sshd_config | grep PermitRootLogin"
    local cur_state=""
    local remediation="￭ root 원격 접속 제한 설정 1. /etc/pam.d/login 파일설정에 추가 설정 # vi /etc/pam.d/login auth required /lib/security/pam_securetty.so 2. /etc/ssh/sshd_config파일 설정 수정\(주석제거 또는 신규 삽입\) # vi /etc/ssh/sshd_config PermitRootLogin no"

    local config_file="/etc/pam.d/login"
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

    add_result "CSAP-Xenserver-22" "네트워크 서비스 및" "root 계정의 ssh 및 sftp 접근 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-23: SSH(Secure Shell) 버전 취약점
check_CSAP_Xenserver_23() {
    local status="양호"
    local detail=""
    local cmd="ssh -V"
    local cur_state=""
    local remediation="￭ ssh 서비스 필요시 OpenSSH 업데이트 권장 ￭ ssh 서비스 불필요 시 1. 실행 중인 서비스 중지 # ps -ef | grep sshd root 414 0.0 0.7 2672 1692 /usr/sbin/sshd # kill 9 414 2. SSH가 시작되지 않도록 시작스크립트의 파일명 변경 \(OS마다 시작 스크립트 위치가 다름\) # ls -al /etc/rc*. d/* | grep sshd \(시작스크립트 파일 위치 확인\) # mv /etc/rc2.d/S55sshd /etc/rc2.d/_S55sshd ※ SSH 설정에 따라 /etc/ssh/sshd_config 파일 위치가 다를 수 있음"

    local output
    output=$({
        ( ssh -V )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="취약한 OpenSSH 버전일 경우"
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
            detail="취약한 OpenSSH 버전일 경우"
        else
            status="양호"
            detail="벤더 사가 권장하는 OpenSSH 버전일 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-23" "" "SSH\(Secure Shell\) 버전 취약점" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-24: 불필요한 서비스 제거
check_CSAP_Xenserver_24() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep"
    local cur_state=""
    local remediation="￭ 서비스 필요시 최신 버전 설치 ￭ 서비스 불필요 시 1. /etc/xinetd.d\" 디렉터리 내의 서비스 파일 수정 # vi /etc/xinetd.d/ [서비스 파일명] 2. xinetd.d 디렉터리 내에서 필요없는 서비스를 Disable 을 yes로 설정 /etc/xinetd.d/chargen 파일 service chargen { Disable = yes ... 생략 ... } 3. service 재시작 #service xinetd restart <클라우드 컴퓨팅 서비스에 불필요한 서비스 중지> 불필요한 서비스 중지 # ps -ef | grep [서비스 명] # kill * 9 [프로세스 ID]"

    local output
    output=$({
        ( ps -ef | grep )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 서비스가 비활성화되어 있는 경우"
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
            detail="불필요한 서비스가 비활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 서비스가 활성화되어 있는 경우"
        else
            status="취약"
            detail="불필요한 서비스가 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-24" "네트워크 서비스 및" "불필요한 서비스 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-25: 관리용 원격 접근 제어
check_CSAP_Xenserver_25() {
    local status="양호"
    local detail=""
    local cmd="xsconsole → NetWork and Management Interface → Configure Management"
    local cur_state=""
    local remediation="￭ 관리용 원격 접속 접근제어 설정 1. xsconsole → Network and Management Interface → Configure Management Interface → Login 2. Login 후 나타나는 Management Interface Configuration 화면에서 Disable Management Interface를 선택하여 관리용도로 원격에서의 접근을 차단 설정"

    local output
    output=$({
        ( xsconsole → NetWork and Management Interface → Configure Management )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="xsconsole의 [Network and"
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
            detail="xsconsole의 [Network and"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="xsconsole의 [Network and"
        else
            status="취약"
            detail="xsconsole의 [Network and"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-25" "하이퍼바이저" "관리용 원격 접근 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-26: Remote Shell 접근 제어
check_CSAP_Xenserver_26() {
    local status="양호"
    local detail=""
    local cmd="Xsconsole → remote Service Configuration → Enable/Disable Remote Shell"
    local cur_state=""
    local remediation="￭ Remote Shell 접근 제어 설정 1. xsconsole의 [Remote Service Configuration] 메뉴에서 [Enable/Disable Remote Shell]을 선택한 후 Login 2. Login 후 나타나는 [Configure Remote Shell] 화면에서 \"Disable\"를 선택하여 원격에서의 Shell 접근 차단을 설정"

    local output
    output=$({
        ( Xsconsole → remote Service Configuration → Enable/Disable Remote Shell )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="xsconsole의 [Remote Service"
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
            detail="xsconsole의 [Remote Service"
        else
            status="양호"
            detail="xsconsole의 [Remote Service"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Xenserver-26" "하이퍼바이저" "Remote Shell 접근 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-27: Guest VM 네트워크 분리
check_CSAP_Xenserver_27() {
    local status="양호"
    local detail=""
    local cmd="Xen Master → Xenserver → network vlan →"
    local cur_state=""
    local remediation="￭ Guest VM 네트워크 설정 1. XenCenter → XenServer → Network에서 Add Network 선택 2. 네트워크 생성 화면에서 External Network → Next 3. 생성하려는 VLAN의 이름, 설명을 입력 → Next 4. VLAN을 설정하는 물리적인 NIC 장치를 선택 → VLAN의 태그 선택 → Finish →VAN 생성 ※ 이미 사용중인 태그는 설정할 수 없음 5. Server Networks에서 생성한 VLAN을 확인 6. 네트워크 분리가 필요한 Guest OS를 선택하고, [Network]를 선택한 후 [Add Interface] 선택 ※ Guest OS를 종료되어야 설정할 수 있음. 7. Network에서 생성한 VLAN을 선택 → Add → Guest OS의 Network를 VLAN으로 설정 8. Virtual Network Interfaces에서 Guest OS에 설정된 네트워크를 확인 또는 현재 VLAN으로 설정 확인"

    local output
    output=$({
        ( Xen Master → Xenserver → network vlan → )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="Guest OS \(Virtual Machine\) Group이"
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

    add_result "CSAP-Xenserver-27" "하이퍼바이저" "Guest VM 네트워크 분리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-28: SU 로그 설정
check_CSAP_Xenserver_28() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/syslog.conf | grep authpriv.*; cat /etc/rsyslog.conf | grep authpriv.*"
    local cur_state=""
    local remediation="￭ /etc/syslog.conf 파일에서 설정 \(6버전\) # vi /etc/syslog.conf 파일에서 아래와 같은 설정으로 변경 authpriv.* /var/log/secure # /etc/rc.d/init.d/syslog restart ￭ /etc/rsyslog.conf 파일에서 설정 \(7, 8 버전\) # vi /etc/rsyslog.conf 파일에서 아래와 같은 설정으로 변경 authpriv.* /var/log/secure # systemctl restart rsyslog"

    local config_file="/var/log/secure"
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

    add_result "CSAP-Xenserver-28" "패치 및 로그 관리" "SU 로그 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-29: syslog 설정
check_CSAP_Xenserver_29() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/syslog.conf | egrep info|alert|notice|debug|warn|error | egrep var|log; cat /etc/rsyslog.conf | egrep info|alert|notice|debug|warn|error | egrep var|log"
    local cur_state=""
    local remediation="￭ XenServer 로그 파일 설정 1. /etc/\(r\)syslog.conf 파일을 점검하여, info, alert 등에 대한 로그 파일을 설정 # vi /etc/\(r\)syslog.conf *.notice /var/log/messages *.emerg * *.alert /dev/console # Set info,warn,error to log to syslog by default info;audit;syslog:local6 warn;;syslog:xapi error;;syslog:xapi # Also print everything \(debug<->error\) into xensource.log for easier debugging debug;;file:/var/log/xensource.log info;;file:/var/log/xensource.log warn;;file:/var/log/xensource.log error;;file:/var/log/xensource.log 2. \"\(r\)syslog.conf\"파일을 수정한 후에는 이것이 적용되도록 다음의 명령을 사용하여 syslogd restart # /etc/rc.d/init.d/syslog restart"

    local config_file="/etc/syslog.conf"
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

    add_result "CSAP-Xenserver-29" "패치 및 로그 관리" "syslog 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-30: syslog 전송 포트 차단
check_CSAP_Xenserver_30() {
    local status="양호"
    local detail=""
    local cmd="netstat -an | grep udp; netstat -an | grep udp | egrep 514"
    local cur_state=""
    local remediation="￭ Remote Log 서버 필요시 Remote Log 사용 시 보안담당자 및 담당 매니저와의 협의 필요 ￭ Remote Log 서버 불필요시 syslog.conf 파일 수정\(\"/etc/sysconfig/syslog\" 파일에 \"SYSLOGD_OPTIONS\"의 \"-r\" 옵션 삭제\) # vi /etc/sysconfig/syslog SYSLOGD_OPTIONS=\"-m 0\" ￭ Remote Log 서버 불필요시 \(7 버전, 8 버전\) Syslog.conf 파일 수정\(\"/etc/sysconfig/rsyslog\" 파일에 \"SYSLOGD_OPTIONS\"의 \"-r\" 옵션 삭제\) # vi /etc/sysconfig/rsyslog SYSLOGD_OPTIONS=\"-m 0\""

    local output
    output=$({
        ( get_process_snapshot "udp" )
        ( get_process_snapshot "udp" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="Remote Log 서버를 사용하지 않을 경우"
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

    add_result "CSAP-Xenserver-30" "패치 및 로그 관리" "syslog 전송 포트 차단" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-31: 로깅 수준 설정
check_CSAP_Xenserver_31() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/syslog.conf | grep info"
    local cur_state=""
    local remediation="[XenServer] ￭ 로깅 수준 설정 /etc/syslog.conf\" 파일에 \"info\" 로그를 남기도록 설정 # vi /etc/syslog.conf\" info;;file:/var/log/xensource.log ￭ 로깅 수준 설정 \(7 버전, 8 버전\) /etc/rsyslog.d/xenserver.conf 파일에 \"info\" 로그를 남기도록 설정 # vi /etc/rsyslog.d/xenserver.conf [XenCenter] ￭ 로깅 수준 설정 XenCenter에서 [XenServer]를 선택 한 후 [Logs] 메뉴에서 \"Information\"에서 로그 설정 ￭ 로깅 수준 설정 \(6.5 이후 버전\) XenCenter에서 왼쪽 패널 하단 Notification에서 Information 로그 설정"

    local config_file="/etc/syslog.conf"
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

    add_result "CSAP-Xenserver-31" "패치 및 로그 관리" "로깅 수준 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-32: 로그 파일 권한 설정
check_CSAP_Xenserver_32() {
    local status="양호"
    local detail=""
    local cmd="ls -alL"
    local cur_state=""
    local remediation="￭ 로깅 파일 소유자 및 권한 변경 1. 로그 파일의 소유자 변경 설정 # chown root [로그 파일명] 2. 로그파일의 타사용자 쓰기 권한 제거 설정 # chmod o-w [로그 파일명]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/var/log/audit.log
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
    target_spec_2=/var/log/btmp
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
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
    local target_spec_3
    target_spec_3=/var/log/xenstored-access.log
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_3). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/var/log/secure
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_4). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_4). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_5
    target_spec_5=/var/log/wtmp
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state+="$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_5). " ;;
                    GOOD*) detail+="$target_path 소유자/권한 적절($result_5). " ;;
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
    [ -z "$detail" ] && detail="로그 파일의 소유자가 root이고, 타사용자" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Xenserver-32" "패치 및 로그 관리" "로그 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Xenserver-33: 보안패치 적용
check_CSAP_Xenserver_33() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 설정 기준 권고 \(또는 정책 기준\) 1. 보안취약점이 발표되면 시스템 영향도를 평가하고, 긴급 대응책 및 중장기 대응책을 마련하여 계획과 허가에 의해 대응하는 것이 좋다. 2. 패치를 수행할 시 시스템의 영향도에 따라 패치를 차등 수행하도록 한다. 3. 시스템 운영에 영향을 주지 않는 범위 내에서 주기적으로 패치를 수행할 것을 권고함"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 패치 적용 정책을 수립하여 주기적으로"
    cur_state="수동점검 필요"

    add_result "CSAP-Xenserver-33" "패치 및 로그 관리" "보안패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
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

# ISMS-HV-05: 가상화 장비 사용자 인증 강화
check_ISMS_HV_05() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:; gpasswd -d user1 users; xe subject-list"
    local cur_state=""
    local remediation="불필요한 권한이 부여된 계정에 대한 권한 제거 [상세 조치 사례] l XenServer [Active Directory에 가입되어 있지 않은 경우] Step 1\) 호스트에 접속 Step 2\) bash 사용자 목록 확인 \$ grep /bin/bash /etc/passwd | cut -f1 -d: root user1 Step 3\) 불필요한 계정 제거 \$ gpasswd -d user1 users [Active Directory에 가입되어 있는 경우] Step 4\) 호스트에 접속 Step 5\) 계정별 부여된 권한 확인 \$ xe subject-list uuid \( RO\): bb6dd239-1fa9-a06b-a497-3be28b8dca44 subject-identifier \( RO\): S-1-5-21-1539997073-1618981536-2562117463-2244 other-config \(MRO\): subject-name: example01\\user_vm_admin; subject-upn: \\ user_vm_admin@XENDT.NET; subject-uid: 1823475908; subject-gid: 1823474177; \\ subject-sid: S-1-5-21-1539997073-1618981536-2562117463-2244; subject-gecos: \\ user_vm_admin; subject-displayname: user_vm_admin; subject-is-group: false; \\ subject-account-disabled: false; subject-account-expired: false; \\ subject-account-locked: false;subject-password-expired: false Step 6\) 부적절한 권한이 있는 경우 기존의 역할을 제거하고 새로운 역할을 추가 \$ xe subject-role-remove uuid=<subject uuid> role-name=<role_name_to_remove> \$ xe subject-role-add uuid=<subject uuid > role-name=<role_name_to_add>"

    local output
    output=$({
        ( get_process_snapshot "/bin/bash" )
        ( gpasswd -d user1 users )
        ( xe subject-list )
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

    add_result "ISMS-HV-05" "가상화 장비 > 1. 계정 관리" "가상화 장비 사용자 인증 강화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-06: 비밀번호 관리정책 설정
check_ISMS_HV_06() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/login.defs | grep -i PASS_MAX_DAYS; cat /etc/login.defs | grep -i PASS_MIN_DAYS; cat /etc/login.defs | grep -i PASS_MIN_LEN"
    local cur_state=""
    local remediation="로그인 계정 비밀번호를 관리 정책에 맞게 설정 [상세 조치 사례] l XenServer Step 1\) XenServer 접속 >　Local Command Shell 실행 Step 2\) 아래 명령어를 통해 비밀번호 설정 확인 # cat /etc/login.defs | grep –i \"PASS_MAX_DAYS\" # cat /etc/login.defs | grep –i \"PASS_MIN_DAYS\" # cat /etc/login.defs | grep -i \"PASS_MIN_LEN\" Step 3\) 아래 명령어 적용 # vi /etc/login.defs PASS_MIN_LEN 8 PASS_MAX_DAYS 90 PASS_MIN_DAYS 7"

    local output
    output=$({
        ( get_process_snapshot "pass_max_days" )
        ( get_process_snapshot "pass_min_days" )
        ( get_process_snapshot "pass_min_len" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="로그인 계정 비밀번호 관리 정책이 적용된 경우"
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
            detail="로그인 계정 비밀번호 관리 정책이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="로그인 계정 비밀번호 관리 정책이 적용되지 않은 경우"
        else
            status="취약"
            detail="로그인 계정 비밀번호 관리 정책이 적용되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-06" "가상화 장비 > 1. 계정 관리" "비밀번호 관리정책 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-08: 시스템 사용 주의사항 출력 설정
check_ISMS_HV_08() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/ssh/sshd_config | grep Banner"
    local cur_state=""
    local remediation="시스템 사용 주의사항 출력 설정 [상세 조치 사례] l XenServer Step 1\) 배너 설정 여부 확인 # cat /etc/ssh/sshd_config | grep \"Banner\" Step 2\) /etc/sshd/sshd_config 파일에 배너 내용 삽입 # vi /etc/sshd/sshd_config Banner /etc/issue.net \(예시\) This system is for the use of authorized users only. l XenServer Step 1\) XenServer 접속 > Network and Management Interface > Network Time \(NTP\) > Provide NTP Servers Manually > 별도 NTP 서버 지정 설정 적용"

    local config_file="/etc/ssh/sshd_config"
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
    local remediation="SNMP Community String을 복잡도를 만족하는 값으로 설정 [상세 조치 사례] l XenServer Step 1\) XenCenter 접속 Step 2\) 해당 서버 설정 > SNMP Step 3\) SNMP 활성화 여부 확인 Step 4\) 활성화 또는 필요에 의해 사용 시 Community String 값 확인 [ SNMP Community String 값 확인 ]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. SNMP Community String이 복잡도를 만족하는 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-10" "가상화 장비 > 2. 시스템 서비스 관리" "SNMP Community String 복잡성 적용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-14: 원격 로그 서버 이용
check_ISMS_HV_14() {
    local status="양호"
    local detail=""
    local cmd="netstat -an | grep udp"
    local cur_state=""
    local remediation="원격 로그 서버 또는 스토리지 연동 설정 [상세 조치 사례] l XenServer Step 1\) Remote Log 서버 사용 유무 확인 Step 2\) udp514 Port 확인 # netstat -an | grep \"udp\" 또는 # netstat -an | grep \" udp\" | egrep \"514\" Step 3\) Syslog.conf 파일 수정\(\"/etc/sysconfig/syslog\" 파일에 \"SYSLOGD_OPTIONS\"의 \"-r\" 옵션 삭제\) # vi /etc/sysconfig/syslog SYSLOGD_OPTIONS=\"-m 0\""

    local output
    output=$({
        ( get_process_snapshot "udp" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="원격 로그 서버 또는 스토리지가 연동 설정된 경우"
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
            detail="원격 로그 서버 또는 스토리지가 연동 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="원격 로그 서버 또는 스토리지가 연동 설정되지 않은 경우"
        else
            status="취약"
            detail="원격 로그 서버 또는 스토리지가 연동 설정되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-14" "가상화 장비 > 2. 시스템 서비스 관리" "원격 로그 서버 이용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-19: 가상 머신의 불필요한 장치 제거
check_ISMS_HV_19() {
    local status="양호"
    local detail=""
    local cmd="xe vm-list name-label=; xe vbd-list vm-uuid=; xe vdi-list"
    local cur_state=""
    local remediation="불필요한 장치 연결 해제 적용 [상세 조치 사례] l XenServer Step 1\) 장치 연결상태 확인 1. PCI 장치 목록 확인 lspci 2. 블록 디바이스 목록 확인 lsblk 3. 네트워크 인터페이스 확인 ifconfig 또는 ip addr 4.가상 머신의 디스크 목록 확인 xe vm-list name-label=\"<VM_NAME>\" 5. VM에 연결된 디스크 확인 xe vbd-list vm-uuid=<VM_UUID> 6. 모든 가상 디스크 이미지 목록 확인 xe vdi-list 7. 네트워크 인터페이스 목록 확인 xe vif-list 8. USB 장치 확인 lsusb 9. 디스크 용량 및 사용 현황 확인 df –h Step 2\) 불필요한 외부 장치 비활성화 842"

    local output
    output=$({
        ( xe vm-list name-label= )
        ( xe vbd-list vm-uuid= )
        ( xe vdi-list )
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
            detail="불필요한 장치가 가상 머신에 연결되지 않은 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 장치가 가상 머신에 연결된 경우"
        else
            status="취약"
            detail="불필요한 장치가 가상 머신에 연결된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-19" "가상화 장비 > 3. 가상머신 관리" "가상 머신의 불필요한 장치 제거" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-23: 가상스위치 무차별(Promiscuous) 모드 정책 비활성화
check_ISMS_HV_23() {
    local status="양호"
    local detail=""
    local cmd="xe pif-list network-name-label=; xe vif-list vm-name-label=; xe pif-param-list uuid="
    local cur_state=""
    local remediation="가상 스위치 무차별\(Promiscuous\) 모드 정책 거부 설정 [상세 조치 사례] l XenServer Step 1\) 가상 스위치 Promiscuous 모드 조회 Step 2\) XenServer CLI 접속 후, 다음 명령어 실행하여 uuid_of_pif/vif 확인 \$ xe pif-list network-name-label=<네트워크 이름> \$ xe vif-list vm-name-label=<VM 이름> Step 3\) 다음 명령어 실행하여 promiscuous 값 확인 \$ xe pif-param-list uuid=<uuid_of_pif> \$ xe vif-param-list uuid=<uuid_of_vif> Step 4\) 다음 명령어 실행하여 promiscuous 값 설정 \$ xe pif-param-set uuid=<uuid_of_pif> other-config:promiscuous=\"false\" \$ xe vif-param-set uuid=<uuid_of_vif> other-config:promiscuous=\"false\" 848"

    local output
    output=$({
        ( xe pif-list network-name-label= )
        ( xe vif-list vm-name-label= )
        ( xe pif-param-list uuid= )
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
            detail="가상 스위치 무차별\(Promiscuous\) 모드 정책 설정이 거부로 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="가상 스위치 무차별\(Promiscuous\) 모드 정책 설정이 허용으로 설정된 경우"
        else
            status="취약"
            detail="가상 스위치 무차별\(Promiscuous\) 모드 정책 설정이 허용으로 설정된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-23" "가상화 장비 > 4. 가상 네트워크 관리" "가상스위치 무차별\(Promiscuous\) 모드 정책 비활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Xenserver CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/42] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Xenserver-02"; check_CSAP_Xenserver_02
progress "CSAP-Xenserver-01"; check_CSAP_Xenserver_01
progress "CSAP-Xenserver-03"; check_CSAP_Xenserver_03
progress "CSAP-Xenserver-04"; check_CSAP_Xenserver_04
progress "CSAP-Xenserver-05"; check_CSAP_Xenserver_05
progress "CSAP-Xenserver-06"; check_CSAP_Xenserver_06
progress "CSAP-Xenserver-07"; check_CSAP_Xenserver_07
progress "CSAP-Xenserver-08"; check_CSAP_Xenserver_08
progress "CSAP-Xenserver-09"; check_CSAP_Xenserver_09
progress "CSAP-Xenserver-10"; check_CSAP_Xenserver_10
progress "CSAP-Xenserver-11"; check_CSAP_Xenserver_11
progress "CSAP-Xenserver-12"; check_CSAP_Xenserver_12
progress "CSAP-Xenserver-13"; check_CSAP_Xenserver_13
progress "CSAP-Xenserver-14"; check_CSAP_Xenserver_14
progress "CSAP-Xenserver-15"; check_CSAP_Xenserver_15
progress "CSAP-Xenserver-16"; check_CSAP_Xenserver_16
progress "CSAP-Xenserver-17"; check_CSAP_Xenserver_17
progress "CSAP-Xenserver-18"; check_CSAP_Xenserver_18
progress "CSAP-Xenserver-19"; check_CSAP_Xenserver_19
progress "CSAP-Xenserver-20"; check_CSAP_Xenserver_20
progress "CSAP-Xenserver-21"; check_CSAP_Xenserver_21
progress "CSAP-Xenserver-22"; check_CSAP_Xenserver_22
progress "CSAP-Xenserver-23"; check_CSAP_Xenserver_23
progress "CSAP-Xenserver-24"; check_CSAP_Xenserver_24
progress "CSAP-Xenserver-25"; check_CSAP_Xenserver_25
progress "CSAP-Xenserver-26"; check_CSAP_Xenserver_26
progress "CSAP-Xenserver-27"; check_CSAP_Xenserver_27
progress "CSAP-Xenserver-28"; check_CSAP_Xenserver_28
progress "CSAP-Xenserver-29"; check_CSAP_Xenserver_29
progress "CSAP-Xenserver-30"; check_CSAP_Xenserver_30
progress "CSAP-Xenserver-31"; check_CSAP_Xenserver_31
progress "CSAP-Xenserver-32"; check_CSAP_Xenserver_32
progress "CSAP-Xenserver-33"; check_CSAP_Xenserver_33
progress "ISMS-HV-01"; check_ISMS_HV_01
progress "ISMS-HV-02"; check_ISMS_HV_02
progress "ISMS-HV-05"; check_ISMS_HV_05
progress "ISMS-HV-06"; check_ISMS_HV_06
progress "ISMS-HV-08"; check_ISMS_HV_08
progress "ISMS-HV-10"; check_ISMS_HV_10
progress "ISMS-HV-14"; check_ISMS_HV_14
progress "ISMS-HV-19"; check_ISMS_HV_19
progress "ISMS-HV-23"; check_ISMS_HV_23

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
    echo '    "platform": "Xenserver",'
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

echo "===== Xenserver CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
