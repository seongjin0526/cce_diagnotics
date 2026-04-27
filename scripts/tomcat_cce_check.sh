#!/bin/bash
###############################################################################
# Tomcat CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash tomcat_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_tomcat_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Tomcat helper ---
CATALINA_HOME="${CATALINA_HOME:-}"
if [ -z "$CATALINA_HOME" ]; then
    for d in /usr/share/tomcat* /opt/tomcat* /var/lib/tomcat* /usr/local/tomcat*; do
        if [ -d "$d" ]; then
            CATALINA_HOME="$d"
            break
        fi
    done
fi

get_tomcat_conf() {
    local file="$1"
    echo "${CATALINA_HOME}/conf/${file}"
}


# --- Pre-flight: Tomcat 설치 확인 및 경로 탐지 ---
APP_FOUND="false"

detect_app() {
    # 1) CATALINA_HOME 이 이미 설정되어 있는지 확인
    if [ -n "$CATALINA_HOME" ] && [ -d "$CATALINA_HOME" ]; then
        APP_FOUND="true"
    fi

    # 2) 프로세스에서 -Dcatalina.home 추출
    if [ "$APP_FOUND" = "false" ]; then
        local tomcat_proc
        tomcat_proc=$(get_process_snapshot 'catalina|tomcat' | head -1)
        if [ -n "$tomcat_proc" ]; then
            local home_from_proc
            home_from_proc=$(echo "$tomcat_proc" | grep -oP '\-Dcatalina\.home=\K[^ ]+' | head -1)
            if [ -n "$home_from_proc" ] && [ -d "$home_from_proc" ]; then
                CATALINA_HOME="$home_from_proc"
                APP_FOUND="true"
            fi
        fi
    fi

    # 3) 공통 설치 경로 탐색
    if [ "$APP_FOUND" = "false" ]; then
        for d in /usr/share/tomcat* /opt/tomcat* /var/lib/tomcat* /usr/local/tomcat*; do
            if [ -d "$d" ] && [ -f "$d/conf/server.xml" ]; then
                CATALINA_HOME="$d"
                APP_FOUND="true"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'tomcat' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'tomcat' && APP_FOUND="true"
        fi
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Tomcat 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Tomcat-01 / ISMS-WEB-01: default 관리자 계정명
check_CSAP_Tomcat_01() {
    local status="양호"
    local detail=""
    local cmd="cat [Tomcat 설치 디렉터리]/tomcat-users.xml | grep \"<user username=\"; cat [Tomcat 설치 디렉터리]/tomcat-users.xml | grep \"roles=\""
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ default 계정명 변경 (admin tomcat 등) 1) # vi [Tomcat 설치 디렉터리]/tomcat-users.xml 2) default 계정명 변경 또는 3) 해당 계정 주석 처리 ￭ 관리자 페이지 비활성화 1) # [Tomcat 설치 디렉터리]/tomcat-users.xml 또는 2) 관리자 계정 주석 처리 ※ 관리자 페이지는 default로 비활성화되어 있음(주석 처리) [주요기반시설 가이드] 기본 관리자 계정명을 추측하기 어려운 계정명으로 설정 [상세 조치 사례] l Tomcat Step 1) 기본 계정명 변경 또는 관리자 페이지 비활성화(기본값: 비활성화) # vi <Tomcat 설치 디렉터리>/conf/server.xml 예시) <user username=\"admin\" password=\"XNDJxndn264!@\" roles=\"manager-gui\"/> Step 2) Tomcat 재구동 # systemctl restart tomcat ※ \"roles = manager-gui, manager-script, manager-jmx, manager-status\" 설정 시 관리자 계정 및 페이지 활성화 상태 03. 웹 서비스 275"

    local config_file="${CATALINA_HOME:-/usr/local/tomcat}/conf/tomcat-users.xml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "^[[:space:]]*<user|manager-gui|admin-gui|username=\"(tomcat|admin)\"|name=\"(tomcat|admin)\"" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="양호"
        detail="관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
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
            detail="관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정명을"
        else
            status="취약"
            detail="계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정명을"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-Tomcat-01 / ISMS-WEB-01" "패치 및 로그 관리" "default 관리자 계정명" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-02 / ISMS-WEB-02: 취약한 패스워드 사용 제한
check_CSAP_Tomcat_02() {
    local status="양호"
    local detail=""
    local cmd="[Tomcat 설치 디렉터리]/tomcat-users.xml | grep \"<user username=\""
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 패스워드 변경 1) 패스워드 복잡도를 만족하도록 설정 # vi [Tomcat 설치 디렉터리]/tomcat-users.xml ※ 패스워드 복잡도 : 영문(대문자, 소문자), 숫자, 특수문자 조합 중 3가지 8자리 이상, 2가지 조합 10자리 이상 [주요기반시설 가이드] 복잡도 기준에 맞는 추측하기 어려운 비밀번호 설정 [상세 조치 사례] l Tomcat Step 1) 복잡도를 만족하는 비밀번호 설정 # vi <Tomcat 설치 디렉터리>/conf/server.xml <user username=\"admin\" password=\"XNDJxndn264!@\" roles=\"manager-gui\"/> Step 2) Tomcat 재시작 # systemctl restart tomcat"

    local output
    output=$({
        ( get_process_snapshot "<user^>+password=" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
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
            detail="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
        else
            status="취약"
            detail="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Tomcat-02 / ISMS-WEB-02" "계정 관리" "취약한 패스워드 사용 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-03 / ISMS-WEB-03: 패스워드 파일 권한 관리
check_CSAP_Tomcat_03() {
    local status="양호"
    local detail=""
    local cmd="ls [Tomcat 설치 디렉터리 ] -l"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 패스워드 파일 권한 변경 1) # chmod 600 [Tomcat 설치 디렉터리]/tomcat-users.xml ※ 설정 파일 권한 변경 시, 시스템 영향도를 파악하여 충분한 테스트를 진행 한 후에 접근권한 수정 [주요기반시설 가이드] 비밀번호 파일 권한 600 이하로 설정 [상세 조치 사례] l Tomcat Step 1) tomcat-users.xml 파일 권한 변경 # chmod 600 /<Tomcat 설치 디렉터리>/tomcat-users.xml"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/tomcat-users.xml
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "600")
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
    local target_spec_2
    target_spec_2=${CATALINA_HOME:-/usr/local/tomcat}/conf/tomcat-users.xml
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "600")
                cur_state+="$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_2). " ;;
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
    [ -z "$detail" ] && detail="비밀번호 파일에 권한이 600 이하로 설정된 경우" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Tomcat-03 / ISMS-WEB-03" "보안 설정" "패스워드 파일 권한 관리" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-06 / ISMS-WEB-04: 디렉터리 리스팅 설정 제한
check_CSAP_Tomcat_06() {
    local status="양호"
    local detail=""
    local cmd="[Tomcat 설치 디렉터리]/web.xml"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 디렉터리 리스팅 비활성화 1) # vi [Tomcat 설치 디렉터리]/web.xml [주요기반시설 가이드] 디렉터리 리스팅 기능 차단 설정 [상세 조치 사례] l Tomcat Step 1) web.xml 파일 내 listings 옵션 비활성화 # vi /<Tomcat 설치 디렉터리>/web.xml <init-param> <param-name>listings</param-name> <param-value>false</param-value> </init-param>"

    local output
    output=$({
        ( get_process_snapshot "<param-name>listings</param-name>" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="디렉터리 리스팅이 설정되지 않은 경우"
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
            detail="디렉터리 리스팅이 설정되지 않은 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="디렉터리 리스팅이 설정된 경우"
        else
            status="취약"
            detail="디렉터리 리스팅이 설정된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Tomcat-06 / ISMS-WEB-04" "보안 설정" "디렉터리 리스팅 설정 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-07 / ISMS-WEB-22: 에러 메시지 관리
check_CSAP_Tomcat_07() {
    local status="양호"
    local detail=""
    local cmd="cat [Tomcat 설치 디렉터리]/web.xml 내 에러 페이지 설정 확인"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 에러 코드 설정 파일 수정 1) 필수 에러 코드(400,401,403,404,500)에 대한 에러 내용을 알 수 없도록 일원화된 에러 페이지로 관리 ※ 에러가 발생 시, 일원화된 에러 페이지가 표시되도록 하는 방식이 아닌 로그인 페이지로 리다이렉션되는 방식 또한 양호로 처리함 [주요기반시설 가이드] 필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정 [상세 조치 사례] l Tomcat Step 1) web.xml 파일 내 에러 코드별 에러 페이지 설정 정보 확인 후 별도의 일원화된 에러 페이지 설정 # vi /[Tomcat 설치 디렉터리]/conf/web.xml <error-page> <error-code>404</error-code> <location>/error/404.html</location> (이하 생략) </error-page> Step 2) Tomcat 재구동 # systemctl restart tomcat"

    local config_file="${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "error-page" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="양호"
        detail="웹 서비스 에러 페이지가 별도로 지정된 경우"
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
            detail="웹 서비스 에러 페이지가 별도로 지정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"
        else
            status="취약"
            detail="웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-Tomcat-07 / ISMS-WEB-22" "보안 설정" "에러 메시지 관리" "하" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-04: 홈 디렉터리 쓰기 권한 관리
check_CSAP_Tomcat_04() {
    local status="양호"
    local detail=""
    local cmd="cat [Tomcat 환경 설정 디렉터리]/server.xml | grep appBase (예시); ls -al [Tomcat 설치 디렉터리]"
    local cur_state=""
    local remediation="￭ 홈 디렉터리 접근 권한 변경 (예시) 1) # chmod 755 [Tomcat 설치 디렉터리]/webapps ※ 설정 파일 권한 변경 시, 시스템 영향도를 파악하여 충분한 테스트를 진행한 후에 접근권한 수정"

    local config_file="${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml"
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

    add_result "CSAP-Tomcat-04" "보안 설정" "홈 디렉터리 쓰기 권한 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-05: 환경 설정 파일 권한 관리
check_CSAP_Tomcat_05() {
    local status="양호"
    local detail=""
    local cmd="ls -al [Tomcat 설치 디렉터리]; cat [Tomcat 설치 디렉터리]/server.xml | grep appBase (예시)"
    local cur_state=""
    local remediation="￭ 파일 권한 변경 1) 설정 파일 권한 변경 # chmod 600 [해당 파일] 2) 소스 파일 권한 변경 # chmod 644 [해당 파일]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/server.xml
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
    local target_spec_2
    target_spec_2=${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "644")
                cur_state+="$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_2). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "" "644")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_3). " ;;
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
    [ -z "$detail" ] && detail="WAS 전용 계정 소유이고 소스파일 접근" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Tomcat-05" "보안 설정" "환경 설정 파일 권한 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-08: 로그 파일 관리 및 주기적 백업
check_CSAP_Tomcat_08() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"AccessLogValve|prefix=.*log|directory=.*log\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_DEFAULT_BAD|로그 설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="￭ 로그 파일 관리 및 주기적 백업 1) 백업 정책 수립 2) 정책에 따라 로그를 기록하고 주기적으로 백업"

    local output
    output=$({
        ( get_process_snapshot "accesslogvalve" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="로그 파일을 관리하고 있으며 주기적으로"
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

    add_result "CSAP-Tomcat-08" "패치 및 로그 관리" "로그 파일 관리 및 주기적 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Tomcat-09: 최신 보안 패치 적용
check_CSAP_Tomcat_09() {
    local status="양호"
    local detail=""
    local cmd="[Tomcat 설치 디렉터리]/bin/version.sh 또는; rpm -qa | grep webapps"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 취약점이 없는 보안 패치가 적용된 버전으로 업데이트해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( /bin/version.sh )
        ( get_process_snapshot "webapps" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="최신 보안 패치를 적용하고 있는 경우"
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

    add_result "CSAP-Tomcat-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-05: 지정하지 않은 CGI/ISAPI 실행 제한
check_ISMS_WEB_05() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"<servlet-name>cgi</servlet-name>|/cgi-bin/\\\\*\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본적으로 CGI servlet 매핑이 비활성입니다.\"; fi; else echo \"FILE_DEFAULT_GOOD|기본적으로 CGI servlet 매핑이 비활성입니다.\"; fi"
    local cur_state=""
    local remediation="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정 [상세 조치 사례] l Tomcat Step 1) web.xml 파일 내 CGI 매핑 비활성화 <!-- <servlet-mapping> <servlet-name>cgi</servlet-name> <url-pattern>/cgi-bin/*</url-pattern> </servlet-mapping> --> Step 2) Tomcat 재시작"

    local output
    output=$({
        ( get_process_snapshot "<servlet-name>cgi</servlet-name>" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
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
            detail="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
        else
            status="취약"
            detail="CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-05" "웹 서비스 > 2. 서비스 관리" "지정하지 않은 CGI/ISAPI 실행 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-06: 웹 서비스 상위 디렉터리 접근 제한 설정
check_ISMS_WEB_06() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"allowLinking\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본값은 allowLinking false 입니다.\"; fi; else echo \"FILE_DEFAULT_GOOD|기본값은 allowLinking false 입니다.\"; fi"
    local cur_state=""
    local remediation="상위 디렉터리 접근 기능 제거 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 Context 요소에서 allowLinking 옵션 확인 # vi /<Tomcat 설치 디렉터리>/conf/server.xml <Context allowLinking=\"true\"> <WatchedResource>WEB-INF/web.xml</WatchedResource> <WatchedResource>WEB-INF/tomcat-web.xml</WatchedResource> <WatchedResource>\${catalina.base}/conf/web.xml</WatchedResource> </Context> Step 2) server.xml 파일 내 Context 요소에서 allowLinking 옵션 제거 #vi /<Tomcat 설치 디렉터리>/conf/server.xml <Context> <WatchedResource>WEB-INF/web.xml</WatchedResource> <WatchedResource>WEB-INF/tomcat-web.xml</WatchedResource> <WatchedResource>\${catalina.base}/conf/web.xml</WatchedResource> </Context>"

    local output
    output=$({
        ( get_process_snapshot "allowlinking" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="상위 디렉터리 접근 기능을 제거한 경우"
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
            detail="상위 디렉터리 접근 기능을 제거한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="상위 디렉터리 접근 기능을 제거하지 않은 경우"
        else
            status="취약"
            detail="상위 디렉터리 접근 기능을 제거하지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-06" "웹 서비스 > 2. 서비스 관리" "웹 서비스 상위 디렉터리 접근 제한 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-07: 웹 서비스 경로 내 불필요한 파일 제거
check_ISMS_WEB_07() {
    local status="양호"
    local detail=""
    local cmd="base=\${CATALINA_HOME:-/usr/local/tomcat}/webapps; if [ -d \"\$base\" ]; then out=\$(find \"\$base\" -maxdepth 2 \\( -name docs -o -name examples -o -name host-manager -o -name manager -o -name ROOT \\) 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"DEFAULT_GOOD|기본 샘플/예제 웹앱을 찾지 못했습니다.\"; fi; else echo \"FILE_MISSING|점검 대상 경로를 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="불필요한 파일 및 디렉터리를 제거하도록 설정 [상세 조치 사례] l Tomcat Step 1) rm 명령어로 확인된 불필요한 매뉴얼 디렉터리 및 파일 제거 # rm –rf /<Tomcat 설치 디렉터리>/webapps/docs/<불필요 파일> ※ BUILDING.txt, RELEASE-NOTES.txt, jndi-resources-howto.html 등 매뉴얼 파일 포함 03. 웹 서비스 291"

    local output
    output=$({
        ( base=${CATALINA_HOME:-/usr/local/tomcat}/webapps; if [ -d "$base" ]; then out=$(find "$base" -maxdepth 2 \( -name docs -o -name examples -o -name host-manager -o -name manager -o -name ROOT \) 2>/dev/null | head -20); if [ -n "$out" ]; then printf '%s\n' "$out"; else echo "DEFAULT_GOOD|기본 샘플/예제 웹앱을 찾지 못했습니다."; fi; else echo "FILE_MISSING|점검 대상 경로를 찾지 못했습니다."; fi )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
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

    add_result "ISMS-WEB-07" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 내 불필요한 파일 제거" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-08: 웹 서비스 파일 업로드 및 다운로드 용량 제한
check_ISMS_WEB_08() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"maxPostSize|maxSwallowSize\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi; cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"<max-file-size>|<max-request-size>|multipart-config\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 maxPostSize 요소 설정 #vi /<Tomcat 설치 디렉터리>/conf/server.xml <Connector port=\"<사용 포트>\" protocol=\"HTTP/1.1\" connectionTimeout=\"20000\" redirectPort=\"<사용 포트>\" 03. 웹 서비스 maxParameterCount=\"1000\" maxPostSize=\"5242880\" // maxPostSize=5242880=5MB /> Step 2) web.xml 파일 내 multipart-config 요소 설정 # vi /<Tomcat 설치 디렉터리>/conf/web.lxml <multipart-config> <max-file-size>2097152</max-file-size> <max-request-size>4194304</max-request-size> <file-size-threshold>0</file-size-threshold> </multipart-config>"

    local output
    output=$({
        ( get_process_snapshot "maxpostsize" )
        ( get_process_snapshot "<max-file-size>" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="파일 업로드 및 다운로드 용량을 제한한 경우"
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
            detail="파일 업로드 및 다운로드 용량을 제한한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="파일 업로드 및 다운로드 용량을 제한하지 않은 경우"
        else
            status="취약"
            detail="파일 업로드 및 다운로드 용량을 제한하지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-08" "웹 서비스 > 2. 서비스 관리" "웹 서비스 파일 업로드 및 다운로드 용량 제한" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-09: 웹 서비스 프로세스 권한 제한
check_ISMS_WEB_09() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정 [상세 조치 사례] l Tomcat Step 1) tomcat.service 파일 내 Tomcat 데몬 구동 권한을 관리자 계정이 아닌 별도 계정으로 변경 # vi /etc/systemd/system/tomcat.service [Service] User=tomcat Group=tomcat Step 2) Tomcat 서비스 파일 소유권 변경 # chown -R tomcat:tomcat /[Tomcat 설치 디렉터리]/usr/share/tomcat9/ # chown -R tomcat:tomcat /[Tomcat 설치 디렉터리]/tomcat9/temp # chown -R tomcat:tomcat / [Tomcat 설치 디렉터리]/logs # chown -R tomcat:tomcat /usr/share/tomcat9/webapps # chown -R tomcat:tomcat /usr/share/tomcat9/work Step 3) 웹서비스 실행 계정 로그인 제한 설정 # usermod -s /sbin/nologin [사용자명] Step 4) Tomcat 서비스 재구동 # systemctl restart tomcat"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진"
    cur_state="수동점검 필요"

    add_result "ISMS-WEB-09" "웹 서비스 > 2. 서비스 관리" "웹 서비스 프로세스 권한 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-10: 불필요한 프록시 설정 제한
check_ISMS_WEB_10() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"proxyName|proxyPort\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본적으로 proxyName/proxyPort가 설정되지 않았습니다.\"; fi; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 Connector 요소에서 불필요한 Proxy 설정 제거 <Connector port=\"8080\" protocol=\"HTTP/1.1\" 03. 웹 서비스 redirectPort=\"8443\" proxyName=\"proxy.example.com\" proxyPort=\"80\" />"

    local output
    output=$({
        ( get_process_snapshot "proxyname" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 Proxy 설정을 제한한 경우"
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

    add_result "ISMS-WEB-10" "웹 서비스 > 2. 서비스 관리" "불필요한 프록시 설정 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-11: 웹 서비스 경로 설정
check_ISMS_WEB_11() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"appBase|docBase\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_DEFAULT_BAD|기본 appBase/docBase 경로 분리 여부를 확인할 수 없습니다.\"; fi"
    local cur_state=""
    local remediation="웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정 [상세 조치 사례] l Tomcat Step 1) web.xml 파일 내 docBase를 별도의 경로로 변경 <Host name=\"localhost\" appBase=\"webapps\" unpackWARs=\"true\" autoDeploy=\"true\"> <Context path=\"\" docBase=\"[별도의 경로]\" /> </Host> 304"

    local output
    output=$({
        ( get_process_snapshot "appbase" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
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
            detail="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
        else
            status="취약"
            detail="웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-11" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-12: 웹 서비스 링크 사용 금지
check_ISMS_WEB_12() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"allowLinking\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본값은 allowLinking false 입니다.\"; fi; else echo \"FILE_DEFAULT_GOOD|기본값은 allowLinking false 입니다.\"; fi"
    local cur_state=""
    local remediation="웹 서비스 링크 사용 제한 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 Context 요소 allowLinking 옵션 설정 <Context allowLiking=\"true\"> <WatchedResource>WEB-INF/web.xml</WatchedResource> <WatchedResource>WEB-INF/tomcat-web.xml</WatchedResource> <WatchedResource>\${catalina.base}/conf/web.xml</WatchedResource> </Context>"

    local output
    output=$({
        ( get_process_snapshot "allowlinking" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
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
            detail="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하는 경우"
        else
            status="취약"
            detail="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-12" "웹 서비스 > 2. 서비스 관리" "웹 서비스 링크 사용 금지" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-13: 웹 서비스 설정 파일 노출 제한
check_ISMS_WEB_13() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결 취약점 제거 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 불필요한 DB 연결 리소스 설정 제거 <GlobalNamingResources> <Resource name=\"jdbc/MyDB\" auth=\"Container\" type=\"javax.sql.DataSource\" maxTotal=\"100\" maxIdle=\"30\" maxWaitMillis=\"10000\" username=\"dbuser\" 03. 웹 서비스 password=\"dbpassword\" driverClassName=\"com.mysql.jdbc.Driver\" url=\"jdbc:mysql://localhost:3306/mydb\"/> </GlobalNamingResources> Step 2) DB 연결 리소스가 존재하는 설정 파일 접근권한을 600으로 설정 # chmod 600 /[Tomcat 설치 디렉터리]/conf/server.xml"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-WEB-13" "웹 서비스 > 2. 서비스 관리" "웹 서비스 설정 파일 노출 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-14: 웹 서비스 경로 내 파일의 접근 통제
check_ISMS_WEB_14() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정 [상세 조치 사례] l Tomcat Step 1) 루트 디렉터리 불필요한 권한 삭제 또는 적절한 권한 부여 # chown –R [Tomcat 계정]:[Tomcat 그룹] web.xml # chmod -R 750 web.xml 312"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-WEB-14" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 내 파일의 접근 통제" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-15: 웹 서비스의 불필요한 스크립트 매핑 제거
check_ISMS_WEB_15() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"<servlet-mapping>|<url-pattern>\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정 [상세 조치 사례] l Tomcat Step 1) 설정 파일의 불필요 스크립트 매핑 제거 <servlet-mapping> <servlet-name>UnuseServlet</servlet-name> <url-pattern>/example/*</url-pattern> </servlet-mapping> ※ context.xml 파일 내 명시된 설정 파일에서도 DB 연결 확인 필요 314"

    local output
    output=$({
        ( get_process_snapshot "<servlet-mapping>" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 스크립트 매핑이 존재하지 않는 경우"
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
            detail="불필요한 스크립트 매핑이 존재하지 않는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 스크립트 매핑이 존재하는 경우"
        else
            status="취약"
            detail="불필요한 스크립트 매핑이 존재하는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-15" "웹 서비스 > 2. 서비스 관리" "웹 서비스의 불필요한 스크립트 매핑 제거" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-16: 웹 서비스 헤더 정보 노출 제한
check_ISMS_WEB_16() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"server=|ErrorReportValve|showServerInfo|xpoweredBy\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_DEFAULT_BAD|기본 헤더/오류 페이지 정보 노출 제한 여부를 확인할 수 없습니다.\"; fi"
    local cur_state=""
    local remediation="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 server 값을 임의 정보로 변경 <Connector port=\"8080\" protocol=\"HTTP/1.1\" connectionTimeout=\"20000\" redirectPort=\"8443\" server=\"{임의 정보로 변경}\" /> Step 1) server.xml 파일 내 아래 내용 추가 <Host> ... 중략 ... <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showReport=\"true\" showServerInfo =\"false\"/> ... 중략 ... </Host>"

    local output
    output=$({
        ( get_process_snapshot "server=" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
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
        if printf '%s\n' "$output" | grep -Eiq "app\.disable\([[:space:]]*[\"\']x-powered-by[\"\']|helmet\(|server_tokens[[:space:]]+off|servertokens[[:space:]]+prod|serversignature[[:space:]]+off|expose_php[[:space:]]*=[[:space:]]*off"; then
            status="양호"
            detail="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
        elif printf '%s\n' "$output" | grep -Eiq "x-powered-by|server_tokens[[:space:]]+on|expose_php[[:space:]]*=[[:space:]]*on"; then
            status="취약"
            detail="HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"
        else
            status="수동점검"
            detail="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-16" "웹 서비스 > 2. 서비스 관리" "웹 서비스 헤더 정보 노출 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-17: 웹 서비스 가상 디렉로리 삭제
check_ISMS_WEB_17() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"<Context[^>]+path=\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|가상 디렉터리 Context path를 확인하지 못했습니다.\"; fi; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정 [상세 조치 사례] l Tomcat Step 1) 'Context' 블록 요소의 'path' 속성값 확인 #vi /[Tomcat 설치 디렉터리]/server.xml <Host name=\"localhost\" appBase=\"webapps\" unpackWARs=\"true\" autoDeploy=\"true\"> <Context path=\"/virtual\" docBase=\"/path/to/your/virtual/directory\" reloadable=\"true\"/> </Host> Step 2) Context 블록 요소 가상 디렉터리 제거"

    local output
    output=$({
        ( get_process_snapshot "<context^>+path=" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 가상 디렉터리가 존재하지 않는 경우"
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
            detail="불필요한 가상 디렉터리가 존재하지 않는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 가상 디렉터리가 존재하는 경우"
        else
            status="취약"
            detail="불필요한 가상 디렉터리가 존재하는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-17" "웹 서비스 > 2. 서비스 관리" "웹 서비스 가상 디렉로리 삭제" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-19: 웹 서비스 SSI(Server Side Includes) 사용 제한
check_ISMS_WEB_19() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"SSIServlet|SSIFilter|\\\\.shtml\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본적으로 SSI servlet/filter 매핑이 비활성입니다.\"; fi; else echo \"FILE_DEFAULT_GOOD|기본적으로 SSI servlet/filter 매핑이 비활성입니다.\"; fi"
    local cur_state=""
    local remediation="웹 서비스 내 불필요한 SSI 사용 제한 설정 [상세 조치 사례] l Tomcat Step 1) web.xml 파일 내 SSI 서블릿 또는 필터 사용 설정 확인 #cat /[Tomcat 설치 디렉터리]/tomcat-users.xml | grep 'SSIServlet\\|SSIFilter' <servlet-mapping> <servlet-name>SSIServlet</servlet-name> <url-pattern>*.shtml</url-pattern> </servlet-mapping> 또는 <filter-mapping> <filter-name>SSIFilter</filter-name> <url-pattern>*.shtml</url-pattern> </filter-mapping> Step 2) web.xml 파일 내 SSI 서블릿 및 필터 설정 삭제 또는 주석 처리 Step 3) web.xml 파일 내에서 SSI와 관련한 불필요 mapping 제거 또는 주석 처리 Step 4) Tomcat 서비스 재구동 # systemctl restart tomcat"

    local output
    output=$({
        ( get_process_snapshot "ssiservlet" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
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
            detail="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
        else
            status="취약"
            detail="웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-19" "웹 서비스 > 3. 보안 설정" "웹 서비스 SSI(Server Side Includes) 사용 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-23: LDAP 알고리즘 적절하게 구성
check_ISMS_WEB_23() {
    local status="양호"
    local detail=""
    local cmd="grep 'digest=' /[Tomcat 설치 디렉터리]/conf/server.xml"
    local cur_state=""
    local remediation="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정 [상세 조치 사례] l Tomcat Step 1) 비밀번호 다이제스트 알고리즘 확인 (LDAP 종류별 암호화 알고리즘 지원 여부 확인) # grep 'digest=' /[Tomcat 설치 디렉터리]/conf/server.xml digest=\"SSHA\" Step 2) 비밀번호 다이제스트 알고리즘 설정 # vi /[Tomcat 설치 디렉터리]/conf/server.xml digest=\"SHA-256\" Step 3) Tomcat 재구동 # systemctl restart tomcat ※ SHA-256 이상 암호화 알고리즘 권고 03. 웹 서비스 343"

    local config_file="${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml"
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

    add_result "ISMS-WEB-23" "웹 서비스 > 3. 보안 설정" "LDAP 알고리즘 적절하게 구성" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-24: 별도의 업로드 경로 사용 및 권한 설정
check_ISMS_WEB_24() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정 [상세 조치 사례] l Tomcat Step 1) server.xml 파일 내 Context 요소 allowLinking 옵션 설정 (기본값 : 업로드 디렉터리 경로 존재하지 않음) # vi /[Tomcat 설치 디렉터리]/conf/context.xml <servlet> <servlet-name>fileUploadServlet</servlet-name> <servlet-class>com.example.FileUploadServlet</servlet-class> </servlet> Step 2) 별도의 업로드 경로 생성 # mkdir [웹서비스 디렉터리 외 경로] # mkdir /var/www/html/uploads Step 3) 업로드 디렉터리 권한 설정 chmod 750 /var/www/html/uploads/ chown tomcat:tomcat /var/www/html/uploads/ Step 4) 지정한 디렉터리 권한을 웹 서비스에서 사용"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-WEB-24" "웹 서비스 > 3. 보안 설정" "별도의 업로드 경로 사용 및 권한 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-25: 주기적 보안 패치 및 벤더 권고사항 적용
check_ISMS_WEB_25() {
    local status="양호"
    local detail=""
    local cmd="cd /[Tomcat 설치 디렉터리]/lib; java -cp catalina.jar org.apache.catalina.util.ServerInfo"
    local cur_state=""
    local remediation="패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정 [상세 조치 사례] l Tomcat Step 1) 웹 서버 버전과 최신 패치 버전을 비교하여 확인 # cd /[Tomcat 설치 디렉터리]/lib # java -cp catalina.jar org.apache.catalina.util.ServerInfo [ Tomcat 웹 서버 버전 확인 ] Step 2) Tomcat 사이트를 통해 주기적으로 버전 점검을 하며, 최신 버전 적용 시 충분한 테스트 후 적용 권고 ※ 참고 사이트: https://tomcat.apache.org/"

    local output
    output=$({
        ( java -cp catalina.jar org.apache.catalina.util.ServerInfo )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
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

    add_result "ISMS-WEB-25" "웹 서비스 > 4. 패치 및 로그 관리" "주기적 보안 패치 및 벤더 권고사항 적용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-26: 로그 디렉터리 및 파일 권한 설정
check_ISMS_WEB_26() {
    local status="양호"
    local detail=""
    local cmd="ls -al /<Tomcat 로그 디렉터리>"
    local cur_state=""
    local remediation="로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정 [상세 조치 사례] l Tomcat Step 1) 로그 디렉터리 및 파일 권한 확인 # ls –al /<Tomcat 로그 디렉터리> Step 2) 로그 디렉터리 및 파일의 불필요 권한 삭제 # chmod o-rwx /<Tomcat 로그 파일> 03. 웹 서비스 351"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${CATALINA_HOME:-/usr/local/tomcat}/logs
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
    [ -z "$detail" ] && detail="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우" && cur_state="점검 대상 파일 없음"

    add_result "ISMS-WEB-26" "웹 서비스 > 4. 패치 및 로그 관리" "로그 디렉터리 및 파일 권한 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Tomcat CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/27] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Tomcat-01"; check_CSAP_Tomcat_01
progress "CSAP-Tomcat-02"; check_CSAP_Tomcat_02
progress "CSAP-Tomcat-03"; check_CSAP_Tomcat_03
progress "CSAP-Tomcat-06"; check_CSAP_Tomcat_06
progress "CSAP-Tomcat-07"; check_CSAP_Tomcat_07
progress "CSAP-Tomcat-04"; check_CSAP_Tomcat_04
progress "CSAP-Tomcat-05"; check_CSAP_Tomcat_05
progress "CSAP-Tomcat-08"; check_CSAP_Tomcat_08
progress "CSAP-Tomcat-09"; check_CSAP_Tomcat_09
progress "ISMS-WEB-05"; check_ISMS_WEB_05
progress "ISMS-WEB-06"; check_ISMS_WEB_06
progress "ISMS-WEB-07"; check_ISMS_WEB_07
progress "ISMS-WEB-08"; check_ISMS_WEB_08
progress "ISMS-WEB-09"; check_ISMS_WEB_09
progress "ISMS-WEB-10"; check_ISMS_WEB_10
progress "ISMS-WEB-11"; check_ISMS_WEB_11
progress "ISMS-WEB-12"; check_ISMS_WEB_12
progress "ISMS-WEB-13"; check_ISMS_WEB_13
progress "ISMS-WEB-14"; check_ISMS_WEB_14
progress "ISMS-WEB-15"; check_ISMS_WEB_15
progress "ISMS-WEB-16"; check_ISMS_WEB_16
progress "ISMS-WEB-17"; check_ISMS_WEB_17
progress "ISMS-WEB-19"; check_ISMS_WEB_19
progress "ISMS-WEB-23"; check_ISMS_WEB_23
progress "ISMS-WEB-24"; check_ISMS_WEB_24
progress "ISMS-WEB-25"; check_ISMS_WEB_25
progress "ISMS-WEB-26"; check_ISMS_WEB_26

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
    echo '    "platform": "Tomcat",'
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

echo "===== Tomcat CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
