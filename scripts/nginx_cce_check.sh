#!/bin/bash
###############################################################################
# Nginx CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash nginx_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_nginx_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Nginx helper ---
NGINX_CONF="${NGINX_CONF:-}"
if [ -z "$NGINX_CONF" ]; then
    for f in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf; do
        if [ -f "$f" ]; then
            NGINX_CONF="$f"
            break
        fi
    done
fi

get_nginx_conf() {
    echo "$NGINX_CONF"
}


# --- Pre-flight: Nginx 설치 확인 및 경로 탐지 ---
NGINX_BIN=""
NGINX_CONF="${NGINX_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NGINX_BIN=$(command -v nginx 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$NGINX_BIN" ]; then
        local nginx_proc
        nginx_proc=$(get_process_snapshot 'nginx.*master' | head -1)
        if [ -n "$nginx_proc" ]; then
            NGINX_BIN=$(echo "$nginx_proc" | awk '{print $8}')
            APP_FOUND="true"
        fi
    fi

    # 3) nginx -t 로 conf 경로 추출
    if [ -n "$NGINX_BIN" ]; then
        local nginx_test
        nginx_test=$("$NGINX_BIN" -t 2>&1)
        local conf_from_test
        conf_from_test=$(echo "$nginx_test" | sed -n 's/.*configuration file \(.*\) test.*/\1/p')
        if [ -n "$conf_from_test" ] && [ -f "$conf_from_test" ]; then
            NGINX_CONF="$conf_from_test"
        fi
    fi

    # 4) 공통 설정 파일 경로 탐색
    if [ -z "$NGINX_CONF" ]; then
        for f in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf /usr/local/etc/nginx/nginx.conf; do
            if [ -f "$f" ]; then
                NGINX_CONF="$f"
                break
            fi
        done
    fi

    # 5) 패키지 매니저 확인
    if [ -z "$NGINX_BIN" ] && [ -z "$NGINX_CONF" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'nginx' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'nginx' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$NGINX_BIN" ] || [ -n "$NGINX_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Nginx 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Nginx-01 / ISMS-WEB-11: 웹 서비스 영역의 분리
check_CSAP_Nginx_01() {
    local status="양호"
    local detail=""
    local cmd="cat [Nginx 환경 설정 파일] | grep root"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 기본 디렉터리 위치 변경 (예시) 1) # vi [Nginx 환경 설정 파일] [주요기반시설 가이드] 웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정 [상세 조치 사례] l Nginx Step 1) sites-available 파일 내 DocumentRoot를 별도의 경로로 변경 # vi /[Nginx 설치 디렉터리]/sites-available root [별도의 경로]"

    local output
    output=$({
        ( get_process_snapshot ":space:*root:space:+" )
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

    add_result "CSAP-Nginx-01 / ISMS-WEB-11" "패치 관리" "웹 서비스 영역의 분리" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Nginx-02 / ISMS-WEB-07: 불필요한 파일 제거
check_CSAP_Nginx_02() {
    local status="양호"
    local detail=""
    local cmd="ls -al [Nginx 설정 디렉터리]"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 불필요한 파일 삭제 1) 주기적으로 Nginx 설정 디렉터리 내 불필요한 파일(test, old, bak 파일 등)을 확인 2) # cd [Nginx 설치 디렉터리] 3) # rm –rf [불필요한 파일명] [주요기반시설 가이드] 불필요한 파일 및 디렉터리를 제거하도록 설정 [상세 조치 사례] l Nginx Step 1) rm 명령어로 확인된 불필요한 매뉴얼 디렉터리 및 파일 제거 # rm –rf /<Nginx 설치 디렉터리>/html/index.html"

    local output
    output=$({
        ( ls -al )
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

    add_result "CSAP-Nginx-02 / ISMS-WEB-07" "보안 설정" "불필요한 파일 제거" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Nginx-03 / ISMS-WEB-12: 링크 사용 금지
check_CSAP_Nginx_03() {
    local status="양호"
    local detail=""
    local cmd="car [Nginx 설정 파일] | grep \"disable_symlinks"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 심볼릭 링크 제한 1) # vi [Nginx 설정 파일] [주요기반시설 가이드] 웹 서비스 링크 사용 제한 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 설정된 모든 디렉터리의 disable_symlinks on 설정(기본값 : 설정값 없음) location / { root html; index index.html index.htm; disable_symlinks on; }"

    local config_file="${NGINX_CONF:-/etc/nginx/nginx.conf}"
    [ -n "${NGINX_CONF:-}" ] && config_file="${NGINX_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "disable_symlinks" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
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
    fi

    add_result "CSAP-Nginx-03 / ISMS-WEB-12" "보안 설정" "링크 사용 금지" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Nginx-04 / ISMS-WEB-08: 파일 업로드 및 다운로드 제한
check_CSAP_Nginx_04() {
    local status="양호"
    local detail=""
    local cmd="cat [Ningx 설정 파일] | grep clien_max_body_size"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 파일 업로드 및 다운로드 용량 제한 설정 1) # vi [Nginx 설정 파일] [주요기반시설 가이드] 파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 client_max_body_size 요소 파일 용량 제한 설정 # vi /<Nginx 설치 디렉터리>/nginx.conf <Directory/> client_max_body_size 5M; (설정 단위: byte) </Directory> Step 2) Nginx 데몬 재구동 # systemctl restart nginx"

    local output
    output=$({
        ( get_process_snapshot "client_max_body_size" )
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

    add_result "CSAP-Nginx-04 / ISMS-WEB-08" "보안 설정" "파일 업로드 및 다운로드 제한" "하" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Nginx-05 / ISMS-WEB-04: 디렉터리 리스팅 제거
check_CSAP_Nginx_05() {
    local status="양호"
    local detail=""
    local cmd="cat [Ningx 설정 파일] | grep autoindex"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 디렉터리 검색 기능 비활성화 1) # vi [Nginx 설정 파일] [주요기반시설 가이드] 디렉터리 리스팅 기능 차단 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 autoindex 지시자 off 설정 # vi /<Nginx 설치 디렉터리>/conf/nginx.conf server { autoindex off; } Step 2) Nginx 재시작 # systemctl restart nginx"

    local output
    output=$({
        ( get_process_snapshot "autoindex:space:+(on" )
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

    add_result "CSAP-Nginx-05 / ISMS-WEB-04" "접근 관리" "디렉터리 리스팅 제거" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Nginx-06 / ISMS-WEB-09: 웹 프로세스 제한
check_CSAP_Nginx_06() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep nginx"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ Nginx 데몬 user/group 변경 1) user 지시자에 root가 아닌 별도의 계정으로 변경 # vi [Nginx 설정 파일] 2) 설정한 별도의 계정이 로그인할 수 없도록 nologin 설정 [주요기반시설 가이드] 웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 Nginx 데몬 구동 권한을 관리자 계정이 아닌 별도 계정으로 변경 # vi /[Nginx 설치 디렉터리]/conf/nginx.conf User nginx nginx; Step 2) Nginx 전용 계정 생성 및 Nginx 전용 그룹 추가 # adduser --system --no-create-home --shell /bin/false nginx # groupadd nginx && sudo usermod -aG nginx nginx Step 3) 웹서비스 실행 계정 로그인 제한 설정 # usermod –s /sbin/nologin [사용자명] Step 4) Nginx 서비스 재구동 # systemctl restart nginx 03. 웹 서비스 297"

    local output
    output=$({
        ( get_process_snapshot "nginx" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진"
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
        if printf '%s\n' "$output" | awk 'NR == 1 && $1 == "UID" {next} $1 == "root" {found=1} END {exit found ? 0 : 1}'; then
            status="취약"
            detail="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정으로 구동되고 있는 경우"
        elif printf '%s\n' "$output" | grep -Eiq "production|node_env|environment=production|user[[:space:]]*=[[:space:]]*[a-z0-9_-]+"; then
            status="양호"
            detail="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진"
        else
            status="양호"
            detail="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Nginx-06 / ISMS-WEB-09" "웹 서비스 > 2. 서비스 관리" "웹 프로세스 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Nginx-07: 최신 보안 패치 적용
check_CSAP_Nginx_07() {
    local status="양호"
    local detail=""
    local cmd="[Nginx 실행 디렉터리]/nginx -v"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( /nginx -v )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="최신 보안 패치를 적용한 경우"
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

    add_result "CSAP-Nginx-07" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-05: 지정하지 않은 CGI/ISAPI 실행 제한
check_ISMS_WEB_05() {
    local status="양호"
    local detail=""
    local cmd="cat /<Nginx 설치 디렉터리>/conf/nginx.conf"
    local cur_state=""
    local remediation="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 Fastcgi 사용 여부 확인 # cat /<Nginx 설치 디렉터리>/conf/nginx.conf location ~ \\.cgi\$ { #fastcgi_pass <FastCGI 서버 주소>:<FastCGI 서버 통신 포트>; #include fastcgi_params; } Step 2) Nginx 재시작"

    local config_file="//conf/nginx.conf"
    [ -n "${NGINX_CONF:-}" ] && config_file="${NGINX_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        actual_config=$(ls ${NGINX_CONF:-/etc/nginx/nginx.conf} 2>/dev/null | head -1)
        [ -n "$actual_config" ] && config_file="${NGINX_CONF:-/etc/nginx/nginx.conf}"
    fi
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "fastcgi_pass|uwsgi_pass|scgi_pass" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
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
    fi

    add_result "ISMS-WEB-05" "웹 서비스 > 2. 서비스 관리" "지정하지 않은 CGI/ISAPI 실행 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-06: 웹 서비스 상위 디렉터리 접근 제한 설정
check_ISMS_WEB_06() {
    local status="양호"
    local detail=""
    local cmd="cat /<Nginx 설치 디렉터리>/conf/nginx.conf"
    local cur_state=""
    local remediation="상위 디렉터리 접근 기능 제거 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 디렉터리 접근을 기본 인증으로 제한 설정 # cat /<Nginx 설치 디렉터리>/conf/nginx.conf location /<접근제한 디렉터리>/ { auth_basic \"Restricted Content\"; auth_basic_user_file /etc/nginx/.htpasswd; }"

    local config_file="//conf/nginx.conf"
    [ -n "${NGINX_CONF:-}" ] && config_file="${NGINX_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        actual_config=$(ls ${NGINX_CONF:-/etc/nginx/nginx.conf} 2>/dev/null | head -1)
        [ -n "$actual_config" ] && config_file="${NGINX_CONF:-/etc/nginx/nginx.conf}"
    fi
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

    add_result "ISMS-WEB-06" "웹 서비스 > 2. 서비스 관리" "웹 서비스 상위 디렉터리 접근 제한 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-10: 불필요한 프록시 설정 제한
check_ISMS_WEB_10() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"proxy_pass|proxy_set_header|proxy_redirect\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본적으로 reverse proxy 지시자가 설정되지 않았습니다.\"; fi; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 웹 사이트에서 불필요한 Proxy 설정 제거 # cat /[Nginx 설치 디렉터리/nginx.conf location / { proxy_pass http://backendserver:8080; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; }"

    local output
    output=$({
        ( get_process_snapshot "proxy_pass" )
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

# ISMS-WEB-14: 웹 서비스 경로 내 파일의 접근 통제
check_ISMS_WEB_14() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정 [상세 조치 사례] l Nginx Step 1) 루트 디렉터리 불필요한 권한 삭제 또는 적절한 권한 부여 # chown –R <Nginx 계정>:<Nginx 그룹> web.xml # chmod -R 750 web.xml"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-WEB-14" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 내 파일의 접근 통제" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-16: 웹 서비스 헤더 정보 노출 제한
check_ISMS_WEB_16() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"server_tokens[[:space:]]+(on|off)\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_BAD|기본값은 server_tokens on 입니다.\"; fi; else echo \"FILE_DEFAULT_BAD|기본값은 server_tokens on 입니다.\"; fi"
    local cur_state=""
    local remediation="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정 [상세 조치 사례] l Nginx Step 2) nginx.conf 파일 내 server_tokens 값을 \"off\"로 설정 server_tokens off;"

    local output
    output=$({
        ( get_process_snapshot "server_tokens:space:+(on" )
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
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"^[[:space:]]*alias[[:space:]]+\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|가상 디렉터리 alias 지시자를 확인하지 못했습니다.\"; fi; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정 [상세 조치 사례] l Nginx Step 1) Alias 지시자 확인 # vi /[Nginx Dir]/nginx –v location /virtual { alias /var/www/virtual; index index.html index.htm; } Step 2) 설정된 모든 디렉터리의 불필요한 Alias 지시자 제거 Step 3) Nginx 재구동 # systemctl restart nginx"

    local output
    output=$({
        ( get_process_snapshot ":space:*alias:space:+" )
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

# ISMS-WEB-18: 웹 서비스 WebDAV 비활성화
check_ISMS_WEB_18() {
    local status="양호"
    local detail=""
    local cmd="cat /[Nginx 설치 디렉터리]/conf/nginx.conf"
    local cur_state=""
    local remediation="WebDAV 서비스 비활성화 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 모든 디렉터리에서 WebDAV 설정 확인 # cat /[Nginx 설치 디렉터리]/conf/nginx.conf location /webdav { root /path/to/webdav; dav_methods PUT DELETE MKCOL COPY MOVE; dav_access user:rw group:rw all:r; create_full_put_path on; } Step 2) nginx.conf 파일 내 모든 디렉터리에서 WebDAV 설정 주석 처리 또는 제거 Step 3) Nginx 재구동 # systemctl restart nginx"

    local output
    output=$({
        ( cat //conf/nginx.conf )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="WebDAV 서비스를 비활성화하고 있는 경우"
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
            detail="WebDAV 서비스를 비활성화하고 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="WebDAV 서비스를 활성화하고 있는 경우"
        else
            status="취약"
            detail="WebDAV 서비스를 활성화하고 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-18" "웹 서비스 > 2. 서비스 관리" "웹 서비스 WebDAV 비활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-19: 웹 서비스 SSI(Server Side Includes) 사용 제한
check_ISMS_WEB_19() {
    local status="양호"
    local detail=""
    local cmd="cat /[Nginx 설치 디렉터리]/conf/nginx.conf"
    local cur_state=""
    local remediation="웹 서비스 내 불필요한 SSI 사용 제한 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 SSI 옵션 사용 여부 확인 # cat /[Nginx 설치 디렉터리]/conf/nginx.conf location / { ssi on; } Step 2) nginx.conf 파일 내 모든 디렉터리의 SSI 옵션 설정 # vi /[Nginx 설치 디렉터리]/conf/nginx.conf location / { ssi off; }"

    local config_file="//conf/nginx.conf"
    [ -n "${NGINX_CONF:-}" ] && config_file="${NGINX_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        actual_config=$(ls ${NGINX_CONF:-/etc/nginx/nginx.conf} 2>/dev/null | head -1)
        [ -n "$actual_config" ] && config_file="${NGINX_CONF:-/etc/nginx/nginx.conf}"
    fi
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

    add_result "ISMS-WEB-19" "웹 서비스 > 3. 보안 설정" "웹 서비스 SSI(Server Side Includes) 사용 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-20: SSL/TLS 활성화
check_ISMS_WEB_20() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"ssl_certificate|listen[[:space:]]+443|ssl_protocols\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_BAD|기본값은 SSL/TLS 미활성입니다.\"; fi; else echo \"FILE_DEFAULT_BAD|기본값은 SSL/TLS 미활성입니다.\"; fi"
    local cur_state=""
    local remediation="웹 서비스 내 SSL/TLS 활성화 설정 [상세 조치 사례] l Nginx Step 1) SSL 인증서 파일 및 개인키 파일 준비 Step 2) nginx.conf 파일 내 SSL/TLS 설정 # vi /[Nginx 설치 디렉터리]/conf/nginx.conf server { listen 80; server_name example.com; location / { return 301 https://\$host\$request_uri; } } server { listen 443 ssl; server_name example.com; ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem; 03. 웹 서비스 ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers on; ssl_ciphers 'SSL_CIPHERS'; } } Step 3) Nginx 재구동 # systemctl restart nginx"

    local output
    output=$({
        ( get_process_snapshot "ssl_certificate" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="SSL/TLS 설정이 활성화되어 있는 경우"
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
            detail="SSL/TLS 설정이 활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="SSL/TLS 설정이 비활성화되어 있는 경우"
        else
            status="취약"
            detail="SSL/TLS 설정이 비활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-20" "웹 서비스 > 3. 보안 설정" "SSL/TLS 활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-21: HTTP 리디렉션
check_ISMS_WEB_21() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"return[[:space:]]+301|rewrite[[:space:]].*https://|error_page[[:space:]]+497\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_BAD|기본값은 HTTP 리디렉션 미설정입니다.\"; fi; else echo \"FILE_DEFAULT_BAD|기본값은 HTTP 리디렉션 미설정입니다.\"; fi"
    local cur_state=""
    local remediation="HTTP Redirection 활성화 설정 [상세 조치 사례] l Nginx Step 1) Server 블록 내 HTTPS Redirection 설정 확인 # vi /[Nginx 설치 디렉터리]/sites-available/default server { listen 80; server_name yourdomain.com www.yourdomain.com; return 301 https://\$host\$request_uri; } Step 2) SSL 활성화 설정 # vi /[Nginx 설치 디렉터리]/sites-available/default server { listen 80; server_name mydomain.com www.mydomain.com; return 301 https://\$host\$request_uri; } Step 3) Nginx 재구동 # systemctl restart nginx"

    local output
    output=$({
        ( get_process_snapshot "return:space:+301" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="HTTP 접근 시 HTTPS Redirection이 활성화된 경우"
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
            detail="HTTP 접근 시 HTTPS Redirection이 활성화된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="HTTP 접근 시 HTTPS Redirection이 비활성화된 경우"
        else
            status="취약"
            detail="HTTP 접근 시 HTTPS Redirection이 비활성화된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-21" "웹 서비스 > 3. 보안 설정" "HTTP 리디렉션" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-22: 에러 페이지 관리
check_ISMS_WEB_22() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"error_page[[:space:]]+[0-9]{3}\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_BAD|기본 에러 페이지가 일원화되어 있지 않을 수 있습니다.\"; fi; else echo \"FILE_DEFAULT_BAD|기본 에러 페이지가 일원화되어 있지 않을 수 있습니다.\"; fi"
    local cur_state=""
    local remediation="필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 에러 코드별 에러 페이지 설정 정보 확인 후 별도의 일원화된 에러 페이지 설정 # vi /[Nginx 설치 디렉터리]/conf/nginx.conf server { ... error_page 404 /404.html; error_page 500 502 503 504 /50x.html; location = /404.html { root html; internal; } location = /50x.html { root html; internal; } (이하 생략) } 340"

    local output
    output=$({
        ( get_process_snapshot "error_page:space:+0-9{3}" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

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

    add_result "ISMS-WEB-22" "웹 서비스 > 3. 보안 설정" "에러 페이지 관리" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-24: 별도의 업로드 경로 사용 및 권한 설정
check_ISMS_WEB_24() {
    local status="양호"
    local detail=""
    local cmd="cfg=\${NGINX_CONF:-/etc/nginx/nginx.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"client_body_temp_path|location[[:space:]]+/.+upload|alias[[:space:]].+upload|root[[:space:]].+upload\" \"\$cfg\" 2>/dev/null | head -20); printf '%s\\n' \"\$out\"; else echo \"FILE_MISSING|설정 파일을 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정 [상세 조치 사례] l Nginx Step 1) nginx.conf 파일 내 업로드 경로 확인 및 웹서비스 디렉터리 경로 사용 여부 확인 #vi /[Nginx 설치 디렉터리]/conf/nginx.conf Step 2) 별도의 업로드 경로 생성 mkdir [웹서비스 디렉터리 외 경로] mkdir /var/www/html/uploads 03. 웹 서비스 Step 3) 업로드 디렉터리의 권한 설정 chmod 750 /var/www/html/uploads/ chown www-data:www-data /var/www/html/uploads/ Step 4) nginx.conf 파일 내 업로드 디렉터리 접근제한 설정 #vi /[Nginx 설치 디렉터리]/conf/nginx.conf location /uploads/ { alias /var/www/html/uploads/; autoindex on; } Step 5) 변경된 설정 내용을 적용하기 위하여 Nginx 데몬 재구동 #systemctl restart nginx"

    local output
    output=$({
        ( get_process_snapshot "client_body_temp_path" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
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
            detail="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
        else
            status="취약"
            detail="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-WEB-24" "웹 서비스 > 3. 보안 설정" "별도의 업로드 경로 사용 및 권한 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-WEB-25: 주기적 보안 패치 및 벤더 권고사항 적용
check_ISMS_WEB_25() {
    local status="양호"
    local detail=""
    local cmd="/[Nginx Dir]/nginx -v"
    local cur_state=""
    local remediation="패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정 [상세 조치 사례] l Nginx Step 1) 웹 서버 버전과 최신 패치 버전을 비교하여 확인 # /[Nginx Dir]/nginx –v [ Nginx 웹 서버 버전 확인 ] Step 2) Nginx 사이트를 통해 주기적으로 버전 점검을 하며, 최신 버전 적용 시 충분한 테스트 후 적용 권고 ※ 참고 사이트: https://nginx.org/en/download.html"

    local output
    output=$({
        ( //nginx -v )
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
    local cmd="ls -al /<Nginx 로그 디렉터리>"
    local cur_state=""
    local remediation="로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정 [상세 조치 사례] l Nginx Step 1) 로그 디렉터리 및 파일의 권한 확인 # ls –al /<Nginx 로그 디렉터리> Step 2) 로그 디렉터리 및 파일의 불필요 권한 삭제 # chmod o-rwx /<Nginx 로그 디렉터리>"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/var/log/nginx
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

echo "===== Nginx CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/21] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Nginx-01"; check_CSAP_Nginx_01
progress "CSAP-Nginx-02"; check_CSAP_Nginx_02
progress "CSAP-Nginx-03"; check_CSAP_Nginx_03
progress "CSAP-Nginx-04"; check_CSAP_Nginx_04
progress "CSAP-Nginx-05"; check_CSAP_Nginx_05
progress "CSAP-Nginx-06"; check_CSAP_Nginx_06
progress "CSAP-Nginx-07"; check_CSAP_Nginx_07
progress "ISMS-WEB-05"; check_ISMS_WEB_05
progress "ISMS-WEB-06"; check_ISMS_WEB_06
progress "ISMS-WEB-10"; check_ISMS_WEB_10
progress "ISMS-WEB-14"; check_ISMS_WEB_14
progress "ISMS-WEB-16"; check_ISMS_WEB_16
progress "ISMS-WEB-17"; check_ISMS_WEB_17
progress "ISMS-WEB-18"; check_ISMS_WEB_18
progress "ISMS-WEB-19"; check_ISMS_WEB_19
progress "ISMS-WEB-20"; check_ISMS_WEB_20
progress "ISMS-WEB-21"; check_ISMS_WEB_21
progress "ISMS-WEB-22"; check_ISMS_WEB_22
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
    echo '    "platform": "Nginx",'
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

echo "===== Nginx CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
