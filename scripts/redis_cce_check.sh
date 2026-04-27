#!/bin/bash
###############################################################################
# Redis CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash redis_cce_check.sh -h <host> -P <port> -u <user> -p <password> [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

# Database connection parameters
DB_HOST="localhost"
DB_PORT="6379"
DB_USER=""
DB_PASS=""

usage() {
    echo "Usage: sudo bash redis_cce_check.sh [-h host] [-P port] [-u user] [-p password] [output_file.json]"
    exit 1
}

while getopts "h:P:u:p:" opt; do
    case $opt in
        h) DB_HOST="$OPTARG" ;;
        P) DB_PORT="$OPTARG" ;;
        u) DB_USER="$OPTARG" ;;
        p) DB_PASS="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )
OUTPUT_FILE="${1:-cce_check_result_redis_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"


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


# --- Redis helper ---
run_redis_cli() {
    local cmd="$1"
    if [ -n "$DB_PASS" ]; then
        redis-cli -h "$DB_HOST" -p "$DB_PORT" -a "$DB_PASS" --no-auth-warning $cmd 2>/dev/null
    else
        redis-cli -h "$DB_HOST" -p "$DB_PORT" $cmd 2>/dev/null
    fi
}


# --- Pre-flight: Redis 설치 확인 및 경로 탐지 ---
REDIS_CLI=""
REDIS_CONF="${REDIS_CONF:-}"
REDIS_DATA_DIR="${REDIS_DATA_DIR:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    REDIS_CLI=$(command -v redis-cli 2>/dev/null)
    local redis_server_bin
    redis_server_bin=$(command -v redis-server 2>/dev/null)

    # 2) 프로세스에서 config 경로 추출
    local redis_proc
    redis_proc=$(get_process_snapshot 'redis-server')
    if [ -n "$redis_proc" ]; then
        # redis-server /path/to/redis.conf 형태에서 추출
        local conf_from_proc
        conf_from_proc=$(echo "$redis_proc" | grep -oP '\S+redis\.conf' | head -1)
        if [ -n "$conf_from_proc" ] && [ -f "$conf_from_proc" ]; then
            REDIS_CONF="$conf_from_proc"
        fi
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$REDIS_CONF" ]; then
        for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf /usr/local/etc/redis.conf /opt/cce/redis/redis.conf; do
            if [ -f "$f" ]; then
                REDIS_CONF="$f"
                break
            fi
        done
    fi
    if [ -z "$REDIS_DATA_DIR" ] && [ -n "$REDIS_CONF" ] && [ -f "$REDIS_CONF" ]; then
        REDIS_DATA_DIR=$(sed -n 's/^[[:space:]]*dir[[:space:]]\+\([^#].*\)$/\1/p' "$REDIS_CONF" | head -1 | tr -d '"')
    fi
    if [ -z "$REDIS_DATA_DIR" ]; then
        REDIS_DATA_DIR="/data"
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$REDIS_CLI" ] && [ -z "$redis_server_bin" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'redis-server' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'redis' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$REDIS_CLI" ] || [ -n "$redis_server_bin" ] || [ -n "$REDIS_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Redis 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Redis-01: Redis 인증 패스워드 설정
check_CSAP_Redis_01() {
    local status="양호"
    local detail=""
    local cmd="cat [redis 디렉터리/redis.conf] | grep -i requirepass"
    local cur_state=""
    local remediation="￭ redis.conf 파일 안의 requirepass 설정 1) # vi /etc/redis/redis.conf 2) requirepass 값 설정 3) 인증 로그인 확인"

    local output
    output=$({ ( run_redis_cli "CONFIG GET requirepass" ); ( cfg="${REDIS_CONF:-/etc/redis/redis.conf}"; [ -f "$cfg" ] && grep -Ein "^[[:space:]]*requirepass" "$cfg" 2>/dev/null || echo "FILE_DEFAULT_BAD|기본값은 인증 비밀번호 미설정입니다." ); } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="${output:-결과 없음}"
    if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then
        status="취약"
        detail="해당 파일이 없으므로 취약 - 기본값은 인증 비밀번호 미설정입니다."
    elif printf '%s\n' "$output" | grep -Eiq "requirepass[[:space:]]+$|^requirepass$|^[[:space:]]*$"; then
        status="취약"
        detail="Redis 인증 비밀번호가 설정되지 않았습니다."
    elif printf '%s\n' "$output" | grep -Eiq "requirepass"; then
        status="양호"
        detail="Redis 인증 비밀번호 설정을 확인했습니다."
    else
        status="수동점검"
        detail="Redis 인증 설정 결과를 수집했습니다. 실제 적용 여부를 확인하십시오."
    fi

    add_result "CSAP-Redis-01" "패치 및 로그 관리" "Redis 인증 패스워드 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-02: Binding 설정
check_CSAP_Redis_02() {
    local status="양호"
    local detail=""
    local cmd="cat [redis 디렉터리/redis.conf | grep -i bind"
    local cur_state=""
    local remediation="￭ redis.conf 파일 안의 bind 설정 1) # vi [redis 디렉터리/redis.conf] (인가된 IP만 접근 가능하도록 설정)"

    local config_file="${REDIS_CONF:-/etc/redis/redis.conf}"
    [ -n "${REDIS_CONF:-}" ] && config_file="${REDIS_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "^[[:space:]]*bind[[:space:]]+|^[[:space:]]*protected-mode[[:space:]]+" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="취약"
        detail="비인가된 IP가 접근 가능하도록 설정되어"
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
            detail="비인가된 IP가 접근 가능하도록 설정되어"
        else
            status="양호"
            detail="인가된 IP만 접근 가능하도록 설정되어 있는"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-Redis-02" "보안 설정" "Binding 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-03: Slave 읽기 모드 전용 모드 설정
check_CSAP_Redis_03() {
    local status="양호"
    local detail=""
    local cmd="cat [redis 디렉터리]/redis.conf | grep -i replica-read-only"
    local cur_state=""
    local remediation="￭ redis.conf 파일 내 replica-read-only 설정 1) # vi [redis 디렉터리]/redis.conf replica-read-only를 yes로 변경"

    local config_file="${REDIS_CONF:-/etc/redis/redis.conf}"
    [ -n "${REDIS_CONF:-}" ] && config_file="${REDIS_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "replica-read-only|slave-read-only" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="취약"
        detail="Slave에 쓰기 설정이 가능하도록 설정되어"
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
            detail="Slave에 쓰기 설정이 가능하도록 설정되어"
        else
            status="양호"
            detail="Slave에 읽기 권한만 설정되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-Redis-03" "" "Slave 읽기 모드 전용 모드 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-04: rename-command 설정
check_CSAP_Redis_04() {
    local status="양호"
    local detail=""
    local cmd="cat [redis 디렉터리]/redis.conf | grep -i rename-command"
    local cur_state=""
    local remediation="￭ redis.conf 파일 안의 rename-command CONFIG 설정 1) # vi [redis 디렉터리]/redis.conf rename-command CONFIG \"\" 주석 처리 해제"

    local config_file="${REDIS_CONF:-/etc/redis/redis.conf}"
    [ -n "${REDIS_CONF:-}" ] && config_file="${REDIS_CONF}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "rename-command[[:space:]]+config" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="양호"
        detail="rename-command CONFIG를 빈칸으로"
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
            detail="rename-command CONFIG를 빈칸으로"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="rename-command CONFIG 설정이"
        else
            status="취약"
            detail="rename-command CONFIG 설정이"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-Redis-04" "보안 설정" "rename-command 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-05: 데이터 디렉터리 접근 권한 설정
check_CSAP_Redis_05() {
    local status="양호"
    local detail=""
    local cmd="ls -ld [redis 데이터 디렉터리]"
    local cur_state=""
    local remediation="￭ redis 데이터 디렉터리 접근 권한 750으로 설정 1) # chmod 750 [redis 데이터 디렉터리]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${REDIS_DATA_DIR:-/data}
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "750")
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
    [ -z "$detail" ] && detail="데이터 디렉토리의 접근 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Redis-05" "" "데이터 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-06: 설정 파일 접근권한 설정
check_CSAP_Redis_06() {
    local status="양호"
    local detail=""
    local cmd="ls -al [redis 디렉터리]/redis.conf"
    local cur_state=""
    local remediation="￭ redis.conf 파일의 권한을 600 이하로 설정 1) # chmod 600 [redis 데이터디렉터리]/redis.conf"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${REDIS_CONF:-/etc/redis/redis.conf}
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="설정 파일의 접근 권한이 600(-rw-------)" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Redis-06" "디렉터리 및 파일권한 관리" "설정 파일 접근권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-07: 로그 활성화
check_CSAP_Redis_07() {
    local status="양호"
    local detail=""
    local cmd="run_redis_cli \"CONFIG GET loglevel\"; run_redis_cli \"CONFIG GET logfile\"; cfg=\${REDIS_CONF:-/etc/redis/redis.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"^[[:space:]]*log(level|file)\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|기본 loglevel은 notice 입니다.\"; fi; else echo \"FILE_DEFAULT_GOOD|기본 loglevel은 notice 입니다.\"; fi"
    local cur_state=""
    local remediation="￭ slow query 로그 설정 1) 127.0.0.1:6379> config set slowlog-log-slower-than 100 ￭ slow query 로그 설정 1) # vi /etc/[redis 디렉터리]/redis.conf 파일 안의 loglevel notice로 변경 ※ default 설정 : notice"

    cmd="run_redis_cli \"CONFIG GET loglevel\"; run_redis_cli \"CONFIG GET logfile\"; grep -Ein \"^[[:space:]]*log(level|file)\" ${REDIS_CONF:-/etc/redis/redis.conf}"
    local output
    output=$({ ( run_redis_cli "CONFIG GET loglevel" ); ( run_redis_cli "CONFIG GET logfile" ); ( cfg="${REDIS_CONF:-/etc/redis/redis.conf}"; [ -f "$cfg" ] && grep -Ein "^[[:space:]]*log(level|file)" "$cfg" 2>/dev/null || echo "FILE_DEFAULT_GOOD|기본 loglevel은 notice 입니다." ); } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="${output:-결과 없음}"
    if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
        status="양호"
        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - 기본 loglevel은 notice 입니다."
    elif printf '%s\n' "$output" | grep -Eiq "notice|verbose|stdout|/proc/1/fd/1"; then
        status="양호"
        detail="Redis 로그 설정을 확인했습니다."
    else
        status="수동점검"
        detail="Redis 로그 설정 결과를 수집했습니다. 보관/백업 정책은 추가 확인이 필요합니다."
    fi

    add_result "CSAP-Redis-07" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Redis-08: 최신 보안 패치 적용
check_CSAP_Redis_08() {
    local status="양호"
    local detail=""
    local cmd="redis-cli -h 127.0.0.1 -p 6379; [redis 디렉터리]/redis-cli -v"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 취약점이 없는 보안 패치가 적용된 버전으로 업데이트해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( redis-cli -h 127.0.0.1 -p 6379 )
        ( /redis-cli -v )
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

    add_result "CSAP-Redis-08" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Redis CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/8] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Redis-01"; check_CSAP_Redis_01
progress "CSAP-Redis-02"; check_CSAP_Redis_02
progress "CSAP-Redis-03"; check_CSAP_Redis_03
progress "CSAP-Redis-04"; check_CSAP_Redis_04
progress "CSAP-Redis-05"; check_CSAP_Redis_05
progress "CSAP-Redis-06"; check_CSAP_Redis_06
progress "CSAP-Redis-07"; check_CSAP_Redis_07
progress "CSAP-Redis-08"; check_CSAP_Redis_08

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
    echo '    "platform": "Redis",'
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

echo "===== Redis CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
