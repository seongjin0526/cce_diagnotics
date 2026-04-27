#!/bin/bash
###############################################################################
# PostgreSQL CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash postgresql_cce_check.sh -h <host> -P <port> -u <user> -p <password> [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

# Database connection parameters
DB_HOST="localhost"
DB_PORT="5432"
DB_USER="postgres"
DB_PASS=""

usage() {
    echo "Usage: sudo bash postgresql_cce_check.sh [-h host] [-P port] [-u user] [-p password] [output_file.json]"
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
OUTPUT_FILE="${1:-cce_check_result_postgresql_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"


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


# --- PostgreSQL helper ---
run_psql_query() {
    local query="$1"
    local db="${2:-postgres}"
    if [ -n "$DB_PASS" ]; then
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db" -t -c "$query" 2>/dev/null
    else
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db" -t -c "$query" 2>/dev/null
    fi
}


# --- Pre-flight: PostgreSQL 설치 확인 및 경로 탐지 ---
PSQL_BIN=""
PG_DATA="${PG_DATA:-}"
PG_CONF="${PG_CONF:-}"
PG_HBA="${PG_HBA:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    PSQL_BIN=$(command -v psql 2>/dev/null)
    local pg_config_bin
    pg_config_bin=$(command -v pg_config 2>/dev/null)

    # 2) 프로세스에서 data dir 추출
    local pg_proc
    pg_proc=$(get_process_snapshot 'postgres')
    if [ -n "$pg_proc" ]; then
        PG_DATA=$(echo "$pg_proc" | sed -n 's/.*-D[[:space:]]*\([^ ]*\).*/\1/p')
    fi

    # pg_config 으로 경로 추출
    if [ -z "$PG_DATA" ] && [ -n "$pg_config_bin" ]; then
        local sharedir
        sharedir=$($pg_config_bin --sharedir 2>/dev/null)
        if [ -n "$sharedir" ]; then
            PG_DATA=$(dirname "$sharedir")/data
            [ ! -d "$PG_DATA" ] && PG_DATA=""
        fi
    fi

    # 3) 공통 경로 탐색
    if [ -z "$PG_DATA" ]; then
        for d in /var/lib/postgresql/*/main /var/lib/pgsql/*/data /var/lib/pgsql/data /usr/local/pgsql/data /opt/cce/postgresql/data; do
            if [ -d "$d" ]; then
                PG_DATA="$d"
                break
            fi
        done
    fi

    # 설정 파일 경로 확정
    if [ -n "$PG_DATA" ]; then
        [ -f "$PG_DATA/postgresql.conf" ] && PG_CONF="$PG_DATA/postgresql.conf"
        [ -f "$PG_DATA/pg_hba.conf" ] && PG_HBA="$PG_DATA/pg_hba.conf"
    fi
    # Debian/Ubuntu 스타일
    if [ -z "$PG_CONF" ]; then
        for f in /etc/postgresql/*/main/postgresql.conf; do
            if [ -f "$f" ]; then
                PG_CONF="$f"
                PG_HBA="$(dirname "$f")/pg_hba.conf"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$PSQL_BIN" ] && [ -z "$PG_DATA" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'postgresql' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'postgresql' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$PSQL_BIN" ] || [ -n "$PG_DATA" ] || [ -n "$PG_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] PostgreSQL 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-PostgreSQL-07 / ISMS-D-08: 안전한 암호화 알고리즘 사용
check_CSAP_PostgreSQL_07() {
    local status="양호"
    local detail=""
    local cmd="postgres=# select usename, passwd from pg_shadow;; postgres=# SELECT usename, passwd FROM pg_shadow;; postgres=# CREATE USER password ' ';"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 명령어를 통해 안전한 암호화 알고리즘 적용 1) user 생성 시 적용 postgres=# CREATE user 계정명 PASSWORD '설정할 패스워드'; 2) 기존 user 적용 postgres=# AlTER user 계정명 WITH PASSWORD '설정할 패스워드'; ※ default 설정으로 SCRAM-SHA-256 암호화 알고리즘이 적용 ※ peer : 로컬에서만 연결이 가능하며 OS에서 클라이언트의 OS 사용자 이름을 얻고 요청한 데이터베이스 사용자 이름과 일치하는지 확인하는 인증 방식 [주요기반시설 가이드] SHA-256 이상의 암호화 알고리즘 적용 [상세 조치 사례] l PostgreSQL Step 1) psql 접속 후 계정별 암호화 알고리즘 확인 postgres=# SELECT usename, passwd FROM pg_shadow; Step 2) 명령어를 통한 알고리즘 적용 - user 생성 시 적용 postgres=# CREATE USER 계정명 password '설정할 비밀번호'; - 기존 user 적용 postgres=# ALTER USER 계정명 WITH password '설정할 비밀번호'; ※ default 설정으로 SCRAM-SHA-256 암호화 알고리즘이 적용 ※ peer : 로컬에서만 연결이 가능하며 OS에서 클라이언트의 OS 사용자 이름을 얻고 요청한 데이터베이스 사용자 이름과 일치하는지 확인하는 인증 방식 08. DBMS 625"

    local output
    output=$({
        ( run_psql_query "select usename, passwd from pg_shadow;" )
        ( run_psql_query "SELECT usename, passwd FROM pg_shadow;" )
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
        if printf '%s\n' "$output" | grep -Eiq "md5|mysql_native_password|old_password|sha1"; then
            status="취약"
            detail="해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우"
        elif printf '%s\n' "$output" | grep -Eiq "sha-?256|caching_sha2_password|scram-sha-256|scram_sha_256"; then
            status="양호"
            detail="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
        else
            status="수동점검"
            detail="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-PostgreSQL-07 / ISMS-D-08" "보안 설정" "안전한 암호화 알고리즘 사용" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-01: 불필요한 계정 제거
check_CSAP_PostgreSQL_01() {
    local status="양호"
    local detail=""
    local cmd="postgres=# \\du"
    local cur_state=""
    local remediation="￭ NOLOGIN 설정 1) postgres=# ALTER ROLE 계정명 WITH NOLOGIN; ￭ 불필요한 사용자 계정 제거 1) postgres=# DROP USER 계정명;"

    local output
    output=$({
        ( run_psql_query "\\du" )
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

    add_result "CSAP-PostgreSQL-01" "패치 및 로그 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-02: 취약한 패스워드 사용 제한
check_CSAP_PostgreSQL_02() {
    local status="양호"
    local detail=""
    local cmd="postgres=# select usename, passwd from pg_shadow;"
    local cur_state=""
    local remediation="￭ 기존 계정의 경우, ALTER 명령어를 통해 패스워드 설정 1) postgres=# ALTER ROLE 계정명 WITH PASSWORD '설정할 비밀번호'; ￭ 새로운 계정의 경우, CREATE 명령어를 통해 패스워드 설정 2) postgres=# create user 계정명 password '설정할 비밀번호'; ※ 패스워드 복잡도를 만족하도록 패스워드 설정 영문(대문자, 소문자), 숫자, 특수문자 조합 중 3가지 조합 8자리 이상 또는 2가지 조합 10자리 이상을 만족해야 함 ￭ 불필요한 사용자 계정 제거 1) postgres=# DROP USER 계정명;"

    local output
    output=$({
        ( run_psql_query "select usename, passwd from pg_shadow;" )
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

    add_result "CSAP-PostgreSQL-02" "보안 설정" "취약한 패스워드 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-03: 불필요한 권한 제거
check_CSAP_PostgreSQL_03() {
    local status="양호"
    local detail=""
    local cmd="postgres=# \\du"
    local cur_state=""
    local remediation="￭ 명령어를 통해 불필요한 권한을 제거 1) postgres=# ALTER ROLE 계정명 WITH NOSUPERUSER NOCREATEROLE; ￭ 권한 제거 확인 1) postgres=# \\du"

    local output
    output=$({
        ( run_psql_query "\\du" )
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
            detail="Superuser, Create Role이 적절한 계정에"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="Superuser, Create Role이 적절하지 않은"
        else
            status="취약"
            detail="Superuser, Create Role이 적절하지 않은"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-PostgreSQL-03" "보안 설정" "불필요한 권한 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-04: Public schema 사용 제한
check_CSAP_PostgreSQL_04() {
    local status="양호"
    local detail=""
    local cmd="postgres=# \\dn+"
    local cur_state=""
    local remediation="￭ 명령어를 통해 Public Schema에 public 권한 제거 (예시) 1) postgres=# REVOKE all ON schema public from PUBLIC; ￭ 모든 계정 접근 제한 확인 1) postgres=# \\dn+"

    local output
    output=$({
        ( run_psql_query "\\dn+" )
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
            status="취약"
            detail="Public Schema에 모든 계정이 접근 가능한"
        else
            status="양호"
            detail="Public Schema에 소유주와 특정 계정만이"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-PostgreSQL-04" "" "Public schema 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-05: IP 접근 제한 설정
check_CSAP_PostgreSQL_05() {
    local status="양호"
    local detail=""
    local cmd="cat / | grep listen_address; cat / | grep -v #"
    local cur_state=""
    local remediation="￭ postgresql.conf 수정 1) 인가된 IP 주소로 수정 (예시) 2) 적용 후, PostgreSQL 재시작 # systemctl restart postgresql.service ￭ pg_hba.conf 수정 1) 인가된 IP 주소로 수정 2) 적용 후, PostgreSQL 재시작 # systemctl restart postgresql.service"

    local config_file="${PG_HBA:-${PG_DATA:-/var/lib/postgresql/data}/pg_hba.conf}"
    [ -n "${PG_HBA:-}" ] && config_file="${PG_HBA}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "^[[:space:]]*host|^[[:space:]]*hostssl|^[[:space:]]*hostnossl" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="양호"
        detail="인가된 IP만 접근이 가능하도록 설정된 경우"
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
            detail="인가된 IP만 접근이 가능하도록 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="비인가된 IP가 접근이 가능하도록 설정된"
        else
            status="취약"
            detail="비인가된 IP가 접근이 가능하도록 설정된"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-PostgreSQL-05" "보안 설정" "IP 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-06: 안전한 인증 방식 설정
check_CSAP_PostgreSQL_06() {
    local status="양호"
    local detail=""
    local cmd="run_psql_query \"SELECT line_number, type, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;\" postgres"
    local cur_state=""
    local remediation="￭ pg_hba.conf 수정 1) METHOD 필드 안전한 인증 방식으로 수정"

    local output
    output=$({
        ( run_psql_query "SELECT line_number, type, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;" postgres )
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
            detail="안전한 인증 방식이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="안전한 인증 방식이 적용되지 않은 경우"
        else
            status="취약"
            detail="안전한 인증 방식이 적용되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-PostgreSQL-06" "보안 설정" "안전한 인증 방식 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-08: 데이터 디렉터리 권한 설정
check_CSAP_PostgreSQL_08() {
    local status="양호"
    local detail=""
    local cmd="ls -ld"
    local cur_state=""
    local remediation="￭ 명령어를 통해 접근 권한 변경 1) # chmod 700 [PostgreSQL 데이터 디렉터리]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${PG_DATA:-/var/lib/postgresql/data}
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
    [ -z "$detail" ] && detail="데이터 디렉터리 접근 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-PostgreSQL-08" "" "데이터 디렉터리 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-09: 환경설정 파일 권한 설정
check_CSAP_PostgreSQL_09() {
    local status="양호"
    local detail=""
    local cmd="ls -al"
    local cur_state=""
    local remediation="￭ 명령어를 통해 접근 권한 변경 1) # chmod 600 [PostgreSQL 환경설정 파일]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${PG_CONF:-${PG_DATA:-/var/lib/postgresql/data}/postgresql.conf}
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
    [ -z "$detail" ] && detail="환경설정 파일의 소유자 및 그룹이 별도의" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-PostgreSQL-09" "" "환경설정 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-10: 로그 활성화
check_CSAP_PostgreSQL_10() {
    local status="양호"
    local detail=""
    local cmd="run_psql_query \"SHOW logging_collector;\" postgres; run_psql_query \"SHOW log_destination;\" postgres"
    local cur_state=""
    local remediation="￭ 명령어를 통해 접근 권한 변경 (예시) 1) # chmod 600 [PostgreSQL 환경 설정 파일]"

    local output
    output=$({
        ( run_psql_query "SHOW logging_collector;" postgres )
        ( run_psql_query "SHOW log_destination;" postgres )
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
            detail="로그가 활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="로그가 비활성화되어 있는 경우"
        else
            status="취약"
            detail="로그가 비활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-PostgreSQL-10" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-PostgreSQL-11: 최신 보안 패치 적용
check_CSAP_PostgreSQL_11() {
    local status="양호"
    local detail=""
    local cmd="postgres=# select version();"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 보안 취약점이 존재하지 않는 버전으로 보안 패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( run_psql_query "select version();" )
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

    add_result "CSAP-PostgreSQL-11" "" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-01: 기본 계정의 비밀번호, 정책 등을 변경하여 사용
check_ISMS_D_01() {
    local status="양호"
    local detail=""
    local cmd="sudo -u postgres psql; ALTER USER postgres WITH PASSWORD ' ';"
    local cur_state=""
    local remediation="기본(관리자) 계정의 초기 비밀번호 및 권한 정책 변경 [상세 조치 사례] l PostgreSQL Step 1) postgres 계정으로 접속 계정 변경 및 접속 \$ sudo –u postgres psql # ALTER USER postgres WITH PASSWORD '신규 비밀번호'; # \\q"

    local output
    output=$({
        ( sudo -u postgres psql )
        ( ALTER USER postgres WITH PASSWORD ' '; )
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
            detail="기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="기본 계정의 초기 비밀번호 를 변경하지 않거나 잠금설정을 하지 않은 경우"
        else
            status="취약"
            detail="기본 계정의 초기 비밀번호 를 변경하지 않거나 잠금설정을 하지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-01" "DBMS > 1. 계정 관리" "기본 계정의 비밀번호, 정책 등을 변경하여 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-02: 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
check_ISMS_D_02() {
    local status="양호"
    local detail=""
    local cmd="run_psql_query \"SELECT usename, usesuper, valuntil FROM pg_user ORDER BY usename;\" postgres"
    local cur_state=""
    local remediation="계정별 용도를 파악한 후 불필요한 계정 삭제 [상세 조치 사례] l PostgreSQL Step 1) 모든 사용자 확인 쿼리문 조회 : SELECT * FROM system_.sys_users_; 명령어 조회 : \\du Step 2) 불필요한 계정 삭제 DROP ROLE '삭제할 계정'; 602"

    local output
    output=$({
        ( run_psql_query "SELECT usename, usesuper, valuntil FROM pg_user ORDER BY usename;" postgres )
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

    add_result "ISMS-D-02" "DBMS > 1. 계정 관리" "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-03: 비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정
check_ISMS_D_03() {
    local status="양호"
    local detail=""
    local cmd="mysql> SHOW VARIABLES LIKE 'validate_password%';; mysql> INSTALL COMPONENT 'file://component_validate_password';; mysql> SHOW VARIABLES LIKE 'default_password_lifetime';"
    local cur_state=""
    local remediation="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정 [상세 조치 사례] l Oracle DB Step 1) PASSWORD_LIFE_TIME Profile 파라미터 변경 SQL> ALTER PROFILE <프로파일명> LIMIT PASSWORD_LIFE_TIME xx; Step 2) Profile 값과 관련된 사용자 변경 SQL> ALTER PROFILE <계정명> PROFILE <변경할 프로파일명>; Step 3) 비밀번호 정책 설정 변경 SQL> ALTER PROFILE <프로파일명> LIMIT FAILED_LOGIN_ATTEMPTS 3 (비밀번호 실패 3번 까지만 가능) PASSWORD_LIFE_TIME 30 (30일 동안만 비밀번호 사용 가능 PASSWORD_REUSE_TIME 30 (사용한 비밀번호 30일 후부터 재사용 가능) PASSWORD_VERIFY_FUNCTION verify_function (비밀번호 복잡성 검증) PASSWORD_GRACE_TIME 5; (life time이 끝나고 5일 동안 메시지를 보여줌) l MSSQL Step 1) 비밀번호 변경 주기는 '암호 만료 강제 적용'을 적용함으로써 주기적으로 변경할 수 있으며, 변경 기간은 OS의 '암호 정책'에서 적용받으므로 '암호 정책 > 최대 암호 사용 기간' 설정도 변경해야 함 Step 2) 암호 만료 강제 적용 보안 > 로그인 > 각 로그인 계정 > 속성 > \"암호 만료 강제 적용\" 설정 [ 암호 만료 강제 적용 설정 ] Step 3) OS 암호 정책 설정 [관리 도구] > [로컬 보안 정책] > [보안 설정] > [계정 정책] > [암호 정책] > 최대 암호 사용 기간 : '60일' 설정 [ 최대 암호 사용 기간 설정 ] l MySQL [비밀번호 복잡도 정책 설정] Step 1) 비밀번호 정책 확인 08. DBMS mysql> SHOW VARIABLES LIKE 'validate_password%'; ※ component_validate_password가 설치되어 있지 않은 경우 아래와 같이 해당 컴포넌트 설치 mysql> INSTALL COMPONENT 'file://component_validate_password'; Step 2) 비밀번호 정책 설정 다음과 같은 방법으로 각각의 비밀번호 정책을 설정 SET GLOBAL validate_password.policy = 'MEDIUM'; (비밀번호 정책의 강도 LOW/MEDIUM/STRONG) SET GLOBAL validate_password.length = 8; (비밀번호 최소 길이) SET GLOBAL validate_password.mixed_case_count = 1; (포함되어야 하는 영문 대소문자 최소 개수) SET GLOBAL validate_password.number_count = 1; (포함되어야 하는 숫자 최소 개수) SET GLOBAL validate_password.special_char_count = 1; (포함되어야 하는 특수문자 최소 개수) ※ Linux계열(/etc/my.cnf 또는 /etc/mysql/my.cnf), Windows(C:\\ProgramData\\MySQL\\MySQL Server <설치된 버전>\\my.ini)의 <mysqld> 섹션에 설정을 추가하여 정책 설정 가능 ※ 비밀번호 신규 적용 및 초기화 시 설정 규칙에 맞추어 관리하고, 저장 시에는 일방향 암호화 알고리즘을 통해 암호화 처리(One-Way Encryption)함 [비밀번호 LifeTime 정책 적용 ] Step 1) 비밀번호 정책 확인 mysql> SHOW VARIABLES LIKE 'default_password_lifetime'; Step 2) 비밀번호 LifeTime 설정 mysql> SET GLOBAL default_password_lifetime=90; ※ 기본 값 - 5.7.11 이전 버전 : 0 - 5.7.11 이후 버전 및 8.0 이후 버전 : 360 Step 3) 정책 적용전에 생성된 계정의 LifeTime 변경 mysql> ALTER USER <계정명>'@'<호스트명 or IP>' PASSWORD EXPIRE INTERVAL 91 DAY; l Altibase Step 1) 다음 명령어를 통해 비밀번호 정책 설정 여부 확인 SELECT * FROM system_.sys_users_; Step 2) 아래 Property에 대해 비밀번호 정책 설정 CASE_SENSITIVE_PASSWORD = 1 FAILED_LOGIN_ATTEMPTS PASSWORD_LOCK_TIME PASSWORD_LIFE_TIME PASSWORD_GRACE_TIME PASSWORD_REUSE_TIME PASSWORD_REUSE_MAX PASSWORD_VERIFY_FUNCTION 정책 적용 시 다음 명령어를 사용 ALTER USER 계정명 LIMIT (Property 숫자); 예시) ALTER USER TESTUSER LIMIT (FAILED_LOGIN_ATTEMPTS 7, PASSWORD_LOCK_TIM E 7); l Tibero Step 1) 사용자별 비밀번호 PROFILE 적용 여부 확인 비밀번호 설정 규칙에 맞추어 비밀번호를 설정할 수 있도록 시스템 차원에서 기능 제공 SELECT * FROM dba_users; [ 사용자별 비밀번호 PROFILE 적용 여부 확인 ] Step 2) 설정되어 있을 경우 PROFILE 설정 내용 확인 SELECT * FROM dba_profiles; 08. DBMS [ PROFILE 설정 내용 확인 ] Step 3) 설정되어 있지 않을 경우 PROFILE 생성 또는 수정 시(ALTER PROFILE) 비밀번호 정책 설정 적용 시 다음 명령어를 사용 CREATE PROFILE prof LIMIT 예시) CREATE PROFILE prof LIMIT failed_login_attempts 3 password_lock_time 1/1440 password_life_time 90 password_reuse_time unlimited password_reuse_max 10 password_grace_time 10 password_verify_function verify_function; 608"

    local output
    output=$({
        ( run_psql_query "SHOW VARIABLES LIKE 'validate_password%';" )
        ( run_psql_query "SHOW VARIABLES LIKE 'default_password_lifetime';" )
        ( run_psql_query "SELECT * FROM system_.sys_users_;" )
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
        if printf '%s\n' "$output" | grep -Eiq "md5|mysql_native_password|old_password|sha1"; then
            status="취약"
            detail="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되지 않은 경우"
        elif printf '%s\n' "$output" | grep -Eiq "sha-?256|caching_sha2_password|scram-sha-256|scram_sha_256"; then
            status="양호"
            detail="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
        else
            status="수동점검"
            detail="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-03" "DBMS > 1. 계정 관리" "비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-04: 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
check_ISMS_D_04() {
    local status="양호"
    local detail=""
    local cmd="run_psql_query \"SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles ORDER BY rolname;\" postgres"
    local cur_state=""
    local remediation="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여 [상세 조치 사례] l PostgreSQL Step 1) 계정의 용도 파악 후 불필요한 계정은 삭제, 새로운 계정 생성 시 적절한 권한을 부여하여 생성 모든 사용자 확인 쿼리문 조회 : SELECT * FROM pg_user; or SELECT username, usesuper FROM pg_shadow; 명령어 조회 : \\du Step 2) 불필요하게 관리자 권한이 부여된 경우 권한 회수 ALTER ROLE <계정명> NOSUPERUSER; ALTER ROLE <계정명> NOCREATEROLE; ALTER ROLE <계정명> NOCREATEDB; ALTER ROLE <계정명> NOREPLICATION; ALTER ROLE <계정명> NOBYPASSRLS; Step 3) 612"

    local output
    output=$({
        ( run_psql_query "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles ORDER BY rolname;" postgres )
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

    add_result "ISMS-D-04" "DBMS > 1. 계정 관리" "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-06: DB 사용자 계정을 개별적으로 부여하여 사용
check_ISMS_D_06() {
    local status="양호"
    local detail=""
    local cmd="\\du"
    local cur_state=""
    local remediation="사용자별 계정 생성 및 권한 부여 [상세 조치 사례] l PostgreSQL Step 1) 모든 사용자 확인 쿼리문 조회 : SELECT * FROM pg_shadow; 명령어 조회 : \\du Step 2) 불필요 계정 삭제 DROP ROLE '삭제할 계정'; Step 3) 계정 생성 및 권한 추가 CREATE USER '생성할 계정'; ALTER ROLE '계정명' '권한명' '권한명' ····; \\du (계정 생성 및 권한 확인) ※ 계정의 용도 파악 후 불필요한 계정은 삭제, 새로운 계정 생성 시 적절한 권한을 부여하여 생성 08. DBMS 619"

    local output
    output=$({
        ( run_psql_query "\\du" )
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

    add_result "ISMS-D-06" "DBMS > 1. 계정 관리" "DB 사용자 계정을 개별적으로 부여하여 사용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-10: 원격에서 DB 서버로의 접속 제한
check_ISMS_D_10() {
    local status="양호"
    local detail=""
    local cmd="run_psql_query \"SHOW listen_addresses;\" postgres; run_psql_query \"SELECT line_number, type, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;\" postgres"
    local cur_state=""
    local remediation="DB 서버에 대해 지정된 IP주소에서만 접근 가능하도록 설정 [상세 조치 사례] l PostgreSQL Step 1) Data 디렉터리 내에 postgres.conf 파일 설정 [ postgres.conf 파일 ] ※ listen_addresses는 서버가 클라이언트 애플리케이션의 연결을 수신 대기할 TCP/IP 주소를 지정함. 호 스트 이름 및/또는 숫자 IP 주소의 쉼표로 구분된 목록 형식으로 지정할 수 있으며, *를 사용하는 경우 모든 IP에 대해 수신 대기함. 기본값은 localhost 이며 로컬 TCP/IP \"루프백\" 연결 만 허용 Step 2) Data 디렉터리 내에 pg_hba.conf 파일 설정 TYPE DATABASE USER CIDR-ADDRESS METHOD -------- ----------------- --------- ------------------------- ---------------- host (DB명) (사용자) (접속 허용 IP) md5 08. DBMS [ pg_hba.conf 파일 ] Step 3) USER에 접근 허용 '계정명'과 CIDR-ADDRESS에 접속을 '허용할 IP' 설정 ※ PostgreSQL은 기본 설치 시 외부에서 접속할 수 없음 ※ IP 접근 제한 설정 시 postgresql.conf와 pg_hba.conf 두 개의 설정 파일이 연계되어 있으므로 하나의 파일이라 도 설정이 잘못되어 있는 경우 DB 접속이 불가능 할 수 있음. 632"

    local output
    output=$({
        ( run_psql_query "SHOW listen_addresses;" postgres )
        ( run_psql_query "SELECT line_number, type, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;" postgres )
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
            detail="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한하지 않은 경우"
        else
            status="취약"
            detail="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한하지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-10" "DBMS > 2. 접근 관리" "원격에서 DB 서버로의 접속 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-11: DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
check_ISMS_D_11() {
    local status="양호"
    local detail=""
    local cmd="SELECT * FROM information_schema.role_table_grants;"
    local cur_state=""
    local remediation="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정 [상세 조치 사례] l PostgreSQL Step 1) 사용자 및 역할 권한 정보 조회 SELECT * FROM information_schema.role_table_grants; Step 2) 스키마명에 해당되는 Table에 대한 접근 권한을 일반 사용자로부터 제거 REVOKE [all,select,insert,update...] ON all tables IN schema '스키마명' FROM '계정명'; 08. DBMS 635"

    local output
    output=$({
        ( run_psql_query "SELECT * FROM information_schema.role_table_grants;" )
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
            detail="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우"
        else
            status="취약"
            detail="시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-11" "DBMS > 2. 접근 관리" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-14: 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
check_ISMS_D_14() {
    local status="양호"
    local detail=""
    local cmd="chmod 640 /postgresql.conf; chmod 640 ./pg_hba.conf; chmod 640 ./pg_ident.conf"
    local cur_state=""
    local remediation="주요 설정 파일 및 디렉터리의 권한 설정 변경 [상세 조치 사례] l PostgreSQL [Unix OS] Step 1) 주요 설정 파일 위치 확인 postgresql.conf 파일 위치: [\$datadir] DB 접속 통제 설정 파일 위치: /postgres/data/pg_hba.conf, /postgres/data/pg_ident.conf log_directory : /log_directory/pg_log Step 2) 주요 설정 파일의 권한 설정 환경설정 파일(postgresql.conf)의 권한을 640 이하로 설정 # chmod 640 [\$datadir]/postgresql.conf DB접속 통제 설정 파일(pg_hba.conf, pg_ident.conf)의 권한을 640 이하로 설정 # chmod 640 ./pg_hba.conf # chmod 640 ./pg_ident.conf 히스토리 파일 (.psql_history)의 권한을 600 이하로 설정 \$chmod 600 .psql_history Log 파일(pg_log)의 권한을 640 이하로 설정 #chmod 640 [Log 파일] [Windows OS] Step 1) 주요 환경설정 파일의 접근 권한은 Administrators, SYSTEM, Owner에게 모든 권한 또는 필요 권한만 부여하여 설정하고 기타 다른 그룹은 권한 제거"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/postgresql.conf
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
    target_spec_2=/pg_hba.conf
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
    target_spec_3=/pg_ident.conf
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
    local target_spec_4
    target_spec_4=/postgres/data/pg_hba.conf
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "" "644")
                cur_state+="$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_4). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_4). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_5
    target_spec_5=/postgres/data/pg_ident.conf
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "" "644")
                cur_state+="$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_5). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_5). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_6
    target_spec_6=${PG_CONF:-${PG_DATA:-/var/lib/postgresql/data}/postgresql.conf}
    local resolved_target_6
    resolved_target_6="$target_spec_6"
    if [ -n "$resolved_target_6" ]; then
        for target_path in $resolved_target_6; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_6
                result_6=$(check_file_owner_perm "$target_path" "" "644")
                cur_state+="$target_path: $result_6; "
                case "$result_6" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_6). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_6). " ;;
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
    [ -z "$detail" ] && detail="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우" && cur_state="점검 대상 파일 없음"

    add_result "ISMS-D-14" "DBMS > 2. 접근 관리" "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-20: 인가되지 않은 Object Owner의 제한
check_ISMS_D_20() {
    local status="양호"
    local detail=""
    local cmd="postgres=# SELECT DISTINCT relowner FROM pg_class WHERE relowner NOT IN (SELECT"
    local cur_state=""
    local remediation="Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정 [상세 조치 사례] l PostgreSQL Step 1) Object 권한 정보 확인 postgres=# SELECT DISTINCT relowner FROM pg_class WHERE relowner NOT IN (SELECT usesysid FROM pg_user WHERE usesuper = TRUE); Step 2) 잘못된 Object 권한 소유자 발견 시 권한 회수 654"

    local output
    output=$({
        ( run_psql_query "SELECT DISTINCT relowner FROM pg_class WHERE relowner NOT IN (SELECT" )
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
            detail="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="Object Owner가 일반 사용자에게도 존재하는 경우"
        else
            status="취약"
            detail="Object Owner가 일반 사용자에게도 존재하는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-20" "DBMS > 3. 옵션 관리" "인가되지 않은 Object Owner의 제한" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
check_ISMS_D_25() {
    local status="양호"
    local detail=""
    local cmd="SELECT VERSION();"
    local cur_state=""
    local remediation="보안 패치가 적용된 버전으로 업데이트 [상세 조치 사례] l PostgreSQL Step 1) 시스템에서 제품 버전 현황 확인 SELECT VERSION(); Step 2) PostgreSQL 최신 버전 확인 08. DBMS http://www.postgresql.org/support/security"

    local output
    output=$({
        ( run_psql_query "SELECT VERSION();" )
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
            detail="보안 패치가 적용된 버전을 사용하는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="보안 패치가 적용되지 않는 버전을 사용하는 경우"
        else
            status="취약"
            detail="보안 패치가 적용되지 않는 버전을 사용하는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-25" "DBMS > 4. 패치 관리" "주기적 보안 패치 및 벤더 권고 사항 적용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-26: 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
check_ISMS_D_26() {
    local status="양호"
    local detail=""
    local cmd="postgres=# SHOW logging_collector;"
    local cur_state=""
    local remediation="DBMS에 대한 감사 로그 저장 정책 수립, 적용 [상세 조치 사례] l PostgreSQL Step 1) Log 감사 설정 여부 확인 postgres=# SHOW logging_collector; logging_collector ------------------- on (1 row) Step 2) postgresql.conf 파일 내 logging_collector을 on으로설정 logging_collector = on"

    local output
    output=$({
        ( run_psql_query "SHOW logging_collector;" )
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
            detail="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="DBMS에 대한 감사 로그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우"
        else
            status="취약"
            detail="DBMS에 대한 감사 로그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-26" "DBMS > 4. 패치 관리" "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== PostgreSQL CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/22] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-PostgreSQL-07"; check_CSAP_PostgreSQL_07
progress "CSAP-PostgreSQL-01"; check_CSAP_PostgreSQL_01
progress "CSAP-PostgreSQL-02"; check_CSAP_PostgreSQL_02
progress "CSAP-PostgreSQL-03"; check_CSAP_PostgreSQL_03
progress "CSAP-PostgreSQL-04"; check_CSAP_PostgreSQL_04
progress "CSAP-PostgreSQL-05"; check_CSAP_PostgreSQL_05
progress "CSAP-PostgreSQL-06"; check_CSAP_PostgreSQL_06
progress "CSAP-PostgreSQL-08"; check_CSAP_PostgreSQL_08
progress "CSAP-PostgreSQL-09"; check_CSAP_PostgreSQL_09
progress "CSAP-PostgreSQL-10"; check_CSAP_PostgreSQL_10
progress "CSAP-PostgreSQL-11"; check_CSAP_PostgreSQL_11
progress "ISMS-D-01"; check_ISMS_D_01
progress "ISMS-D-02"; check_ISMS_D_02
progress "ISMS-D-03"; check_ISMS_D_03
progress "ISMS-D-04"; check_ISMS_D_04
progress "ISMS-D-06"; check_ISMS_D_06
progress "ISMS-D-10"; check_ISMS_D_10
progress "ISMS-D-11"; check_ISMS_D_11
progress "ISMS-D-14"; check_ISMS_D_14
progress "ISMS-D-20"; check_ISMS_D_20
progress "ISMS-D-25"; check_ISMS_D_25
progress "ISMS-D-26"; check_ISMS_D_26

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
    echo '    "platform": "PostgreSQL",'
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

echo "===== PostgreSQL CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
