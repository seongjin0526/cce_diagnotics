#!/bin/bash
###############################################################################
# MySQL CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash mysql_cce_check.sh -h <host> -P <port> -u <user> -p <password> [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

# Database connection parameters
DB_HOST="localhost"
DB_PORT="3306"
DB_USER="root"
DB_PASS=""

usage() {
    echo "Usage: sudo bash mysql_cce_check.sh [-h host] [-P port] [-u user] [-p password] [output_file.json]"
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

OUTPUT_FILE="${1:-cce_check_result_mysql_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"


TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# --- JSON helper functions ---
results=()

normalize_trace_value() {
    printf '%s' "$1" | tr '\t\r\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//'
}

summarize_output() {
    printf '%s' "$1" | head -n 5 | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'
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
    detail=$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    command=$(echo "$command" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')

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


# --- MySQL helper ---
run_mysql_query() {
    local query="$1"
    if [ -n "$DB_PASS" ]; then
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" -N -e "$query" 2>/dev/null
    else
        if [ -z "$DB_HOST" ] || [ "$DB_HOST" = "localhost" ] || [ "$DB_HOST" = "127.0.0.1" ] || [ "$DB_HOST" = "::1" ]; then
            mysql -u "$DB_USER" -N -e "$query" 2>/dev/null                 || mysql --protocol=tcp -h 127.0.0.1 -P "${DB_PORT:-3306}" -u "$DB_USER" -N -e "$query" 2>/dev/null                 || mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -N -e "$query" 2>/dev/null
        else
            mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -N -e "$query" 2>/dev/null
        fi
    fi
}


# --- Pre-flight: MySQL 설치 확인 및 경로 탐지 ---
MYSQL_BIN=""
MYSQLD_BIN=""
MYSQL_CONF="${MYSQL_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    MYSQL_BIN=$(command -v mysql 2>/dev/null)
    MYSQLD_BIN=$(command -v mysqld 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$MYSQLD_BIN" ]; then
        MYSQLD_BIN=$(get_process_snapshot 'mysqld' | awk '{for(i=1;i<=NF;i++) if($i ~ /mysqld$/) print $i}' | head -1)
    fi

    # 프로세스에서 --defaults-file 추출
    local defaults_file
    defaults_file=$(get_process_snapshot 'mysqld' | sed -n 's/.*--defaults-file=\([^ ]*\).*/\1/p' | head -1)
    if [ -n "$defaults_file" ] && [ -f "$defaults_file" ]; then
        MYSQL_CONF="$defaults_file"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$MYSQL_CONF" ]; then
        for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf ~/.my.cnf /usr/local/mysql/my.cnf /opt/cce/mysql/my.cnf; do
            if [ -f "$f" ]; then
                MYSQL_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$MYSQL_BIN" ] && [ -z "$MYSQLD_BIN" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'mysql-server\|mysql-client\|mariadb-server' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'mysql-server\|mysql-community\|mariadb-server' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$MYSQL_BIN" ] || [ -n "$MYSQLD_BIN" ] || [ -n "$MYSQL_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] MySQL 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-MY-SQL-05 / ISMS-D-07: root 권한으로 서버 구동 제한
check_CSAP_MY_SQL_05() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep mysqld"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ mysql server configuration 파일에서 [mysqld] 그룹의 'user' 지시자 설정 1\) # vi [mysql server configuration 파일 위치] 2\) user = <mysqld를 구동할 시스템의 일반 사용자 계정> [주요기반시설 가이드] DBMS 구동 계정 변경 [상세 조치 사례] l MySQL Step 1\) 실행 중인 프로세스를 통한 확인 # ps –ef | grep mysqld Step 2\) mysql server configuration 파일에서 [mysqld] 그룹의 'user' 지시자의 설정값 확인 # cat [mysql server configuration 파일 위치] | grep user \(user=mysql로 설정되어 있으면 양호\) Step 3\) mysql server configuration 파일에서 [mysqld] 그룹의 'user' 지시자 설정 # vi [mysql server configuration 파일 위치] \(일반적으로 /etc/my.cnf.d/mysql-server.cnf\) ※ user = [mysqld를 구동할 시스템의 일반 사용자 계정]"

    local output
    output=$({
        ( get_process_snapshot "mysqld" )
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
        if printf '%s\n' "$output" | awk 'NR == 1 && $1 == "UID" {next} $1 == "root" {found=1} END {exit found ? 0 : 1}'; then
            status="취약"
            detail="DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우"
        elif printf '%s\n' "$output" | grep -Eiq "production|node_env|environment=production|user[[:space:]]*=[[:space:]]*[a-z0-9_-]+"; then
            status="양호"
            detail="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
        else
            status="양호"
            detail="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-MY-SQL-05 / ISMS-D-07" "보안 설정" "root 권한으로 서버 구동 제한" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-07 / ISMS-D-08: 안전한 암호화 알고리즘 사용
check_CSAP_MY_SQL_07() {
    local status="양호"
    local detail=""
    local cmd="mysql> SELECT host, user, plugin, authentication_string FROM user;; mysql> SELECT user, host, plugin FROM mysql.user;; mysql> SELECT host, user, plugin, password AS authentication_string FROM mysql.user;"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 안전한 패스워드 암호화 알고리즘 사용 1\) mysql> ALTER user '사용자 계정 이름'@'localhost' IDENTIFIED WITH caching_sha2_password BY '패스워드'; 2\) mysql> FLUSH privileges; [주요기반시설 가이드] SHA-256 이상의 암호화 알고리즘 적용 [상세 조치 사례] l MySQL Step 1\) 계정별 암호화 알고리즘 확인 [mysql 5.7] mysql> SELECT user, host, plugin FROM mysql.user; 또는 mysql> SELECT host, user, plugin, password AS authentication_string FROM mysql.user; [mysql 8.0] 08. DBMS mysql> SELECT user, host, plugin FROM mysql.user; 또는 mysql> SELECT host, user, plugin, authentication_string FROM mysql.user; Step 2\) 비밀번호 및 암호화 알고리즘 설정 [mysql 5.7] - user 생성 시 적용 CREATE USER '계정명'@'host' IDENTIFIED BY '비밀번호'; - 기존 user 적용 ALTER USER '계정명'@'host' IDENTIFIED '신규 비밀번호'; ※ mysql 5.7에서는 기본적으로 mysql_native_password 플러그인이 사용되므로 별도의 지정이 필요하지 않음 [mysql 8.0] - user 생성 시 적용 mysql> CREATE USER '계정명'@'localhost' IDENTIFIED WITH caching_sha2_password BY '비밀번호'; - 기존 user 적용 mysql> ALTER USER '계정명'@'localhost' IDENTIFIED WITH caching_sha2_password BY '비밀번호'; ※ mysql v8.0 이상부터 암호화 알고리즘으로 caching_sha2_password\(SHA-256\)가 적용됨 ※ mysql v5.7 버전에서 사용하던 데이터베이스를 8.0으로 업그레이드하여 mysql_native_password 플러그인이 유 지되는 경우 위와 같이 caching_sha2_password 알고리즘을 지정하여 적용할 수 있음"

    local output
    output=$({
        ( run_mysql_query "SELECT host, user, plugin, authentication_string FROM mysql.user;" )
        ( run_mysql_query "SELECT user, host, plugin FROM mysql.user;" )
        ( run_mysql_query "SELECT host, user, plugin, password AS authentication_string FROM mysql.user;" )
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

    add_result "CSAP-MY-SQL-07 / ISMS-D-08" "DBMS > 1. 계정 관리" "안전한 암호화 알고리즘 사용" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-01: 불필요한 계정 제거
check_CSAP_MY_SQL_01() {
    local status="양호"
    local detail=""
    local cmd="mysql> USE mysql;; mysql> SELECT host, user, authentication_string FROM user;"
    local cur_state=""
    local remediation="￭ 불필요한 계정 삭제 1\) mysql> DELETE FROM user WHERE user='삭제할 계정명';"

    local output
    output=$({
        ( run_mysql_query "SELECT host, user, authentication_string FROM mysql.user;" )
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

    add_result "CSAP-MY-SQL-01" "패치 및 로그 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-02: 취약한 패스워드 사용 제한
check_CSAP_MY_SQL_02() {
    local status="양호"
    local detail=""
    local cmd="mysql> INSTALL COMPONENT file://component_validate_password;; mysql> SHOW VARIABLES LIKE validate_password%;"
    local cur_state=""
    local remediation="￭ validate_password 패스워드 정책 \(예시\) 1\) mysql server configuration 파일에서 아래의 내용으로 수정 # vi /etc/mysql/mysql.conf.d/mysqld.cnf validate_password.length=8 validate_password.mixed_case_count=1 validate_password.number_count=1 validate_password.special_char_count=1 validate_password.policy=MEDIUM 또는 STRONG 2\) # service mysql restart 3\) mysql> SHOW VARIABLES LIKE 'validate_password%';"

    local output
    output=$({
        ( run_mysql_query "SHOW VARIABLES LIKE 'validate_password%';" )
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
            detail="패스워드 복잡도 설정을 적용하고 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="패스워드 복잡도 설정을 적용하고 있지 않은"
        else
            status="취약"
            detail="패스워드 복잡도 설정을 적용하고 있지 않은"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-MY-SQL-02" "계정 관리" "취약한 패스워드 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-03: 타 사용자에 권한 부여 옵션 제한
check_CSAP_MY_SQL_03() {
    local status="양호"
    local detail=""
    local cmd="mysql> USE mysql;; mysql> SELECT host, user, Grant_priv FROM user WHERE Grant_priv=Y;"
    local cur_state=""
    local remediation="￭ 불필요한 grant_priv 권한 제거 1\) mysql> USE mysql; 2\) mysql> REVOKE grant option ON *.* FROM '권한 제거 사용자 계정명'@'접속 IP'; 3\) mysql> FLUSH privileges;"

    local output
    output=$({
        ( run_mysql_query "SELECT host, user, Grant_priv FROM mysql.user WHERE Grant_priv=Y;" )
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

    add_result "CSAP-MY-SQL-03" "계정 관리" "타 사용자에 권한 부여 옵션 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-04: 사용자 계정 정보 테이블 접근 권한
check_CSAP_MY_SQL_04() {
    local status="양호"
    local detail=""
    local cmd="mysql> SELECT host, user, select_priv FROM mysql.user;"
    local cur_state=""
    local remediation="￭ 일반 사용자 계정으로부터 mysql.user 테이블의 모든 권한 제거 1\) mysql> REVOKE all ON *.* FROM '사용자 계정명'@'접속 IP'; 2\) mysql> FLUSH prvileges;"

    local output
    output=$({
        ( run_mysql_query "SELECT host, user, select_priv FROM mysql.user;" )
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
            detail="DB사용자 계정 정보 테이블의 접근 권한이"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="DB사용자 계정 정보 테이블의 접근 권한이"
        else
            status="취약"
            detail="DB사용자 계정 정보 테이블의 접근 권한이"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-MY-SQL-04" "" "사용자 계정 정보 테이블 접근 권한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-06: 환경설정 파일 접근 권한
check_CSAP_MY_SQL_06() {
    local status="양호"
    local detail=""
    local cmd="ls -alL"
    local cur_state=""
    local remediation="￭ mysql server configuration 파일 접근 권한 변경 1\) # chmod 640 [mysql server configuration 파일 위치]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${MYSQL_CONF:-/etc/my.cnf}
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "640")
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
    [ -z "$detail" ] && detail="환경설정 파일의 접근 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-MY-SQL-06" "보안 설정" "환경설정 파일 접근 권한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-08: 로그 활성화
check_CSAP_MY_SQL_08() {
    local status="양호"
    local detail=""
    local cmd="mysql> SHOW VARIABLES LIKE general_log%;; mysql> SHOW VARIABLES LIKE slow%;"
    local cur_state=""
    local remediation="￭ General log 설정 1\) # vi [mysql server configuration 파일] general_log = 1; 2\) # vi [mysql server configuration 파일] general_log_file 경로 설정 ￭ Slow log 설정 1\) # vi [mysql server configuration 파일] slow_query_log = 1; 2\) # vi [mysql server configuration 파일] slow_launch_time 설정 3\) # vi [mysql server configuration 파일] slow_query_log_file 경로 설정"

    local output
    output=$({
        ( run_mysql_query "SHOW VARIABLES LIKE 'general_log%';" )
        ( run_mysql_query "SHOW VARIABLES LIKE 'slow%';" )
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
            detail="로그 기능이 활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="로그 기능이 비활성화되어 있는 경우"
        else
            status="취약"
            detail="로그 기능이 비활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-MY-SQL-08" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MY-SQL-09: 최신 보안 패치 적용
check_CSAP_MY_SQL_09() {
    local status="양호"
    local detail=""
    local cmd="mysql> use mysql;; mysql> SELECT @@VERSION;; dpkg -l | grep -i mysql-server"
    local cur_state=""
    local remediation="￭ 데이터베이스에 대한 최신 보안 패치 버전으로 업그레이드 및 패치 수행 버그 패치 릴리즈 사이트 : http://downloads.mysql.com/archives/ 버그 현황 사이트 : http://bugs.mysql.com/bugstats.php ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( run_mysql_query "SELECT @@VERSION;" )
        ( get_process_snapshot "mysql-server" )
        ( get_process_snapshot "mysql" )
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

    add_result "CSAP-MY-SQL-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-01: 기본 계정의 비밀번호, 정책 등을 변경하여 사용
check_ISMS_D_01() {
    local status="양호"
    local detail=""
    local cmd="mysql> UPDATE user SET authentication_string = PASSWORD WHERE User = 'root';; mysql> flush privileges;; mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY ' ';"
    local cur_state=""
    local remediation="기본\(관리자\) 계정의 초기 비밀번호 및 권한 정책 변경 [상세 조치 사례] l MySQL Step 1\) root 계정 비밀번호 변경 [mysql 5.7] mysql> UPDATE user SET authentication_string = PASSWORD\('신규 비밀번호'\) WHERE User = 'root'; mysql> flush privileges; [mysql 8.0] mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY '신규 비밀번호'; User Password User Password scott tiger or tigger system manager dbsnmp dbsnmp sys changeon_install tracesvr trace outln outln ordplugins ordplugins ordsys ordsys ctxsys ctxsys mdsys mdsys adams wood blake papr clark clth jones steel lbacsys lbacsys - - mysql> flush privileges;"

    cmd="run_mysql_query \"SELECT user, host, plugin, account_locked, password_expired FROM mysql.user WHERE user = \'root\';\""
    local output
    output=$(run_mysql_query "SELECT user, host, plugin, account_locked, password_expired FROM mysql.user WHERE user = 'root';")
    cur_state="${output:-결과 없음}"
    if [ -z "$output" ]; then
        status="N/A"
        detail="root 계정 정보를 조회하지 못했습니다."
    elif printf '%s\n' "$output" | grep -Eiq "root"; then
        status="수동점검"
        detail="기본 계정(root) 상태를 수집했습니다. 잠금/비밀번호 정책 변경 여부는 운영 기준 확인이 필요합니다."
    else
        status="양호"
        detail="기본 root 계정을 조회하지 못해 기본 관리자 계정 사용 흔적이 없습니다."
    fi

    add_result "ISMS-D-01" "DBMS > 1. 계정 관리" "기본 계정의 비밀번호, 정책 등을 변경하여 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-02: 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
check_ISMS_D_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="계정별 용도를 파악한 후 불필요한 계정 삭제 [상세 조치 사례] l MySQL Step 1\) 불필요한 계정 삭제 DROP USER '삭제할 계정'@'호스트명 or IP'; FLUSH PRIVILEGES; 08. DBMS 601"

    cmd="run_mysql_query \"SELECT user, host, account_locked FROM mysql.user ORDER BY user, host;\""
    local output
    output=$(run_mysql_query "SELECT user, host, account_locked FROM mysql.user ORDER BY user, host;")
    cur_state="${output:-결과 없음}"
    if [ -z "$output" ]; then
        status="N/A"
        detail="MySQL 계정 목록을 조회하지 못했습니다."
    else
        status="수동점검"
        detail="MySQL 계정 목록과 잠금 상태를 수집했습니다. 불필요 계정 여부는 운영 목적 대조가 필요합니다."
    fi

    add_result "ISMS-D-02" "DBMS > 1. 계정 관리" "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-03: 비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정
check_ISMS_D_03() {
    local status="양호"
    local detail=""
    local cmd="mysql> SHOW VARIABLES LIKE 'validate_password%';; mysql> INSTALL COMPONENT 'file://component_validate_password';; mysql> SHOW VARIABLES LIKE 'default_password_lifetime';"
    local cur_state=""
    local remediation="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정 [상세 조치 사례] l MySQL [비밀번호 복잡도 정책 설정] Step 1\) 비밀번호 정책 확인 08. DBMS mysql> SHOW VARIABLES LIKE 'validate_password%'; ※ component_validate_password가 설치되어 있지 않은 경우 아래와 같이 해당 컴포넌트 설치 mysql> INSTALL COMPONENT 'file://component_validate_password'; Step 2\) 비밀번호 정책 설정 다음과 같은 방법으로 각각의 비밀번호 정책을 설정 SET GLOBAL validate_password.policy = 'MEDIUM'; \(비밀번호 정책의 강도 LOW/MEDIUM/STRONG\) SET GLOBAL validate_password.length = 8; \(비밀번호 최소 길이\) SET GLOBAL validate_password.mixed_case_count = 1; \(포함되어야 하는 영문 대소문자 최소 개수\) SET GLOBAL validate_password.number_count = 1; \(포함되어야 하는 숫자 최소 개수\) SET GLOBAL validate_password.special_char_count = 1; \(포함되어야 하는 특수문자 최소 개수\) ※ Linux계열\(/etc/my.cnf 또는 /etc/mysql/my.cnf\), Windows\(C:\\ProgramData\\MySQL\\MySQL Server <설치된 버전>\\my.ini\)의 <mysqld> 섹션에 설정을 추가하여 정책 설정 가능 ※ 비밀번호 신규 적용 및 초기화 시 설정 규칙에 맞추어 관리하고, 저장 시에는 일방향 암호화 알고리즘을 통해 암호화 처리\(One-Way Encryption\)함 [비밀번호 LifeTime 정책 적용 ] Step 1\) 비밀번호 정책 확인 mysql> SHOW VARIABLES LIKE 'default_password_lifetime'; Step 2\) 비밀번호 LifeTime 설정 mysql> SET GLOBAL default_password_lifetime=90; ※ 기본 값 - 5.7.11 이전 버전 : 0 - 5.7.11 이후 버전 및 8.0 이후 버전 : 360 Step 3\) 정책 적용전에 생성된 계정의 LifeTime 변경 mysql> ALTER USER <계정명>'@'<호스트명 or IP>' PASSWORD EXPIRE INTERVAL 91 DAY;"

    local output
    output=$({
        ( run_mysql_query "SHOW VARIABLES LIKE 'validate_password%';" )
        ( run_mysql_query "SHOW VARIABLES LIKE 'default_password_lifetime';" )
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
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여 [상세 조치 사례] l MySQL Step 1\) Step 1\) SUPER 권한\(관리자 권한\)이 부여되어 있는 계정 확인 SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'SUPER'; Step 2\) 불필요하게 SUPER 권한이 부여되어 있는 계정에 대해 SUPER 권한 회수 REVOKE SUPER ON *.* FROM '<계정명>'; FLUSH PRIVILEGES; ※ 만약 관리자 'test'@'localhost' 계정이 바이너리 로그 정리 및 시스템 변수 수정을 위해 SUPER 권한을 필 요로 하는 경우 아래와 같은 명령문으로 필요한 권한으로 제한. GRANT BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN ON *.* TO 'test'@'localhost'; REVOKE SUPER ON *.* FROM 'test'@'localhost'; FLUSH PRIVILEGES;"

    cmd="run_mysql_query \"SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE privilege_type IN (\'SUPER\',\'SYSTEM_USER\',\'SYSTEM_VARIABLES_ADMIN\',\'ROLE_ADMIN\',\'CREATE USER\',\'GRANT OPTION\') ORDER BY grantee, privilege_type;\""
    local output
    output=$(run_mysql_query "SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE privilege_type IN ('SUPER','SYSTEM_USER','SYSTEM_VARIABLES_ADMIN','ROLE_ADMIN','CREATE USER','GRANT OPTION') ORDER BY grantee, privilege_type;")
    cur_state="${output:-결과 없음}"
    if [ -z "$output" ]; then
        status="양호"
        detail="고위험 관리자 권한이 부여된 계정을 조회하지 못했습니다."
    else
        status="수동점검"
        detail="관리자급 권한 보유 계정을 수집했습니다. 실제 필요 계정인지 운영 정책 확인이 필요합니다."
    fi

    add_result "ISMS-D-04" "DBMS > 1. 계정 관리" "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-06: DB 사용자 계정을 개별적으로 부여하여 사용
check_ISMS_D_06() {
    local status="양호"
    local detail=""
    local cmd="mysql> DROP USER @; mysql> create user ''@'' identified by '';; mysql> grant select, insert on DB. to ''@'';"
    local cur_state=""
    local remediation="사용자별 계정 생성 및 권한 부여 [상세 조치 사례] l MySQL Step 1\) 공용용 계정 삭제 mysql> DROP USER <계정명>@<호스트명 or IP> Step 2\) 사용자별, 응용 프로그램별 계정 생성 및 권한 설정 // 사용자 계정 생성 mysql> create user '<계정명>'@'<호스트명 or IP>' identified by '비밀번호'; // 특정 데이터베이스의 특정 테이블에 select, insert 권한을 부여 mysql> grant select, insert on DB이름.테이블명 to '<계정명>'@'<호스트명 or IP>'; // 특정 데이터베이스의 모든 테이블에 모든 권한을 부여 mysql> grant all privileges on DB이름.* to '<계정명>'@'<호스트명 or IP>'; mysql> flush privileges; ※ 모든 권한을 부여할 경우, 해당 사용자는 지정된 데이터베이스에서 모든 작업의 수행이 가능하므로 사용자의 관리적 측면에서는 편리하나, 보안적 측면에서는 필요한 최소한의 권한만 부여하여 안정성을 높여야 함"

    cmd="run_mysql_query \"SELECT user, host FROM mysql.user ORDER BY user, host;\""
    local output
    output=$(run_mysql_query "SELECT user, host FROM mysql.user ORDER BY user, host;")
    cur_state="${output:-결과 없음}"
    if [ -z "$output" ]; then
        status="N/A"
        detail="MySQL 계정 정보를 조회하지 못했습니다."
    elif printf '%s\n' "$output" | awk -F"\t" 'NF>=2 && $1 != "" {count[$1]++} END {for (k in count) if (count[k] > 1) exit 0; exit 1}'; then
        status="양호"
        detail="동일 사용자명에 대해 host별 개별 계정이 사용 중입니다."
    else
        status="수동점검"
        detail="계정 목록을 수집했습니다. 공용 계정 여부는 실제 사용자 용도 대조가 필요합니다."
    fi

    add_result "ISMS-D-06" "DBMS > 1. 계정 관리" "DB 사용자 계정을 개별적으로 부여하여 사용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-10: 원격에서 DB 서버로의 접속 제한
check_ISMS_D_10() {
    local status="양호"
    local detail=""
    local cmd="mysql> UPDATE user SET host = '' WHERE user ='' and host='%';"
    local cur_state=""
    local remediation="DB 서버에 대해 지정된 IP주소에서만 접근 가능하도록 설정 [상세 조치 사례] l MySQL Step 1\) user 테이블을 조회하여 모든 클리이언트에서 접속 가능하도록 설정되어 있는 계정을 특정 IP에서만 접 속 가능하도록 변경 mysql> UPDATE user SET host = '<접속 IP>' WHERE user ='<계정명>' and host='%'; 630"

    cmd="run_mysql_query \"SELECT user, host FROM mysql.user WHERE host IN (\'%\',\'0.0.0.0\',\'::\') ORDER BY user, host;\""
    local output
    output=$(run_mysql_query "SELECT user, host FROM mysql.user WHERE host IN ('%','0.0.0.0','::') ORDER BY user, host;")
    cur_state="${output:-결과 없음}"
    if [ -z "$output" ]; then
        status="양호"
        detail="모든 원격지(%, 0.0.0.0, ::) 허용 계정을 확인하지 못했습니다."
    else
        status="취약"
        detail="모든 원격지에서 접속 가능한 MySQL 계정이 존재합니다."
    fi

    add_result "ISMS-D-10" "DBMS > 2. 접근 관리" "원격에서 DB 서버로의 접속 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-11: DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
check_ISMS_D_11() {
    local status="양호"
    local detail=""
    local cmd="SHOW GRANTS FOR ;"
    local cur_state=""
    local remediation="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정 [상세 조치 사례] l MySQL Step 1\) 사용자 계정에 부여된 권한 확인 SHOW GRANTS FOR <계정명>; Step 2\) 접근이 필요한 데이터베이스 및 테이블에만 권한 적용 GRANT <권한> privileges ON <DB명>.<테이블명> to '<계정명>'@'<호스트명 or IP>';"

    cmd="run_mysql_query \"SELECT grantee, privilege_type FROM information_schema.schema_privileges WHERE table_schema = \'mysql\' ORDER BY grantee, privilege_type;\""
    local output
    output=$(run_mysql_query "SELECT grantee, privilege_type FROM information_schema.schema_privileges WHERE table_schema = 'mysql' ORDER BY grantee, privilege_type;")
    cur_state="${output:-결과 없음}"
    if [ -z "$output" ]; then
        status="양호"
        detail="mysql 시스템 스키마에 대한 일반 권한을 조회하지 못했습니다."
    elif printf '%s\n' "$output" | grep -Eiv "^\'root\'@|mysql\.sys|mysql\.session|mysql\.infoschema" | grep -q .; then
        status="취약"
        detail="root 이외 계정에 mysql 시스템 스키마 접근 권한이 부여되어 있습니다."
    else
        status="양호"
        detail="mysql 시스템 스키마 접근 권한이 root 또는 시스템 계정으로 제한됩니다."
    fi

    add_result "ISMS-D-11" "DBMS > 2. 접근 관리" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-21: 인가되지 않은 GRANT OPTION 사용 제한
check_ISMS_D_21() {
    local status="양호"
    local detail=""
    local cmd="SELECT user, grant_priv FROM mysql.user;"
    local cur_state=""
    local remediation="WITH_GRANT_OPTION이 ROLE에 의하여 설정되도록 변경 [상세 조치 사례] l l MySQL Step 1\) 설정 확인 08. DBMS SELECT user, grant_priv FROM mysql.user; \(계정이 나오는 경우 취약\) Step 2\) 권한 회수 REVOKE <권한> ON <대상> FROM [계정명];"

    local output
    output=$({
        ( run_mysql_query "SELECT user, grant_priv FROM mysql.user;" )
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
            detail="WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="WITH_GRANT_OPTION이 ROLE에 의하여 설정되지 않은 경우"
        else
            status="취약"
            detail="WITH_GRANT_OPTION이 ROLE에 의하여 설정되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-D-21" "DBMS > 3. 옵션 관리" "인가되지 않은 GRANT OPTION 사용 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
check_ISMS_D_25() {
    local status="양호"
    local detail=""
    local cmd="mysql> SELECT VERSION\(\);"
    local cur_state=""
    local remediation="보안 패치가 적용된 버전으로 업데이트 [상세 조치 사례] l MySQL Step 1\) 시스템에서 제품 버전 현황 확인 mysql> SELECT VERSION\(\); Step 2\) MySQL 최신 버전 확인 버그 패치된 릴리즈 사이트 http://downloads.mysql.com/archives.php"

    local output
    output=$({
        ( run_mysql_query "SELECT VERSION\(\);" )
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


###############################################################################
# Execute all checks
###############################################################################

echo "===== MySQL CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/18] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-MY-SQL-05"; check_CSAP_MY_SQL_05
progress "CSAP-MY-SQL-07"; check_CSAP_MY_SQL_07
progress "CSAP-MY-SQL-01"; check_CSAP_MY_SQL_01
progress "CSAP-MY-SQL-02"; check_CSAP_MY_SQL_02
progress "CSAP-MY-SQL-03"; check_CSAP_MY_SQL_03
progress "CSAP-MY-SQL-04"; check_CSAP_MY_SQL_04
progress "CSAP-MY-SQL-06"; check_CSAP_MY_SQL_06
progress "CSAP-MY-SQL-08"; check_CSAP_MY_SQL_08
progress "CSAP-MY-SQL-09"; check_CSAP_MY_SQL_09
progress "ISMS-D-01"; check_ISMS_D_01
progress "ISMS-D-02"; check_ISMS_D_02
progress "ISMS-D-03"; check_ISMS_D_03
progress "ISMS-D-04"; check_ISMS_D_04
progress "ISMS-D-06"; check_ISMS_D_06
progress "ISMS-D-10"; check_ISMS_D_10
progress "ISMS-D-11"; check_ISMS_D_11
progress "ISMS-D-21"; check_ISMS_D_21
progress "ISMS-D-25"; check_ISMS_D_25

echo ""
echo ""

###############################################################################
# Generate JSON output
###############################################################################

# System info
SYS_HOSTNAME=$(hostname 2>/dev/null)
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
    echo '    "platform": "MySQL",'
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

echo "===== MySQL CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
