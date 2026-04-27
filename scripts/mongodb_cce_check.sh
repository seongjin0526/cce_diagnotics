#!/bin/bash
###############################################################################
# MongoDB CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash mongodb_cce_check.sh -h <host> -P <port> -u <user> -p <password> [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

# Database connection parameters
DB_HOST="localhost"
DB_PORT="27017"
DB_USER=""
DB_PASS=""

usage() {
    echo "Usage: sudo bash mongodb_cce_check.sh [-h host] [-P port] [-u user] [-p password] [output_file.json]"
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
OUTPUT_FILE="${1:-cce_check_result_mongodb_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"


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


# --- MongoDB helper ---
run_mongo_query() {
    local query="$1"
    local db="${2:-admin}"
    local output=""
    local rc=0
    local mongo_bin=""
    if [ -n "$DB_PASS" ] && [ -n "$DB_USER" ]; then
        output=$(mongosh --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ]; then
            mongo_bin=$(command -v mongo 2>/dev/null || true)
        fi
        if [ "$rc" -ne 0 ] && [ -n "$mongo_bin" ]; then
            output=$(mongo --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>&1)
            rc=$?
        fi
    else
        output=$(mongosh --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ]; then
            mongo_bin=$(command -v mongo 2>/dev/null || true)
        fi
        if [ "$rc" -ne 0 ] && [ -n "$mongo_bin" ]; then
            output=$(mongo --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>&1)
            rc=$?
        fi
    fi
    printf '%s' "$output"
}


# --- Pre-flight: MongoDB 설치 확인 및 경로 탐지 ---
MONGO_BIN=""
MONGOD_CONF="${MONGOD_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    MONGO_BIN=$(command -v mongosh 2>/dev/null)
    if [ -z "$MONGO_BIN" ]; then
        MONGO_BIN=$(command -v mongo 2>/dev/null)
    fi
    local mongod_bin
    mongod_bin=$(command -v mongod 2>/dev/null)

    # 2) 프로세스에서 --config 추출
    local mongod_proc
    mongod_proc=$(ps -ef 2>/dev/null | grep '[m]ongod' | grep -v mongos | head -1)
    if [ -n "$mongod_proc" ]; then
        APP_FOUND="true"
        local conf_from_proc
        conf_from_proc=$(echo "$mongod_proc" | sed -n 's/.*--config[= ]\([^ ]*\).*/\1/p')
        if [ -n "$conf_from_proc" ] && [ -f "$conf_from_proc" ]; then
            MONGOD_CONF="$conf_from_proc"
        fi
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$MONGOD_CONF" ]; then
        for f in /etc/mongod.conf /etc/mongodb.conf /usr/local/etc/mongod.conf; do
            if [ -f "$f" ]; then
                MONGOD_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$MONGO_BIN" ] && [ -z "$mongod_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'mongodb\|mongod' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'mongodb\|mongod' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$MONGO_BIN" ] || [ -n "$mongod_bin" ] || [ -n "$MONGOD_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] MongoDB 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-MongoDB-01: 불필요한 데이터베이스 및 테이블 제거
check_CSAP_MongoDB_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 불필요한 데이터베이스 삭제 1) > use [삭제할 DB명] 2) > db.dropDatabase(); ￭ 불필요한 collection 삭제 1) > use [삭제할 collection이 존재하는 DB명] 2) > db.[collection명].drop();"

    cmd="run_mongo_query \"db.adminCommand({listDatabases:1})\" admin; run_mongo_query \"db.getSiblingDB(...).getCollectionNames()\" admin"
    local dbs_output
    local collections_output
    dbs_output=$(run_mongo_query 'db.adminCommand({listDatabases:1}).databases.map(function(x){return x.name;}).join("\n")' admin)
    collections_output=$(run_mongo_query 'db.adminCommand({listDatabases:1}).databases.filter(function(x){ return ["admin","config","local"].indexOf(x.name) === -1; }).map(function(x){ var cols = db.getSiblingDB(x.name).getCollectionNames(); return x.name + ": " + (cols.length ? cols.join(", ") : "(no collections)"); }).join("\n")' admin)
    cur_state="DBS: ${dbs_output:-조회 실패 또는 결과 없음}"
    if [ -n "$collections_output" ]; then
        cur_state="${cur_state} | COLLECTIONS: $collections_output"
    fi
    detail="데이터베이스/컬렉션 목록을 수집했습니다. 운영상 불필요 여부는 수동 확인이 필요합니다."
    status="수동점검"

    add_result "CSAP-MongoDB-01" "패치 및 로그 관리" "불필요한 데이터베이스 및 테이블 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-02: 불필요한 계정 제거
check_CSAP_MongoDB_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 불필요한 계정 삭제 1) > db.dropUser(\"계정명\"); ※ MongoDB v2.6까지 계정 삭제 시, db.removeUser() 명령어 사용"

    cmd="run_mongo_query \"db.getSiblingDB(\'admin\').runCommand({usersInfo:1})\" admin"
    local users_output
    users_output=$(run_mongo_query 'var users = db.getSiblingDB("admin").runCommand({usersInfo:1}).users || []; users.map(function(u){ return u.user + " => " + (u.roles || []).map(function(r){ return r.role + "@" + r.db; }).join(", "); }).join("\n")' admin)
    cur_state="${users_output:-결과 없음}"
    detail="MongoDB 계정 목록을 수집했습니다. 불필요 계정 여부는 수동 확인이 필요합니다."
    status="수동점검"

    add_result "CSAP-MongoDB-02" "계정 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-03: 데몬 실행 시 인증 옵션 사용
check_CSAP_MongoDB_03() {
    local status="양호"
    local detail=""
    local cmd="cat [MongoDB 환경설정 파일] | grep auth (예시)"
    local cur_state=""
    local remediation="￭ 인증 옵션 사용 활성화 1) 환경설정 파일 내 security 필드 아래 authorization 값 enabled 설정 ※ MongoDB v3.0 이하에서는 auth=true로 설정 ￭ MongoDB 재구동 (예시) 1) # systemctl restart mongod ￭ 사용자 인증 확인 1) > db.auth(\"사용자 계정\", \"패스워드\");"

    local config_output
    local active_auth
    if [ -n "$MONGOD_CONF" ] && [ -f "$MONGOD_CONF" ]; then
        config_output=$(grep -Ein "authorization|auth" "$MONGOD_CONF" 2>/dev/null | head -20)
        active_auth=$(grep -Ei "^[[:space:]]*authorization[[:space:]]*:[[:space:]]*enabled|^[[:space:]]*auth[[:space:]]*=[[:space:]]*true" "$MONGOD_CONF" 2>/dev/null | head -5)
        cur_state="${config_output:-설정 파일에서 관련 항목을 찾지 못함}"
        if [ -n "$active_auth" ]; then
            detail="mongod 환경설정 파일에 인증 옵션이 활성화되어 있습니다."
            status="양호"
        else
            detail="mongod 환경설정 파일에서 인증 옵션 활성화를 확인하지 못했습니다."
            status="취약"
        fi
    else
        cur_state="MongoDB 설정 파일 없음"
        detail="해당 파일이 없으므로 취약 - MongoDB 기본값은 인증 비활성입니다."
        status="취약"
    fi

    add_result "CSAP-MongoDB-03" "계정 관리" "데몬 실행 시 인증 옵션 사용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-04: 관리자 계정 생성 여부
check_CSAP_MongoDB_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 관리자 계정 생성 1) 쿼리 입력 > db.createUser({user: \"관리자 계정명\", pwd: \"패스워드\", roles: [\"readWriteAny Database\",\"userAdminAnyDatabase\",\"dbAdminAnyDatabase\"]}); ※ roles : superuser 권한(root)은 사용하지 않도록 설정"

    cmd="run_mongo_query \"db.getSiblingDB(\'admin\').runCommand({usersInfo:1})\" admin"
    local admin_users_output
    admin_users_output=$(run_mongo_query 'var users = db.getSiblingDB("admin").runCommand({usersInfo:1}).users || []; users.filter(function(u){ return (u.roles || []).some(function(r){ return ["root","userAdminAnyDatabase","dbAdminAnyDatabase","readWriteAnyDatabase","userAdmin","dbAdmin"].indexOf(r.role) !== -1; }); }).map(function(u){ return u.user + " => " + (u.roles || []).map(function(r){ return r.role + "@" + r.db; }).join(", "); }).join("\n")' admin)
    cur_state="${admin_users_output:-결과 없음}"
    if [ -n "$admin_users_output" ]; then
        detail="관리자 권한 계정을 확인했습니다."
        status="양호"
    else
        detail="관리자 권한 계정을 확인하지 못했습니다."
        status="취약"
    fi

    add_result "CSAP-MongoDB-04" "계정 관리" "관리자 계정 생성 여부" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-05: 주요 실행 및 설정 파일 권한 관리
check_CSAP_MongoDB_05() {
    local status="양호"
    local detail=""
    local cmd="ls -al [MongoDB 실행 파일] | grep \"mongo*\"; ls -al [MongoDB 설정 파일]"
    local cur_state=""
    local remediation="￭ 실행 파일, 설정 파일 소유자 수정 및 Others 실행 권한 제거 1) # chown dba:dba [file명] 2) # chmod 750 [file명]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/mongod.conf
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "dba" "750")
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
    target_spec_2=$(command -v mongod 2>/dev/null)
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "dba" "750")
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
    target_spec_3=${MONGOD_CONF:-/etc/mongod.conf}
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "dba" "750")
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="실행 파일 및 설정 파일의 소유자 및 그룹이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-MongoDB-05" "디렉터리 및" "주요 실행 및 설정 파일 권한 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-06: http interface 접근 통제
check_CSAP_MongoDB_06() {
    local status="양호"
    local detail=""
    local cmd="run_mongo_query 'db.adminCommand({getCmdLineOpts:1})' admin; cfg=\${MONGOD_CONF:-/etc/mongod.conf}; if [ -f \"\$cfg\" ]; then out=\$(grep -Ein \"http|rest|bindIp|bindIpAll\" \"\$cfg\" 2>/dev/null | head -20); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"SETTING_DEFAULT_GOOD|MongoDB 7 기본값은 HTTP interface 미사용입니다.\"; fi; else echo \"FILE_DEFAULT_GOOD|MongoDB 7 기본값은 HTTP interface 미사용입니다.\"; fi"
    local cur_state=""
    local remediation="￭ 인증 옵션 추가 후, 데몬 재시작 (예시) 1) --auth 옵션 설정 후, mongod 데몬 재시작 # mongod—config [MongoDB 설정 파일] --auth 2) 설정 파일 수정 # vi [MongoDB 설정 파일] authorization : enabled 설정 ※ auth=true (일부 버전에 해당)"

    cmd="run_mongo_query \"db.adminCommand({getCmdLineOpts:1})\" admin; grep -En \"http|rest\" ${MONGOD_CONF:-/etc/mongod.conf}"
    local output
    output=$({ ( run_mongo_query 'db.adminCommand({getCmdLineOpts:1})' admin ); ( cfg="${MONGOD_CONF:-/etc/mongod.conf}"; [ -f "$cfg" ] && grep -Ein "http|rest" "$cfg" 2>/dev/null || echo "FILE_DEFAULT_GOOD|MongoDB 7 기본값은 HTTP interface 미사용입니다." ); } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="${output:-결과 없음}"
    if printf '%s\n' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then
        status="양호"
        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - MongoDB 7 기본값은 HTTP interface 미사용입니다."
    elif printf '%s\n' "$output" | grep -Eiq "rest|http"; then
        status="취약"
        detail="MongoDB HTTP interface 관련 설정이 확인되었습니다."
    else
        status="양호"
        detail="MongoDB HTTP interface 관련 설정을 확인하지 못했습니다."
    fi

    add_result "CSAP-MongoDB-06" "디렉터리 및" "http interface 접근 통제" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-07: 데이터베이스 접근 제한 설정
check_CSAP_MongoDB_07() {
    local status="양호"
    local detail=""
    local cmd="cat [MongoDB 환경 설정 파일] | grep bind"
    local cur_state=""
    local remediation="￭ 환경 설정 파일에서 bindip 수정 1) # vi [MongoDB 환경 설정 파일] bindIp : 인가된 IP"

    local bind_output
    if [ -n "$MONGOD_CONF" ] && [ -f "$MONGOD_CONF" ]; then
        bind_output=$(grep -Ein "bindIp|bindIpAll" "$MONGOD_CONF" 2>/dev/null | head -20)
        cur_state="${bind_output:-설정 파일에서 관련 항목을 찾지 못함}"
        if echo "$bind_output" | grep -Eiq "bindIpAll[[:space:]]*:[[:space:]]*true|0\.0\.0\.0"; then
            detail="MongoDB가 전체 인터페이스에 바인드되어 있습니다."
            status="취약"
        elif [ -n "$bind_output" ]; then
            detail="MongoDB 접근 제한 관련 설정을 수집했습니다."
            status="양호"
        else
            detail="MongoDB 접근 제한 관련 설정을 찾지 못했습니다."
            status="취약"
        fi
    else
        cur_state="MongoDB 설정 파일 없음"
        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - MongoDB 기본 bindIp는 127.0.0.1 입니다."
        status="양호"
    fi

    add_result "CSAP-MongoDB-07" "디렉터리 및" "데이터베이스 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-08: 로그 기록 및 백업
check_CSAP_MongoDB_08() {
    local status="양호"
    local detail=""
    local cmd="cat [MongoDB 환경 설정 파일] | grep path"
    local cur_state=""
    local remediation="￭ 정책 수립 1) 백업 정책을 수립하여 로그 파일을 관리 2) 주기적으로 로그 파일을 백업"

    local log_output
    if [ -n "$MONGOD_CONF" ] && [ -f "$MONGOD_CONF" ]; then
        log_output=$(grep -Ein "systemLog|path|destination" "$MONGOD_CONF" 2>/dev/null | head -20)
        cur_state="${log_output:-설정 파일에서 관련 항목을 찾지 못함}"
        detail="MongoDB 로그 설정 관련 값을 수집했습니다. 백업 정책 충족 여부는 수동 확인이 필요합니다."
        status="수동점검"
    else
        cur_state="MongoDB 설정 파일 없음"
        detail="해당 파일이 없으므로 취약 - 기본 로그 설정 및 백업 경로를 확인할 수 없습니다."
        status="취약"
    fi

    add_result "CSAP-MongoDB-08" "패치 및 로그 관리" "로그 기록 및 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-MongoDB-09: 최신 보안 패치 적용
check_CSAP_MongoDB_09() {
    local status="양호"
    local detail=""
    local cmd="mongod --version; mongosh"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( mongod --version )
        ( mongosh )
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

    add_result "CSAP-MongoDB-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== MongoDB CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/9] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-MongoDB-01"; check_CSAP_MongoDB_01
progress "CSAP-MongoDB-02"; check_CSAP_MongoDB_02
progress "CSAP-MongoDB-03"; check_CSAP_MongoDB_03
progress "CSAP-MongoDB-04"; check_CSAP_MongoDB_04
progress "CSAP-MongoDB-05"; check_CSAP_MongoDB_05
progress "CSAP-MongoDB-06"; check_CSAP_MongoDB_06
progress "CSAP-MongoDB-07"; check_CSAP_MongoDB_07
progress "CSAP-MongoDB-08"; check_CSAP_MongoDB_08
progress "CSAP-MongoDB-09"; check_CSAP_MongoDB_09

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
    echo '    "platform": "MongoDB",'
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

echo "===== MongoDB CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
