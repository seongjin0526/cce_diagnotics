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

OUTPUT_FILE="${1:-cce_check_result_mongodb_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"


TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# --- JSON helper functions ---
results=()

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

    # Escape strings for JSON
    detail=$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    command=$(echo "$command" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')

    results+=("{\"code\":\"$code\",\"category\":\"$category\",\"title\":\"$title\",\"importance\":\"$importance\",\"status\":\"$status\",\"detail\":\"$detail\",\"source\":\"$source\",\"command\":\"$command\",\"current_state\":\"$current_state\",\"remediation\":\"$remediation\"}")
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
    if [ "$owner" = "$expected_owner" ]; then
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

is_service_active() {
    local svc="$1"
    if systemctl is-active "$svc" &>/dev/null; then
        echo "active"
    elif ps -ef | grep -v grep | grep -q "$svc"; then
        echo "active"
    else
        echo "inactive"
    fi
}


# --- MongoDB helper ---
run_mongo_query() {
    local query="$1"
    local db="${2:-admin}"
    if [ -n "$DB_PASS" ] && [ -n "$DB_USER" ]; then
        mongosh --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>/dev/null ||         mongo --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>/dev/null
    else
        mongosh --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>/dev/null ||         mongo --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>/dev/null
    fi
}


# CLD-MongoDB-01: 불필요한 데이터베이스 및 테이블 제거
check_CLD_MongoDB_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 불필요한 데이터베이스 삭제 1\) > use [삭제할 DB명] 2\) > db.dropDatabase\(\); ￭ 불필요한 collection 삭제 1\) > use [삭제할 collection이 존재하는 DB명] 2\) > db.[collection명].drop\(\);"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 운영에 불필요한 데이터베이스,"
    cur_state="수동점검 필요"

    add_result "CLD-MongoDB-01" "패치 및 로그 관리" "불필요한 데이터베이스 및 테이블 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-02: 불필요한 계정 제거
check_CLD_MongoDB_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 불필요한 계정 삭제 1\) > db.dropUser\(\"계정명\"\); ※ MongoDB v2.6까지 계정 삭제 시, db.removeUser\(\) 명령어 사용"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 운영에 불필요한 계정이 존재하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MongoDB-02" "계정 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-03: 데몬 실행 시 인증 옵션 사용
check_CLD_MongoDB_03() {
    local status="양호"
    local detail=""
    local cmd="cat | grep auth"
    local cur_state=""
    local remediation="￭ 인증 옵션 사용 활성화 1\) 환경설정 파일 내 security 필드 아래 authorization 값 enabled 설정 ※ MongoDB v3.0 이하에서는 auth=true로 설정 ￭ MongoDB 재구동 \(예시\) 1\) # systemctl restart mongod ￭ 사용자 인증 확인 1\) > db.auth\(\"사용자 계정\", \"패스워드\"\);"

    local output
    output=$(cat | grep auth 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-MongoDB-03" "계정 관리" "데몬 실행 시 인증 옵션 사용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-04: 관리자 계정 생성 여부
check_CLD_MongoDB_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 관리자 계정 생성 1\) 쿼리 입력 > db.createUser\({user: \"관리자 계정명\", pwd: \"패스워드\", roles: [\"readWriteAny Database\",\"userAdminAnyDatabase\",\"dbAdminAnyDatabase\"]}\); ※ roles : superuser 권한\(root\)은 사용하지 않도록 설정"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 관리자 계정이 존재하는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MongoDB-04" "계정 관리" "관리자 계정 생성 여부" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-05: 주요 실행 및 설정 파일 권한 관리
check_CLD_MongoDB_05() {
    local status="양호"
    local detail=""
    local cmd="ls -al | grep mongo*; ls -al"
    local cur_state=""
    local remediation="￭ 실행 파일, 설정 파일 소유자 수정 및 Others 실행 권한 제거 1\) # chown dba:dba [file명] 2\) # chmod 750 [file명]"

    local output
    output=$(ls -al | grep mongo* 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-MongoDB-05" "디렉터리 및" "주요 실행 및 설정 파일 권한 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-06: http interface 접근 통제
check_CLD_MongoDB_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 인증 옵션 추가 후, 데몬 재시작 \(예시\) 1\) --auth 옵션 설정 후, mongod 데몬 재시작 # mongod—config [MongoDB 설정 파일] --auth 2\) 설정 파일 수정 # vi [MongoDB 설정 파일] authorization : enabled 설정 ※ auth=true \(일부 버전에 해당\)"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. http interface를 사용하지 않거나 해당"
    cur_state="수동점검 필요"

    add_result "CLD-MongoDB-06" "디렉터리 및" "http interface 접근 통제" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-07: 데이터베이스 접근 제한 설정
check_CLD_MongoDB_07() {
    local status="양호"
    local detail=""
    local cmd="cat | grep bind"
    local cur_state=""
    local remediation="￭ 환경 설정 파일에서 bindip 수정 1\) # vi [MongoDB 환경 설정 파일] bindIp : 인가된 IP"

    local output
    output=$(cat | grep bind 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-MongoDB-07" "디렉터리 및" "데이터베이스 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-08: 로그 기록 및 백업
check_CLD_MongoDB_08() {
    local status="양호"
    local detail=""
    local cmd="cat | grep path"
    local cur_state=""
    local remediation="￭ 정책 수립 1\) 백업 정책을 수립하여 로그 파일을 관리 2\) 주기적으로 로그 파일을 백업"

    local output
    output=$(cat | grep path 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-MongoDB-08" "패치 및 로그 관리" "로그 기록 및 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MongoDB-09: 최신 보안 패치 적용
check_CLD_MongoDB_09() {
    local status="양호"
    local detail=""
    local cmd="mongod --version; mongosh"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(mongod --version 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-MongoDB-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== MongoDB CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/9] %s 점검 중...                " "$total" "$1"
}


progress "CLD-MongoDB-01"; check_CLD_MongoDB_01
progress "CLD-MongoDB-02"; check_CLD_MongoDB_02
progress "CLD-MongoDB-03"; check_CLD_MongoDB_03
progress "CLD-MongoDB-04"; check_CLD_MongoDB_04
progress "CLD-MongoDB-05"; check_CLD_MongoDB_05
progress "CLD-MongoDB-06"; check_CLD_MongoDB_06
progress "CLD-MongoDB-07"; check_CLD_MongoDB_07
progress "CLD-MongoDB-08"; check_CLD_MongoDB_08
progress "CLD-MongoDB-09"; check_CLD_MongoDB_09

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
