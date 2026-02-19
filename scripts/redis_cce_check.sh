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

OUTPUT_FILE="${1:-cce_check_result_redis_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"


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
REDIS_CONF=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    REDIS_CLI=$(command -v redis-cli 2>/dev/null)
    local redis_server_bin
    redis_server_bin=$(command -v redis-server 2>/dev/null)

    # 2) 프로세스에서 config 경로 추출
    local redis_proc
    redis_proc=$(ps -ef 2>/dev/null | grep '[r]edis-server' | head -1)
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
        for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf /usr/local/etc/redis.conf; do
            if [ -f "$f" ]; then
                REDIS_CONF="$f"
                break
            fi
        done
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


# CLD-Redis-01: Redis 인증 패스워드 설정
check_CLD_Redis_01() {
    local status="양호"
    local detail=""
    local cmd="cat | grep -i requirepass"
    local cur_state=""
    local remediation="￭ redis.conf 파일 안의 requirepass 설정 1\) # vi /etc/redis/redis.conf 2\) requirepass 값 설정 3\) 인증 로그인 확인"

    local config_file="/etc/app/config"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "requirepass" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: requirepass 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Redis-01" "패치 및 로그 관리" "Redis 인증 패스워드 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-02: Binding 설정
check_CLD_Redis_02() {
    local status="양호"
    local detail=""
    local cmd="cat [redis /redis.conf | grep -i bind"
    local cur_state=""
    local remediation="￭ redis.conf 파일 안의 bind 설정 1\) # vi [redis 디렉터리/redis.conf] \(인가된 IP만 접근 가능하도록 설정\)"

    local config_file="/redis.conf"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "bind" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: bind 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Redis-02" "보안 설정" "Binding 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-03: Slave 읽기 모드 전용 모드 설정
check_CLD_Redis_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ redis.conf 파일 내 replica-read-only 설정 1\) # vi [redis 디렉터리]/redis.conf replica-read-only를 yes로 변경"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Slave에 읽기 권한만 설정되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-Redis-03" "" "Slave 읽기 모드 전용 모드 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-04: rename-command 설정
check_CLD_Redis_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ redis.conf 파일 안의 rename-command CONFIG 설정 1\) # vi [redis 디렉터리]/redis.conf rename-command CONFIG \"\" 주석 처리 해제"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. rename-command CONFIG를 빈칸으로"
    cur_state="수동점검 필요"

    add_result "CLD-Redis-04" "보안 설정" "rename-command 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-05: 데이터 디렉터리 접근 권한 설정
check_CLD_Redis_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ redis 데이터 디렉터리 접근 권한 750으로 설정 1\) # chmod 750 [redis 데이터 디렉터리]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 데이터 디렉토리의 접근 권한이"
    cur_state="수동점검 필요"

    add_result "CLD-Redis-05" "" "데이터 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-06: 설정 파일 접근권한 설정
check_CLD_Redis_06() {
    local status="양호"
    local detail=""
    local cmd="ls -al /redis.conf"
    local cur_state=""
    local remediation="￭ redis.conf 파일의 권한을 600 이하로 설정 1\) # chmod 600 [redis 데이터디렉터리]/redis.conf"

    local output
    output=$(ls -al /redis.conf 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Redis-06" "디렉터리 및 파일권한 관리" "설정 파일 접근권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-07: 로그 활성화
check_CLD_Redis_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ slow query 로그 설정 1\) 127.0.0.1:6379> config set slowlog-log-slower-than 100 ￭ slow query 로그 설정 1\) # vi /etc/[redis 디렉터리]/redis.conf 파일 안의 loglevel notice로 변경 ※ default 설정 : notice"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그가 활성화되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-Redis-07" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Redis-08: 최신 보안 패치 적용
check_CLD_Redis_08() {
    local status="양호"
    local detail=""
    local cmd="redis-cli -h 127.0.0.1 -p 6379; /redis-cli -v"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 취약점이 없는 보안 패치가 적용된 버전으로 업데이트해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(redis-cli -h 127.0.0.1 -p 6379 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Redis-08" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Redis CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/8] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Redis-01"; check_CLD_Redis_01
progress "CLD-Redis-02"; check_CLD_Redis_02
progress "CLD-Redis-03"; check_CLD_Redis_03
progress "CLD-Redis-04"; check_CLD_Redis_04
progress "CLD-Redis-05"; check_CLD_Redis_05
progress "CLD-Redis-06"; check_CLD_Redis_06
progress "CLD-Redis-07"; check_CLD_Redis_07
progress "CLD-Redis-08"; check_CLD_Redis_08

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
