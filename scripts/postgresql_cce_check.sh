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

OUTPUT_FILE="${1:-cce_check_result_postgresql_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"


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


# CLD-PostgreSQL-07 / D-08: 안전한 암호화 알고리즘 사용
check_CLD_PostgreSQL_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 명령어를 통해 안전한 암호화 알고리즘 적용 1\) user 생성 시 적용 postgres=# CREATE user 계정명 PASSWORD '설정할 패스워드'; 2\) 기존 user 적용 postgres=# AlTER user 계정명 WITH PASSWORD '설정할 패스워드'; ※ default 설정으로 SCRAM-SHA-256 암호화 알고리즘이 적용 ※ peer : 로컬에서만 연결이 가능하며 OS에서 클라이언트의 OS 사용자 이름을 얻고 요청한 데이터베이스 사용자 이름과 일치하는지 확인하는 인증 방식 [주요기반시설 가이드] SHA-256 이상의 암호화 알고리즘 적용 [상세 조치 사례] l PostgreSQL Step 1\) psql 접속 후 계정별 암호화 알고리즘 확인 postgres=# SELECT usename, passwd FROM pg_shadow; Step 2\) 명령어를 통한 알고리즘 적용 - user 생성 시 적용 postgres=# CREATE USER 계정명 password '설정할 비밀번호'; - 기존 user 적용 postgres=# ALTER USER 계정명 WITH password '설정할 비밀번호'; ※ default 설정으로 SCRAM-SHA-256 암호화 알고리즘이 적용 ※ peer : 로컬에서만 연결이 가능하며 OS에서 클라이언트의 OS 사용자 이름을 얻고 요청한 데이터베이스 사용자 이름과 일치하는지 확인하는 인증 방식 08. DBMS 625"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-PostgreSQL-07 / D-08" "보안 설정" "안전한 암호화 알고리즘 사용" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-01: 불필요한 계정 제거
check_CLD_PostgreSQL_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ NOLOGIN 설정 1\) postgres=# ALTER ROLE 계정명 WITH NOLOGIN; ￭ 불필요한 사용자 계정 제거 1\) postgres=# DROP USER 계정명;"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. DB 설치 시 Default로 생성되는 계정 및"
    cur_state="수동점검 필요"

    add_result "CLD-PostgreSQL-01" "패치 및 로그 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-02: 취약한 패스워드 사용 제한
check_CLD_PostgreSQL_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 기존 계정의 경우, ALTER 명령어를 통해 패스워드 설정 1\) postgres=# ALTER ROLE 계정명 WITH PASSWORD '설정할 비밀번호'; ￭ 새로운 계정의 경우, CREATE 명령어를 통해 패스워드 설정 2\) postgres=# create user 계정명 password '설정할 비밀번호'; ※ 패스워드 복잡도를 만족하도록 패스워드 설정 영문\(대문자, 소문자\), 숫자, 특수문자 조합 중 3가지 조합 8자리 이상 또는 2가지 조합 10자리 이상을 만족해야 함 ￭ 불필요한 사용자 계정 제거 1\) postgres=# DROP USER 계정명;"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. null인 패스워드를 사용하지 않으며 복잡도"
    cur_state="수동점검 필요"

    add_result "CLD-PostgreSQL-02" "보안 설정" "취약한 패스워드 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-03: 불필요한 권한 제거
check_CLD_PostgreSQL_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 명령어를 통해 불필요한 권한을 제거 1\) postgres=# ALTER ROLE 계정명 WITH NOSUPERUSER NOCREATEROLE; ￭ 권한 제거 확인 1\) postgres=# \\du"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Superuser, Create Role이 적절한 계정에"
    cur_state="수동점검 필요"

    add_result "CLD-PostgreSQL-03" "보안 설정" "불필요한 권한 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-04: Public schema 사용 제한
check_CLD_PostgreSQL_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 명령어를 통해 Public Schema에 public 권한 제거 \(예시\) 1\) postgres=# REVOKE all ON schema public from PUBLIC; ￭ 모든 계정 접근 제한 확인 1\) postgres=# \\dn+"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Public Schema에 소유주와 특정 계정만이"
    cur_state="수동점검 필요"

    add_result "CLD-PostgreSQL-04" "" "Public schema 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-05: IP 접근 제한 설정
check_CLD_PostgreSQL_05() {
    local status="양호"
    local detail=""
    local cmd="cat / | grep listen_address; cat / | grep -v #"
    local cur_state=""
    local remediation="￭ postgresql.conf 수정 1\) 인가된 IP 주소로 수정 \(예시\) 2\) 적용 후, PostgreSQL 재시작 # systemctl restart postgresql.service ￭ pg_hba.conf 수정 1\) 인가된 IP 주소로 수정 2\) 적용 후, PostgreSQL 재시작 # systemctl restart postgresql.service"

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
        grep_result=$(grep -i "-v #" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: -v # 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-PostgreSQL-05" "보안 설정" "IP 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-06: 안전한 인증 방식 설정
check_CLD_PostgreSQL_06() {
    local status="양호"
    local detail=""
    local cmd="cat | grep -v #"
    local cur_state=""
    local remediation="￭ pg_hba.conf 수정 1\) METHOD 필드 안전한 인증 방식으로 수정"

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
        grep_result=$(grep -i "-v #" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: -v # 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-PostgreSQL-06" "보안 설정" "안전한 인증 방식 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-08: 데이터 디렉터리 권한 설정
check_CLD_PostgreSQL_08() {
    local status="양호"
    local detail=""
    local cmd="ls -ld"
    local cur_state=""
    local remediation="￭ 명령어를 통해 접근 권한 변경 1\) # chmod 700 [PostgreSQL 데이터 디렉터리]"

    local output
    output=$(ls -ld 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-PostgreSQL-08" "" "데이터 디렉터리 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-09: 환경설정 파일 권한 설정
check_CLD_PostgreSQL_09() {
    local status="양호"
    local detail=""
    local cmd="ls -al"
    local cur_state=""
    local remediation="￭ 명령어를 통해 접근 권한 변경 1\) # chmod 600 [PostgreSQL 환경설정 파일]"

    local output
    output=$(ls -al 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-PostgreSQL-09" "" "환경설정 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-10: 로그 활성화
check_CLD_PostgreSQL_10() {
    local status="양호"
    local detail=""
    local cmd="cat | grep log_statement"
    local cur_state=""
    local remediation="￭ 명령어를 통해 접근 권한 변경 \(예시\) 1\) # chmod 600 [PostgreSQL 환경 설정 파일]"

    local output
    output=$(cat | grep log_statement 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-PostgreSQL-10" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-PostgreSQL-11: 최신 보안 패치 적용
check_CLD_PostgreSQL_11() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 보안 취약점이 존재하지 않는 버전으로 보안 패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 보안"
    cur_state="수동점검 필요"

    add_result "CLD-PostgreSQL-11" "" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# D-01: 기본 계정의 비밀번호, 정책 등을 변경하여 사용
check_D_01() {
    local status="양호"
    local detail=""
    local cmd="sudo -u postgres psql; ALTER USER postgres WITH PASSWORD ' ';"
    local cur_state=""
    local remediation="기본\(관리자\) 계정의 초기 비밀번호 및 권한 정책 변경 [상세 조치 사례] l PostgreSQL Step 1\) postgres 계정으로 접속 계정 변경 및 접속 \$ sudo –u postgres psql # ALTER USER postgres WITH PASSWORD '신규 비밀번호'; # \\q"

    local output
    output=$(sudo -u postgres psql 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "D-01" "DBMS > 1. 계정 관리" "기본 계정의 비밀번호, 정책 등을 변경하여 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-02: 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
check_D_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="계정별 용도를 파악한 후 불필요한 계정 삭제 [상세 조치 사례] l PostgreSQL Step 1\) 모든 사용자 확인 쿼리문 조회 : SELECT * FROM system_.sys_users_; 명령어 조회 : \\du Step 2\) 불필요한 계정 삭제 DROP ROLE '삭제할 계정'; 602"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 계정 정보를 확인하여 불필요한 계정이 없는 경우"
    cur_state="수동점검 필요"

    add_result "D-02" "DBMS > 1. 계정 관리" "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-03: 비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정
check_D_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정 [상세 조치 사례] l Oracle DB Step 1\) PASSWORD_LIFE_TIME Profile 파라미터 변경 SQL> ALTER PROFILE <프로파일명> LIMIT PASSWORD_LIFE_TIME xx; Step 2\) Profile 값과 관련된 사용자 변경 SQL> ALTER PROFILE <계정명> PROFILE <변경할 프로파일명>; Step 3\) 비밀번호 정책 설정 변경 SQL> ALTER PROFILE <프로파일명> LIMIT FAILED_LOGIN_ATTEMPTS 3 \(비밀번호 실패 3번 까지만 가능\) PASSWORD_LIFE_TIME 30 \(30일 동안만 비밀번호 사용 가능 PASSWORD_REUSE_TIME 30 \(사용한 비밀번호 30일 후부터 재사용 가능\) PASSWORD_VERIFY_FUNCTION verify_function \(비밀번호 복잡성 검증\) PASSWORD_GRACE_TIME 5; \(life time이 끝나고 5일 동안 메시지를 보여줌\) l MSSQL Step 1\) 비밀번호 변경 주기는 '암호 만료 강제 적용'을 적용함으로써 주기적으로 변경할 수 있으며, 변경 기간은 OS의 '암호 정책'에서 적용받으므로 '암호 정책 > 최대 암호 사용 기간' 설정도 변경해야 함 Step 2\) 암호 만료 강제 적용 보안 > 로그인 > 각 로그인 계정 > 속성 > \"암호 만료 강제 적용\" 설정 [ 암호 만료 강제 적용 설정 ] Step 3\) OS 암호 정책 설정 [관리 도구] > [로컬 보안 정책] > [보안 설정] > [계정 정책] > [암호 정책] > 최대 암호 사용 기간 : '60일' 설정 [ 최대 암호 사용 기간 설정 ] l MySQL [비밀번호 복잡도 정책 설정] Step 1\) 비밀번호 정책 확인 08. DBMS mysql> SHOW VARIABLES LIKE 'validate_password%'; ※ component_validate_password가 설치되어 있지 않은 경우 아래와 같이 해당 컴포넌트 설치 mysql> INSTALL COMPONENT 'file://component_validate_password'; Step 2\) 비밀번호 정책 설정 다음과 같은 방법으로 각각의 비밀번호 정책을 설정 SET GLOBAL validate_password.policy = 'MEDIUM'; \(비밀번호 정책의 강도 LOW/MEDIUM/STRONG\) SET GLOBAL validate_password.length = 8; \(비밀번호 최소 길이\) SET GLOBAL validate_password.mixed_case_count = 1; \(포함되어야 하는 영문 대소문자 최소 개수\) SET GLOBAL validate_password.number_count = 1; \(포함되어야 하는 숫자 최소 개수\) SET GLOBAL validate_password.special_char_count = 1; \(포함되어야 하는 특수문자 최소 개수\) ※ Linux계열\(/etc/my.cnf 또는 /etc/mysql/my.cnf\), Windows\(C:\\ProgramData\\MySQL\\MySQL Server <설치된 버전>\\my.ini\)의 <mysqld> 섹션에 설정을 추가하여 정책 설정 가능 ※ 비밀번호 신규 적용 및 초기화 시 설정 규칙에 맞추어 관리하고, 저장 시에는 일방향 암호화 알고리즘을 통해 암호화 처리\(One-Way Encryption\)함 [비밀번호 LifeTime 정책 적용 ] Step 1\) 비밀번호 정책 확인 mysql> SHOW VARIABLES LIKE 'default_password_lifetime'; Step 2\) 비밀번호 LifeTime 설정 mysql> SET GLOBAL default_password_lifetime=90; ※ 기본 값 - 5.7.11 이전 버전 : 0 - 5.7.11 이후 버전 및 8.0 이후 버전 : 360 Step 3\) 정책 적용전에 생성된 계정의 LifeTime 변경 mysql> ALTER USER <계정명>'@'<호스트명 or IP>' PASSWORD EXPIRE INTERVAL 91 DAY; l Altibase Step 1\) 다음 명령어를 통해 비밀번호 정책 설정 여부 확인 SELECT * FROM system_.sys_users_; Step 2\) 아래 Property에 대해 비밀번호 정책 설정 CASE_SENSITIVE_PASSWORD = 1 FAILED_LOGIN_ATTEMPTS PASSWORD_LOCK_TIME PASSWORD_LIFE_TIME PASSWORD_GRACE_TIME PASSWORD_REUSE_TIME PASSWORD_REUSE_MAX PASSWORD_VERIFY_FUNCTION 정책 적용 시 다음 명령어를 사용 ALTER USER 계정명 LIMIT \(Property 숫자\); 예시\) ALTER USER TESTUSER LIMIT \(FAILED_LOGIN_ATTEMPTS 7, PASSWORD_LOCK_TIM E 7\); l Tibero Step 1\) 사용자별 비밀번호 PROFILE 적용 여부 확인 비밀번호 설정 규칙에 맞추어 비밀번호를 설정할 수 있도록 시스템 차원에서 기능 제공 SELECT * FROM dba_users; [ 사용자별 비밀번호 PROFILE 적용 여부 확인 ] Step 2\) 설정되어 있을 경우 PROFILE 설정 내용 확인 SELECT * FROM dba_profiles; 08. DBMS [ PROFILE 설정 내용 확인 ] Step 3\) 설정되어 있지 않을 경우 PROFILE 생성 또는 수정 시\(ALTER PROFILE\) 비밀번호 정책 설정 적용 시 다음 명령어를 사용 CREATE PROFILE prof LIMIT 예시\) CREATE PROFILE prof LIMIT failed_login_attempts 3 password_lock_time 1/1440 password_life_time 90 password_reuse_time unlimited password_reuse_max 10 password_grace_time 10 password_verify_function verify_function; 608"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "D-03" "DBMS > 1. 계정 관리" "비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-04: 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
check_D_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여 [상세 조치 사례] l PostgreSQL Step 1\) 계정의 용도 파악 후 불필요한 계정은 삭제, 새로운 계정 생성 시 적절한 권한을 부여하여 생성 모든 사용자 확인 쿼리문 조회 : SELECT * FROM pg_user; or SELECT username, usesuper FROM pg_shadow; 명령어 조회 : \\du Step 2\) 불필요하게 관리자 권한이 부여된 경우 권한 회수 ALTER ROLE <계정명> NOSUPERUSER; ALTER ROLE <계정명> NOCREATEROLE; ALTER ROLE <계정명> NOCREATEDB; ALTER ROLE <계정명> NOREPLICATION; ALTER ROLE <계정명> NOBYPASSRLS; Step 3\) 612"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
    cur_state="수동점검 필요"

    add_result "D-04" "DBMS > 1. 계정 관리" "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-06: DB 사용자 계정을 개별적으로 부여하여 사용
check_D_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="사용자별 계정 생성 및 권한 부여 [상세 조치 사례] l PostgreSQL Step 1\) 모든 사용자 확인 쿼리문 조회 : SELECT * FROM pg_shadow; 명령어 조회 : \\du Step 2\) 불필요 계정 삭제 DROP ROLE '삭제할 계정'; Step 3\) 계정 생성 및 권한 추가 CREATE USER '생성할 계정'; ALTER ROLE '계정명' '권한명' '권한명' ····; \\du \(계정 생성 및 권한 확인\) ※ 계정의 용도 파악 후 불필요한 계정은 삭제, 새로운 계정 생성 시 적절한 권한을 부여하여 생성 08. DBMS 619"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 사용자별 계정을 사용하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-06" "DBMS > 1. 계정 관리" "DB 사용자 계정을 개별적으로 부여하여 사용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-10: 원격에서 DB 서버로의 접속 제한
check_D_10() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="DB 서버에 대해 지정된 IP주소에서만 접근 가능하도록 설정 [상세 조치 사례] l PostgreSQL Step 1\) Data 디렉터리 내에 postgres.conf 파일 설정 [ postgres.conf 파일 ] ※ listen_addresses는 서버가 클라이언트 애플리케이션의 연결을 수신 대기할 TCP/IP 주소를 지정함. 호 스트 이름 및/또는 숫자 IP 주소의 쉼표로 구분된 목록 형식으로 지정할 수 있으며, *를 사용하는 경우 모든 IP에 대해 수신 대기함. 기본값은 localhost 이며 로컬 TCP/IP \"루프백\" 연결 만 허용 Step 2\) Data 디렉터리 내에 pg_hba.conf 파일 설정 TYPE DATABASE USER CIDR-ADDRESS METHOD -------- ----------------- --------- ------------------------- ---------------- host \(DB명\) \(사용자\) \(접속 허용 IP\) md5 08. DBMS [ pg_hba.conf 파일 ] Step 3\) USER에 접근 허용 '계정명'과 CIDR-ADDRESS에 접속을 '허용할 IP' 설정 ※ PostgreSQL은 기본 설치 시 외부에서 접속할 수 없음 ※ IP 접근 제한 설정 시 postgresql.conf와 pg_hba.conf 두 개의 설정 파일이 연계되어 있으므로 하나의 파일이라 도 설정이 잘못되어 있는 경우 DB 접속이 불가능 할 수 있음. 632"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
    cur_state="수동점검 필요"

    add_result "D-10" "DBMS > 2. 접근 관리" "원격에서 DB 서버로의 접속 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-11: DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
check_D_11() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정 [상세 조치 사례] l PostgreSQL Step 1\) 사용자 및 역할 권한 정보 조회 SELECT * FROM information_schema.role_table_grants; Step 2\) 스키마명에 해당되는 Table에 대한 접근 권한을 일반 사용자로부터 제거 REVOKE [all,select,insert,update...] ON all tables IN schema '스키마명' FROM '계정명'; 08. DBMS 635"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-11" "DBMS > 2. 접근 관리" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-14: 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
check_D_14() {
    local status="양호"
    local detail=""
    local cmd="chmod 640 /postgresql.conf; chmod 640 ./pg_hba.conf; chmod 640 ./pg_ident.conf"
    local cur_state=""
    local remediation="주요 설정 파일 및 디렉터리의 권한 설정 변경 [상세 조치 사례] l PostgreSQL [Unix OS] Step 1\) 주요 설정 파일 위치 확인 postgresql.conf 파일 위치: [\$datadir] DB 접속 통제 설정 파일 위치: /postgres/data/pg_hba.conf, /postgres/data/pg_ident.conf log_directory : /log_directory/pg_log Step 2\) 주요 설정 파일의 권한 설정 환경설정 파일\(postgresql.conf\)의 권한을 640 이하로 설정 # chmod 640 [\$datadir]/postgresql.conf DB접속 통제 설정 파일\(pg_hba.conf, pg_ident.conf\)의 권한을 640 이하로 설정 # chmod 640 ./pg_hba.conf # chmod 640 ./pg_ident.conf 히스토리 파일 \(.psql_history\)의 권한을 600 이하로 설정 \$chmod 600 .psql_history Log 파일\(pg_log\)의 권한을 640 이하로 설정 #chmod 640 [Log 파일] [Windows OS] Step 1\) 주요 환경설정 파일의 접근 권한은 Administrators, SYSTEM, Owner에게 모든 권한 또는 필요 권한만 부여하여 설정하고 기타 다른 그룹은 권한 제거"

    local vuln_found=false
    if [ -e "/postgresql.conf" ]; then
        local result_postgresql_conf
        result_postgresql_conf=$(check_file_owner_perm "/postgresql.conf" "root" "644")
        cur_state+="/postgresql.conf: $result_postgresql_conf; "
        case "$result_postgresql_conf" in
            VULN*) vuln_found=true; detail+="/postgresql.conf 소유자/권한 부적절($result_postgresql_conf). " ;;
            GOOD*) detail+="/postgresql.conf 소유자/권한 적절($result_postgresql_conf). " ;;
            NOT_FOUND) detail+="/postgresql.conf 파일 없음. " ;;
        esac
    else
        detail+="/postgresql.conf 파일 없음. "
        cur_state+="/postgresql.conf: 파일 없음; "
    fi
    if [ -e "/pg_hba.conf" ]; then
        local result_pg_hba_conf
        result_pg_hba_conf=$(check_file_owner_perm "/pg_hba.conf" "root" "644")
        cur_state+="/pg_hba.conf: $result_pg_hba_conf; "
        case "$result_pg_hba_conf" in
            VULN*) vuln_found=true; detail+="/pg_hba.conf 소유자/권한 부적절($result_pg_hba_conf). " ;;
            GOOD*) detail+="/pg_hba.conf 소유자/권한 적절($result_pg_hba_conf). " ;;
            NOT_FOUND) detail+="/pg_hba.conf 파일 없음. " ;;
        esac
    else
        detail+="/pg_hba.conf 파일 없음. "
        cur_state+="/pg_hba.conf: 파일 없음; "
    fi
    if [ -e "/pg_ident.conf" ]; then
        local result_pg_ident_conf
        result_pg_ident_conf=$(check_file_owner_perm "/pg_ident.conf" "root" "644")
        cur_state+="/pg_ident.conf: $result_pg_ident_conf; "
        case "$result_pg_ident_conf" in
            VULN*) vuln_found=true; detail+="/pg_ident.conf 소유자/권한 부적절($result_pg_ident_conf). " ;;
            GOOD*) detail+="/pg_ident.conf 소유자/권한 적절($result_pg_ident_conf). " ;;
            NOT_FOUND) detail+="/pg_ident.conf 파일 없음. " ;;
        esac
    else
        detail+="/pg_ident.conf 파일 없음. "
        cur_state+="/pg_ident.conf: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우" && cur_state="점검 대상 파일 없음"

    add_result "D-14" "DBMS > 2. 접근 관리" "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-20: 인가되지 않은 Object Owner의 제한
check_D_20() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정 [상세 조치 사례] l PostgreSQL Step 1\) Object 권한 정보 확인 postgres=# SELECT DISTINCT relowner FROM pg_class WHERE relowner NOT IN \(SELECT usesysid FROM pg_user WHERE usesuper = TRUE\); Step 2\) 잘못된 Object 권한 소유자 발견 시 권한 회수 654"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
    cur_state="수동점검 필요"

    add_result "D-20" "DBMS > 3. 옵션 관리" "인가되지 않은 Object Owner의 제한" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
check_D_25() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="보안 패치가 적용된 버전으로 업데이트 [상세 조치 사례] l PostgreSQL Step 1\) 시스템에서 제품 버전 현황 확인 SELECT VERSION\(\); Step 2\) PostgreSQL 최신 버전 확인 08. DBMS http://www.postgresql.org/support/security"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 보안 패치가 적용된 버전을 사용하는 경우"
    cur_state="수동점검 필요"

    add_result "D-25" "DBMS > 4. 패치 관리" "주기적 보안 패치 및 벤더 권고 사항 적용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-26: 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
check_D_26() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="DBMS에 대한 감사 로그 저장 정책 수립, 적용 [상세 조치 사례] l PostgreSQL Step 1\) Log 감사 설정 여부 확인 postgres=# SHOW logging_collector; logging_collector ------------------- on \(1 row\) Step 2\) postgresql.conf 파일 내 logging_collector을 on으로설정 logging_collector = on"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "D-26" "DBMS > 4. 패치 관리" "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== PostgreSQL CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/22] %s 점검 중...                " "$total" "$1"
}


progress "CLD-PostgreSQL-07"; check_CLD_PostgreSQL_07
progress "CLD-PostgreSQL-01"; check_CLD_PostgreSQL_01
progress "CLD-PostgreSQL-02"; check_CLD_PostgreSQL_02
progress "CLD-PostgreSQL-03"; check_CLD_PostgreSQL_03
progress "CLD-PostgreSQL-04"; check_CLD_PostgreSQL_04
progress "CLD-PostgreSQL-05"; check_CLD_PostgreSQL_05
progress "CLD-PostgreSQL-06"; check_CLD_PostgreSQL_06
progress "CLD-PostgreSQL-08"; check_CLD_PostgreSQL_08
progress "CLD-PostgreSQL-09"; check_CLD_PostgreSQL_09
progress "CLD-PostgreSQL-10"; check_CLD_PostgreSQL_10
progress "CLD-PostgreSQL-11"; check_CLD_PostgreSQL_11
progress "D-01"; check_D_01
progress "D-02"; check_D_02
progress "D-03"; check_D_03
progress "D-04"; check_D_04
progress "D-06"; check_D_06
progress "D-10"; check_D_10
progress "D-11"; check_D_11
progress "D-14"; check_D_14
progress "D-20"; check_D_20
progress "D-25"; check_D_25
progress "D-26"; check_D_26

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
