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


# --- MySQL helper ---
run_mysql_query() {
    local query="$1"
    if [ -n "$DB_PASS" ]; then
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" -N -e "$query" 2>/dev/null
    else
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -N -e "$query" 2>/dev/null
    fi
}


# --- Pre-flight: MySQL 설치 확인 및 경로 탐지 ---
MYSQL_BIN=""
MYSQLD_BIN=""
MYSQL_CONF=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    MYSQL_BIN=$(command -v mysql 2>/dev/null)
    MYSQLD_BIN=$(command -v mysqld 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$MYSQLD_BIN" ]; then
        MYSQLD_BIN=$(ps -ef 2>/dev/null | grep '[m]ysqld' | awk '{for(i=1;i<=NF;i++) if($i ~ /mysqld$/) print $i}' | head -1)
    fi

    # 프로세스에서 --defaults-file 추출
    local defaults_file
    defaults_file=$(ps -ef 2>/dev/null | grep '[m]ysqld' | sed -n 's/.*--defaults-file=\([^ ]*\).*/\1/p' | head -1)
    if [ -n "$defaults_file" ] && [ -f "$defaults_file" ]; then
        MYSQL_CONF="$defaults_file"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$MYSQL_CONF" ]; then
        for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf ~/.my.cnf /usr/local/mysql/my.cnf; do
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


# CLD-MY-SQL-05 / D-07: root 권한으로 서버 구동 제한
check_CLD_MY_SQL_05() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep mysqld; cat | grep user; ps -ef | grep mysqld"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ mysql server configuration 파일에서 [mysqld] 그룹의 'user' 지시자 설정 1\) # vi [mysql server configuration 파일 위치] 2\) user = <mysqld를 구동할 시스템의 일반 사용자 계정> [주요기반시설 가이드] DBMS 구동 계정 변경 [상세 조치 사례] l MySQL Step 1\) 실행 중인 프로세스를 통한 확인 # ps –ef | grep mysqld Step 2\) mysql server configuration 파일에서 [mysqld] 그룹의 'user' 지시자의 설정값 확인 # cat [mysql server configuration 파일 위치] | grep user \(user=mysql로 설정되어 있으면 양호\) Step 3\) mysql server configuration 파일에서 [mysqld] 그룹의 'user' 지시자 설정 # vi [mysql server configuration 파일 위치] \(일반적으로 /etc/my.cnf.d/mysql-server.cnf\) ※ user = [mysqld를 구동할 시스템의 일반 사용자 계정]"

    local output
    output=$(ps -ef | grep mysqld 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-MY-SQL-05 / D-07" "보안 설정" "root 권한으로 서버 구동 제한" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-07 / D-08: 안전한 암호화 알고리즘 사용
check_CLD_MY_SQL_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 안전한 패스워드 암호화 알고리즘 사용 1\) mysql> ALTER user '사용자 계정 이름'@'localhost' IDENTIFIED WITH caching_sha2_password BY '패스워드'; 2\) mysql> FLUSH privileges; [주요기반시설 가이드] SHA-256 이상의 암호화 알고리즘 적용 [상세 조치 사례] l MySQL Step 1\) 계정별 암호화 알고리즘 확인 [mysql 5.7] mysql> SELECT user, host, plugin FROM mysql.user; 또는 mysql> SELECT host, user, plugin, password AS authentication_string FROM mysql.user; [mysql 8.0] 08. DBMS mysql> SELECT user, host, plugin FROM mysql.user; 또는 mysql> SELECT host, user, plugin, authentication_string FROM mysql.user; Step 2\) 비밀번호 및 암호화 알고리즘 설정 [mysql 5.7] - user 생성 시 적용 CREATE USER '계정명'@'host' IDENTIFIED BY '비밀번호'; - 기존 user 적용 ALTER USER '계정명'@'host' IDENTIFIED '신규 비밀번호'; ※ mysql 5.7에서는 기본적으로 mysql_native_password 플러그인이 사용되므로 별도의 지정이 필요하지 않음 [mysql 8.0] - user 생성 시 적용 mysql> CREATE USER '계정명'@'localhost' IDENTIFIED WITH caching_sha2_password BY '비밀번호'; - 기존 user 적용 mysql> ALTER USER '계정명'@'localhost' IDENTIFIED WITH caching_sha2_password BY '비밀번호'; ※ mysql v8.0 이상부터 암호화 알고리즘으로 caching_sha2_password\(SHA-256\)가 적용됨 ※ mysql v5.7 버전에서 사용하던 데이터베이스를 8.0으로 업그레이드하여 mysql_native_password 플러그인이 유 지되는 경우 위와 같이 caching_sha2_password 알고리즘을 지정하여 적용할 수 있음"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MY-SQL-07 / D-08" "DBMS > 1. 계정 관리" "안전한 암호화 알고리즘 사용" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-01: 불필요한 계정 제거
check_CLD_MY_SQL_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 불필요한 계정 삭제 1\) mysql> DELETE FROM user WHERE user='삭제할 계정명';"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. DB 설치 시 Default로 생성된 계정 및"
    cur_state="수동점검 필요"

    add_result "CLD-MY-SQL-01" "패치 및 로그 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-02: 취약한 패스워드 사용 제한
check_CLD_MY_SQL_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ validate_password 패스워드 정책 \(예시\) 1\) mysql server configuration 파일에서 아래의 내용으로 수정 # vi /etc/mysql/mysql.conf.d/mysqld.cnf validate_password.length=8 validate_password.mixed_case_count=1 validate_password.number_count=1 validate_password.special_char_count=1 validate_password.policy=MEDIUM 또는 STRONG 2\) # service mysql restart 3\) mysql> SHOW VARIABLES LIKE 'validate_password%';"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 패스워드 복잡도 설정을 적용하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MY-SQL-02" "계정 관리" "취약한 패스워드 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-03: 타 사용자에 권한 부여 옵션 제한
check_CLD_MY_SQL_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 불필요한 grant_priv 권한 제거 1\) mysql> USE mysql; 2\) mysql> REVOKE grant option ON *.* FROM '권한 제거 사용자 계정명'@'접속 IP'; 3\) mysql> FLUSH privileges;"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. grant_priv 권한이 적절한 사용자에게만"
    cur_state="수동점검 필요"

    add_result "CLD-MY-SQL-03" "계정 관리" "타 사용자에 권한 부여 옵션 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-04: 사용자 계정 정보 테이블 접근 권한
check_CLD_MY_SQL_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 일반 사용자 계정으로부터 mysql.user 테이블의 모든 권한 제거 1\) mysql> REVOKE all ON *.* FROM '사용자 계정명'@'접속 IP'; 2\) mysql> FLUSH prvileges;"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. DB사용자 계정 정보 테이블의 접근 권한이"
    cur_state="수동점검 필요"

    add_result "CLD-MY-SQL-04" "" "사용자 계정 정보 테이블 접근 권한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-06: 환경설정 파일 접근 권한
check_CLD_MY_SQL_06() {
    local status="양호"
    local detail=""
    local cmd="ls -alL"
    local cur_state=""
    local remediation="￭ mysql server configuration 파일 접근 권한 변경 1\) # chmod 640 [mysql server configuration 파일 위치]"

    local output
    output=$(ls -alL 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-MY-SQL-06" "보안 설정" "환경설정 파일 접근 권한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-08: 로그 활성화
check_CLD_MY_SQL_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ General log 설정 1\) # vi [mysql server configuration 파일] general_log = 1; 2\) # vi [mysql server configuration 파일] general_log_file 경로 설정 ￭ Slow log 설정 1\) # vi [mysql server configuration 파일] slow_query_log = 1; 2\) # vi [mysql server configuration 파일] slow_launch_time 설정 3\) # vi [mysql server configuration 파일] slow_query_log_file 경로 설정"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그 기능이 활성화되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MY-SQL-08" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MY-SQL-09: 최신 보안 패치 적용
check_CLD_MY_SQL_09() {
    local status="양호"
    local detail=""
    local cmd="dpkg -l | grep -i mysql-server; rpm -qa | grep -i mysql"
    local cur_state=""
    local remediation="￭ 데이터베이스에 대한 최신 보안 패치 버전으로 업그레이드 및 패치 수행 버그 패치 릴리즈 사이트 : http://downloads.mysql.com/archives/ 버그 현황 사이트 : http://bugs.mysql.com/bugstats.php ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(dpkg -l | grep -i mysql-server 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-MY-SQL-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# D-01: 기본 계정의 비밀번호, 정책 등을 변경하여 사용
check_D_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="기본\(관리자\) 계정의 초기 비밀번호 및 권한 정책 변경 [상세 조치 사례] l MySQL Step 1\) root 계정 비밀번호 변경 [mysql 5.7] mysql> UPDATE user SET authentication_string = PASSWORD\('신규 비밀번호'\) WHERE User = 'root'; mysql> flush privileges; [mysql 8.0] mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY '신규 비밀번호'; User Password User Password scott tiger or tigger system manager dbsnmp dbsnmp sys changeon_install tracesvr trace outln outln ordplugins ordplugins ordsys ordsys ctxsys ctxsys mdsys mdsys adams wood blake papr clark clth jones steel lbacsys lbacsys - - mysql> flush privileges;"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
    cur_state="수동점검 필요"

    add_result "D-01" "DBMS > 1. 계정 관리" "기본 계정의 비밀번호, 정책 등을 변경하여 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-02: 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
check_D_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="계정별 용도를 파악한 후 불필요한 계정 삭제 [상세 조치 사례] l MySQL Step 1\) 불필요한 계정 삭제 DROP USER '삭제할 계정'@'호스트명 or IP'; FLUSH PRIVILEGES; 08. DBMS 601"

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
    local remediation="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정 [상세 조치 사례] l MySQL [비밀번호 복잡도 정책 설정] Step 1\) 비밀번호 정책 확인 08. DBMS mysql> SHOW VARIABLES LIKE 'validate_password%'; ※ component_validate_password가 설치되어 있지 않은 경우 아래와 같이 해당 컴포넌트 설치 mysql> INSTALL COMPONENT 'file://component_validate_password'; Step 2\) 비밀번호 정책 설정 다음과 같은 방법으로 각각의 비밀번호 정책을 설정 SET GLOBAL validate_password.policy = 'MEDIUM'; \(비밀번호 정책의 강도 LOW/MEDIUM/STRONG\) SET GLOBAL validate_password.length = 8; \(비밀번호 최소 길이\) SET GLOBAL validate_password.mixed_case_count = 1; \(포함되어야 하는 영문 대소문자 최소 개수\) SET GLOBAL validate_password.number_count = 1; \(포함되어야 하는 숫자 최소 개수\) SET GLOBAL validate_password.special_char_count = 1; \(포함되어야 하는 특수문자 최소 개수\) ※ Linux계열\(/etc/my.cnf 또는 /etc/mysql/my.cnf\), Windows\(C:\\ProgramData\\MySQL\\MySQL Server <설치된 버전>\\my.ini\)의 <mysqld> 섹션에 설정을 추가하여 정책 설정 가능 ※ 비밀번호 신규 적용 및 초기화 시 설정 규칙에 맞추어 관리하고, 저장 시에는 일방향 암호화 알고리즘을 통해 암호화 처리\(One-Way Encryption\)함 [비밀번호 LifeTime 정책 적용 ] Step 1\) 비밀번호 정책 확인 mysql> SHOW VARIABLES LIKE 'default_password_lifetime'; Step 2\) 비밀번호 LifeTime 설정 mysql> SET GLOBAL default_password_lifetime=90; ※ 기본 값 - 5.7.11 이전 버전 : 0 - 5.7.11 이후 버전 및 8.0 이후 버전 : 360 Step 3\) 정책 적용전에 생성된 계정의 LifeTime 변경 mysql> ALTER USER <계정명>'@'<호스트명 or IP>' PASSWORD EXPIRE INTERVAL 91 DAY;"

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
    local remediation="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여 [상세 조치 사례] l MySQL Step 1\) Step 1\) SUPER 권한\(관리자 권한\)이 부여되어 있는 계정 확인 SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'SUPER'; Step 2\) 불필요하게 SUPER 권한이 부여되어 있는 계정에 대해 SUPER 권한 회수 REVOKE SUPER ON *.* FROM '<계정명>'; FLUSH PRIVILEGES; ※ 만약 관리자 'test'@'localhost' 계정이 바이너리 로그 정리 및 시스템 변수 수정을 위해 SUPER 권한을 필 요로 하는 경우 아래와 같은 명령문으로 필요한 권한으로 제한. GRANT BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN ON *.* TO 'test'@'localhost'; REVOKE SUPER ON *.* FROM 'test'@'localhost'; FLUSH PRIVILEGES;"

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
    local remediation="사용자별 계정 생성 및 권한 부여 [상세 조치 사례] l MySQL Step 1\) 공용용 계정 삭제 mysql> DROP USER <계정명>@<호스트명 or IP> Step 2\) 사용자별, 응용 프로그램별 계정 생성 및 권한 설정 // 사용자 계정 생성 mysql> create user '<계정명>'@'<호스트명 or IP>' identified by '비밀번호'; // 특정 데이터베이스의 특정 테이블에 select, insert 권한을 부여 mysql> grant select, insert on DB이름.테이블명 to '<계정명>'@'<호스트명 or IP>'; // 특정 데이터베이스의 모든 테이블에 모든 권한을 부여 mysql> grant all privileges on DB이름.* to '<계정명>'@'<호스트명 or IP>'; mysql> flush privileges; ※ 모든 권한을 부여할 경우, 해당 사용자는 지정된 데이터베이스에서 모든 작업의 수행이 가능하므로 사용자의 관리적 측면에서는 편리하나, 보안적 측면에서는 필요한 최소한의 권한만 부여하여 안정성을 높여야 함"

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
    local remediation="DB 서버에 대해 지정된 IP주소에서만 접근 가능하도록 설정 [상세 조치 사례] l MySQL Step 1\) user 테이블을 조회하여 모든 클리이언트에서 접속 가능하도록 설정되어 있는 계정을 특정 IP에서만 접 속 가능하도록 변경 mysql> UPDATE user SET host = '<접속 IP>' WHERE user ='<계정명>' and host='%'; 630"

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
    local remediation="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정 [상세 조치 사례] l MySQL Step 1\) 사용자 계정에 부여된 권한 확인 SHOW GRANTS FOR <계정명>; Step 2\) 접근이 필요한 데이터베이스 및 테이블에만 권한 적용 GRANT <권한> privileges ON <DB명>.<테이블명> to '<계정명>'@'<호스트명 or IP>';"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-11" "DBMS > 2. 접근 관리" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-21: 인가되지 않은 GRANT OPTION 사용 제한
check_D_21() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="WITH_GRANT_OPTION이 ROLE에 의하여 설정되도록 변경 [상세 조치 사례] l l MySQL Step 1\) 설정 확인 08. DBMS SELECT user, grant_priv FROM mysql.user; \(계정이 나오는 경우 취약\) Step 2\) 권한 회수 REVOKE <권한> ON <대상> FROM [계정명];"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
    cur_state="수동점검 필요"

    add_result "D-21" "DBMS > 3. 옵션 관리" "인가되지 않은 GRANT OPTION 사용 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
check_D_25() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="보안 패치가 적용된 버전으로 업데이트 [상세 조치 사례] l MySQL Step 1\) 시스템에서 제품 버전 현황 확인 mysql> SELECT VERSION\(\); Step 2\) MySQL 최신 버전 확인 버그 패치된 릴리즈 사이트 http://downloads.mysql.com/archives.php"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 보안 패치가 적용된 버전을 사용하는 경우"
    cur_state="수동점검 필요"

    add_result "D-25" "DBMS > 4. 패치 관리" "주기적 보안 패치 및 벤더 권고 사항 적용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
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


progress "CLD-MY-SQL-05"; check_CLD_MY_SQL_05
progress "CLD-MY-SQL-07"; check_CLD_MY_SQL_07
progress "CLD-MY-SQL-01"; check_CLD_MY_SQL_01
progress "CLD-MY-SQL-02"; check_CLD_MY_SQL_02
progress "CLD-MY-SQL-03"; check_CLD_MY_SQL_03
progress "CLD-MY-SQL-04"; check_CLD_MY_SQL_04
progress "CLD-MY-SQL-06"; check_CLD_MY_SQL_06
progress "CLD-MY-SQL-08"; check_CLD_MY_SQL_08
progress "CLD-MY-SQL-09"; check_CLD_MY_SQL_09
progress "D-01"; check_D_01
progress "D-02"; check_D_02
progress "D-03"; check_D_03
progress "D-04"; check_D_04
progress "D-06"; check_D_06
progress "D-10"; check_D_10
progress "D-11"; check_D_11
progress "D-21"; check_D_21
progress "D-25"; check_D_25

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
