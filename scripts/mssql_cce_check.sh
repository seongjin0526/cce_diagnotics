#!/bin/bash
###############################################################################
# MSSQL CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash mssql_cce_check.sh -h <host> -P <port> -u <user> -p <password> [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

# Database connection parameters
DB_HOST="localhost"
DB_PORT="1433"
DB_USER="sa"
DB_PASS=""

usage() {
    echo "Usage: sudo bash mssql_cce_check.sh [-h host] [-P port] [-u user] [-p password] [output_file.json]"
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

OUTPUT_FILE="${1:-cce_check_result_mssql_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"


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


# --- MSSQL helper ---
run_mssql_query() {
    local query="$1"
    if command -v sqlcmd &>/dev/null; then
        sqlcmd -S "$DB_HOST,$DB_PORT" -U "$DB_USER" -P "$DB_PASS" -Q "$query" -h -1 2>/dev/null
    elif command -v mssql-cli &>/dev/null; then
        mssql-cli -S "$DB_HOST" -U "$DB_USER" -P "$DB_PASS" -Q "$query" 2>/dev/null
    else
        echo "ERROR: sqlcmd or mssql-cli not found"
    fi
}


# CLD-MS-SQL-05 / D-24: Regisrtry Procedure Permission 제한
check_CLD_MS_SQL_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 새 쿼리를 통해 프로시저 제한 1\) SQL Server Management Studio → 새쿼리 2\) USE master; 3\) REVOKE <권한> ON object :: <시스템 확자 저장 프로시저명> TO public; ￭ 개체 탐색기를 통해 프로시저 제한 1\) SQL Server Management Studio → 개체 탐색기 → 데이터베이스 2\) 시스템 데이터베이스 → master → 프로그래밍 기능 → 확장 저장 프로시저 → 시스템 확장 저장 프로시저 3\) 아래 *비고\) 시스템 확장 저장 프로시저 제한 목록의 프로시저 별 → 마우스 우클릭 → 속성 4\) 사용 권한 → public 실행 권한 제거 [주요기반시설 가이드] guest/public에게 부여된 시스템 확장 저장 프로시저 권한 제거 [상세 조치 사례] l MSSQL Step 1\) SQL Server Management Studio > 개체 탐색기 > 데이터베이스 Step 2\) 시스템 데이터베이스 > master > 프로그래밍 기능 > 확장 저장 프로시저 > 시스템 확장 저장 프로시저 [ 시스템 확장 저장 프로시저 확인 ] Step 3\) 각 시스템 확장 저장 프로시저 제한 > 마우스 우클릭 > 속성 [ 시스템 확장 저장 프로시저 속성 확인 ] Step 4\) 사용 권한 > public 실행 권한 제거\(체크 해제\) [ public 실행 권한 제거 ] 시스템 확장 저장 프로시저 제한 sys.xp_readdmultistring sys.xp_redeletekey sys.xp_regdeletevalue sys.xp_regenumvalues sys.xp_regread sys.xp_regremovemultistring sys.xp_regwrite 08. DBMS 663"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-05 / D-24" "DBMS > 3. 옵션 관리" "Regisrtry Procedure Permission 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-06 / D-23: xp_cmdshell 사용 제한
check_CLD_MS_SQL_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 새 쿼리를 통해 프로시저 확인 1\) SQL Server Management Studio → 새쿼리 2\) EXEC sp_configure 'xp_cmdshell', 0; ￭ 개체 탐색기를 통해 프로시저 확인 1\) SQL Server Management Studio → 개체 탐색기 → 컴퓨터 이름 → 오른쪽 마우스 → 패싯 → 일반 2\) XPCmdShellEnabled 값 false 설정 [주요기반시설 가이드] xp_cmdshell 설정 값을 0 또는 False로 설정 [상세 조치 사례] l MSSQL [ xp_cmdshell 사용이 불필요한 경우ㅣ Step 1\) SQL Server Management Studio > 개체 탐색기 > 컴퓨터 이름 우클릭 > 패싯 > 일반 Step 2\) XPCmdShellEnabled 값 확인 2.1\) Microsoft SQL Server Management Studio에서 확인 [ 개체 탐색기를 통한 프로시저 확인 ] 2.2\) 퀴리문으로 확인 SELECT name, value FROM sys.configurations WHERE name = 'xp_cmdshell'; ※ value가 1이면 활성화, 0이면 비활성화 되어 있는 상태 Step 3\) XPCmdShellEnabled 값을 false로 설정 3.1\) Microsoft SQL Server Management Studio에서 설정 SQL Server Management Studio > 개체 탐색기 > 컴퓨터 이름 우클릭 > 패싯 > 일반 3.2\) 퀴리문으로 설정 EXEC sp_configure 'show advanced options', 1; GO RECONFIGURE; GO EXEC sp_configure 'xp_cmdshell', 1; GO RECONFIGURE GO [ xp_cmdshell 사용이 필요한 경우ㅣ Step 1\) xp_cmdshell의 public 실행 권한 제거 1.1\) Microsoft SQL Server Management Studio에서 제거 SQL Server Management Studio > 개체 탐색기 > [컴퓨터 이름] > 데이터베이스 > 시스템 데이터베이스 > master > 프로그래밍 기능 > 확장 저장 프로시저 > 시스템 확장 저장 프로시저 > sys.xp_cmdshell > 마우스 우클릭 > 속성 > 사용권한에서 public에 대한 사용권한에 '실행' 권한 제거 08. DBMS 1.2\) 퀴리문으로 public에 대한 실행 권한 제거 REVOKE EXECUTE ON master.dbo.xp_cmdshell TO public Step 1\) 서비스 계정\(애플리케이션 연동 등\)의 sysadmin 권한 제거 2.1\) Microsoft SQL Server Management Studio에서 제거 SQL Server Management Studio > 개체 탐색기 > [컴퓨터 이름] > 보안 > 로그인 > [각 계정 선택] > 마우스 우클릭 > 속성 > 서버 역할에서 sysadmin 권한 제거 2.2\) 퀴리문으로 서비스 계정의 sysadmin 권한 제거 - sysadmin 권한이 부여된 계정 확인 EXEC sp_helpsrvrolemember 'sysadmin' - sysadmin 권한이 부여된 계정에 대해 권한 제거 EXEC master..sp_dropsrvrolemember @loginame = N'<계정명>', @rolename = N'sysadmin' ※ 08. DBMS 661"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-06 / D-23" "보안 설정" "xp_cmdshell 사용 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-01: 불필요한 계정 제거
check_CLD_MS_SQL_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 새 쿼리를 통해 불필요한 계정 삭제 1\) SQL Server Management Studio → 새 쿼리 2\) DROP login \"로그인 사용자 계정명\" ￭ 개체 탐색기를 통해 불필요한 계정 삭제 1\) SQL Server Management Studio → 개체 탐색기 → 보안 → 로그인 2\) 해당 계정 오른쪽 마우스 → 삭제 → 확인"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 계정이 존재하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-01" "패치 및 로그 관리" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-02: SYSADMIN 권한 제한
check_CLD_MS_SQL_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 새 쿼리를 통해 역할 제거 1\) SQL Server Management Studio → 새 쿼리 2\) EXEC sp_droprolemember '<구성원 이름>', 'sysadmin' ￭ 개체 탐색기를 통해 역할 제거 1\) SQL Server Management Studio → 개체 탐색기 → 보안 → 로그인 2\) 계정별 오른쪽 마우스 → 속성 → 서버 역할에서 sysadmin 권한 해제"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. sysadmin 역할 구성원에 관리자 구성원만"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-02" "계정 관리" "SYSADMIN 권한 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-03: SA 계정 패스워드 관리
check_CLD_MS_SQL_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 새 쿼리를 통해 변경 1\) SQL Server Management Studio → 새 쿼리 2\) ALTER LOGIN sa WITH password='변경할 패스워드'; ￭ 개체 탐색기를 통해 변경 1\) SQL Server Management Studio → 개체 탐색기 → 보안 → 로그인 2\) sa 계정 오른쪽 마우스 → 속성 → 일반 → 암호 변경"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. sa 계정에 패스워드가 설정된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-03" "계정 관리" "SA 계정 패스워드 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-04: Guest 계정 사용 제한
check_CLD_MS_SQL_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 데이터베이스에 존재하는 Guest 계정 비활성화 1\) SQL Server Management Studio → 새 쿼리 2\) USE [해당 데이터베이스] 3\) REVOKE connect FROM guest;"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 데이터베이스에 Guest 계정이 활성화되어"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-04" "" "Guest 계정 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-07: 로그 활성화
check_CLD_MS_SQL_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 개체 탐색기를 통해 로그 활성화 1\) SQL Server Management Studio → 개체 탐색기 → 컴퓨터 이름 → 오른쪽 마우스 → 보안 → 로그인 감사 설정 여부 확인 2\) \(실패한 로그인만/성공한 로그인만/실패한 로그인과 성공한 로그인 모두\) 이 3가지 중 1가지로 설정 ￭ 백업 정책 수립 1\) 백업 정책을 수립하고 주기적으로 로그 파일을 백업 ※ DBMS 유지 보수 및 업그레이드 시에는 전체 FULL 백업 절차 수립 \(권고\)"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 백업 정책이 수립되어 있으며 데이터,"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-07" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-MS-SQL-08: 최신 보안 패치 적용
check_CLD_MS_SQL_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 적용 1\) 최신 보안 패치가 발표되면 패치 적용 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 최신 보안 패치가 적용되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-MS-SQL-08" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# D-01: 기본 계정의 비밀번호, 정책 등을 변경하여 사용
check_D_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="기본\(관리자\) 계정의 초기 비밀번호 및 권한 정책 변경 [상세 조치 사례] l MSSQL Step 1\) sa 계정 비밀번호 변경 ALTER LOGIN sa WITH PASSWORD = '신규 비밀번호'; [ sa 계정 비밀번호 변경 ] Step 2\) 비밀번호 정책 강제 사용 적용"

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
    local remediation="계정별 용도를 파악한 후 불필요한 계정 삭제 [상세 조치 사례] l MSSQL Step 1\) 불필요한 계정 삭제 EXEC sp_droplogin '삭제할 계정';"

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
    local remediation="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정 [상세 조치 사례] l MSSQL Step 1\) 비밀번호 변경 주기는 '암호 만료 강제 적용'을 적용함으로써 주기적으로 변경할 수 있으며, 변경 기간은 OS의 '암호 정책'에서 적용받으므로 '암호 정책 > 최대 암호 사용 기간' 설정도 변경해야 함 Step 2\) 암호 만료 강제 적용 보안 > 로그인 > 각 로그인 계정 > 속성 > \"암호 만료 강제 적용\" 설정 [ 암호 만료 강제 적용 설정 ] Step 3\) OS 암호 정책 설정 [관리 도구] > [로컬 보안 정책] > [보안 설정] > [계정 정책] > [암호 정책] > 최대 암호 사용 기간 : '60일' 설정 [ 최대 암호 사용 기간 설정 ]"

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
    local remediation="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여 [상세 조치 사례] l MSSQL Step 1\) sysadmin서버 역할의 계정 목록을 확인 후 서버 역할에 불필요한 계정이 있는 경우 서버 역할에서 삭제 EXEC sp_droprolemember 'user_name', 'sysadmin'; 예시\) EXEC sp_dropsrvrolemember 'user01', 'sysadmin'; \(user01계정을 sysadmin서버 역할에서 삭제\) [ 서버 역할에서 불필요 계정 삭제 예시 ]"

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
    local remediation="사용자별 계정 생성 및 권한 부여 [상세 조치 사례] l MSSQL Step 1\) 공용계정 삭제 EXEC sp_droplogin '공용 계정'; 08. DBMS Step 2\) 사용자별, 응용 프로그램별 계정 생성 CREATE LOGIN '생성 계정' WITH PASSWORD = '비밀번호'; CREATE USER '생성 계정' FOR LOGIN '생성 계정' WITH DEFAULT_SCHEMA ='생성 계정'; ALTER USER '생성 계정'; EXEC sp_adduser '생성 계정', '생성 계정', 'db_owner'; EXEC sp_adduser '생성 계정', '생성 계정', '생성 계정'; EXEC sp_grantdbaccess '생성 계정', '생성 계정';"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 사용자별 계정을 사용하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-06" "DBMS > 1. 계정 관리" "DB 사용자 계정을 개별적으로 부여하여 사용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-08: 안전한 암호화 알고리즘 사용
check_D_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="SHA-256 이상의 암호화 알고리즘 적용 [상세 조치 사례] l MSSQL Step 1\) 저장된 비밀번호 해시 값 확인 select name, password_hash from sys.sql_logins; ※ MSSQL 2012이상에서 사용자 계정의 비밀번호는 32bit Salt를 적용한 SHA-512 해시 알고리즘을 사용 [ 일반 이용자 패스워드 해시 알고리즘 변경 ] Step 1\) 데이터베이스 접속 USE <데이터베이스명> GO Step 1\) 열 추가 ALTER TABLE <테이블명> ADD <신규 해시 칼럼명> varbinary\(256\) GO Step 2\) 새로운 열에 암호화 된 데이터 저장 UPDATE <테이블명> SET <신규 해시 칼럼명> = HASHBYTES\('SHA2_256', <기존 해시 칼럼명>\) GO Step 3\) 기존 열 제거 ALTER TABLE <테이블명> DROP COLUMN <기존 해시 칼럼명> GO"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-08" "DBMS > 1. 계정 관리" "안전한 암호화 알고리즘 사용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-11: DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
check_D_11() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정 [상세 조치 사례] l MSSQL Step 1\) system tables 접근 권한이 PUBLIC, GUEST 또는 비인가된 사용자에게 부여된 경우 접근 권한을 제거 REVOKE <권한> ON <Object> FROM [계정명]|[PUBLIC]|[GUEST]; Step 2\) 시스템 테이블에 접근하기 위해서는 stored procedure 또는 information_schema views를 통해 접근해야 함 Step 3\) 시스템 테이블에 접근 가능한 stored procedure는 사용이 제한되어야 함"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-11" "DBMS > 2. 접근 관리" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-16: Windows 인증 모드 사용
check_D_16() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="Windows 인증 모드 사용 [상세 조치 사례] l MSSQL Step 1\) Windows 인증 모드 활성화 SQL Server Management Studio > 해당 서버 우클릭 > 속성 > 보안 > 서버 인증> Windows 인증 모드 \(W\)를 클릭하여 활성화 08. DBMS [ Windows 인증 모드\(W\) 활성화 ] 646"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "D-16" "DBMS > 2. 접근 관리" "Windows 인증 모드 사용" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
check_D_25() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="보안 패치가 적용된 버전으로 업데이트 [상세 조치 사례] l MSSQL Step 1\) 시스템에서 제품 버전 현황 확인 SELECT @@version 또는 SELECT SERVERPROPERTY\('productversion'\) AS ProductVersion, SERVERPROPERTY\('productlev el'\) AS ProductLevel, SERVERPROPERTY\('edition'\) AS Edition; Step 2\) MSSQL 최신 버전 확인 http://support.microsoft.com/kb/321185/en-uswnloads/index.html 664"

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
    local remediation="DBMS에 대한 감사 로그 저장 정책 수립, 적용 [상세 조치 사례] l MSSQL 데이터베이스 감사 기록 정책 및 백업 정책 수립 ● MSSQL 2000 DB 접근에 대한 보안 감사를 할 수 있도록 보안 감사 설정 [SQL SERVER] > [등록정보] > [보안] > [감사수준] > '모두' 선택 ● MSSQL 2005, 2008, 2012, 2016, 2019, 2022 [SQL SERVER] > [마우스 우클릭] > [속성] > [보안] > [로그인 감사] 옵션 > '실패한 로그인과 성공한 로그인 모두' 선택 [ 로그인 감사 설정 ]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "D-26" "DBMS > 4. 패치 관리" "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== MSSQL CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/18] %s 점검 중...                " "$total" "$1"
}


progress "CLD-MS-SQL-05"; check_CLD_MS_SQL_05
progress "CLD-MS-SQL-06"; check_CLD_MS_SQL_06
progress "CLD-MS-SQL-01"; check_CLD_MS_SQL_01
progress "CLD-MS-SQL-02"; check_CLD_MS_SQL_02
progress "CLD-MS-SQL-03"; check_CLD_MS_SQL_03
progress "CLD-MS-SQL-04"; check_CLD_MS_SQL_04
progress "CLD-MS-SQL-07"; check_CLD_MS_SQL_07
progress "CLD-MS-SQL-08"; check_CLD_MS_SQL_08
progress "D-01"; check_D_01
progress "D-02"; check_D_02
progress "D-03"; check_D_03
progress "D-04"; check_D_04
progress "D-06"; check_D_06
progress "D-08"; check_D_08
progress "D-11"; check_D_11
progress "D-16"; check_D_16
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
    echo '    "platform": "MSSQL",'
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

echo "===== MSSQL CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
