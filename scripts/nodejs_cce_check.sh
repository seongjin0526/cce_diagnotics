#!/bin/bash
###############################################################################
# Node.js CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash nodejs_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_node.js_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Pre-flight: Node.js 설치 확인 및 경로 탐지 ---
NODE_BIN=""
NPM_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NODE_BIN=$(command -v node 2>/dev/null)
    NPM_BIN=$(command -v npm 2>/dev/null)

    # 2) 프로세스에서 node 탐지
    if [ -z "$NODE_BIN" ]; then
        if ps -ef 2>/dev/null | grep -q '[n]ode '; then
            APP_FOUND="true"
        fi
    fi

    # 3) nvm 환경 확인
    if [ -z "$NODE_BIN" ] && [ -d "$HOME/.nvm" ]; then
        local nvm_node
        nvm_node=$(ls -d "$HOME/.nvm/versions/node"/*/bin/node 2>/dev/null | tail -1)
        if [ -n "$nvm_node" ] && [ -x "$nvm_node" ]; then
            NODE_BIN="$nvm_node"
        fi
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$NODE_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'nodejs' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'nodejs' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$NODE_BIN" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Node.js 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CLD-NodeJS-01: node 프로세스 권한 제한
check_CLD_NodeJS_01() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep node | grep -v grep; app.js | grep process.env.NODE_ENV"
    local cur_state=""
    local remediation="￭ root 계정 이외의 계정으로 node 프로세스 실행 1\) # set DEBU=www & npm start dev ￭ production 모드로 변경 1\) # export NODE_ENV=production"

    local output
    output=$(ps -ef | grep node | grep -v grep 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-NodeJS-01" "로그 및 패치 관리" "node 프로세스 권한 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-NodeJS-02: 헤더 정보 노출 방지
check_CLD_NodeJS_02() {
    local status="양호"
    local detail=""
    local cmd="cat app.js"
    local cur_state=""
    local remediation="￭ node 메인 파일에 헤더 정보 노출 설정 추가 예시\) 1\) # vi app.js"

    local output
    output=$(cat app.js 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-NodeJS-02" "보안 설정" "헤더 정보 노출 방지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-NodeJS-03: 오류 메시지 설정
check_CLD_NodeJS_03() {
    local status="양호"
    local detail=""
    local cmd="cat app.js; cat views/error.jade"
    local cur_state=""
    local remediation="￭ 일원화된 오류 메시지 설정 예시\) 1\) # vi views/error/jade ￭ 에러 내용을 알 수 없는 일원화된 오류 메시지"

    local output
    output=$(cat app.js 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-NodeJS-03" "보안 설정" "오류 메시지 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-NodeJS-04: 로그 디렉터리 및 파일 권한 설정
check_CLD_NodeJS_04() {
    local status="양호"
    local detail=""
    local cmd="ls -ld; ls -ld"
    local cur_state=""
    local remediation="￭ 로그 디렉터리 및 로그 파일 접근 권한 변경 1\) 로그 디렉터리 접근 권한 변경 # chown nodeLnode [node 애플리케이션 로그 디렉터리] # chown 750 [node 애플리케이션 로그 디렉터리] ￭ 로그 파일 접근 권한 변경 # chown node:node [node 애플리케이션 로그 파일] # chmod 640 [node 애플리케이션 로그 디렉터리]"

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

    add_result "CLD-NodeJS-04" "보안 설정" "로그 디렉터리 및 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-NodeJS-05: 로그 포맷 설정
check_CLD_NodeJS_05() {
    local status="양호"
    local detail=""
    local cmd="cat app.js; cat app.js"
    local cur_state=""
    local remediation="￭ 실시간 콘솔 로그 설정 예시\) Express의 Morgan 모듈을 사용하는 경우 1\) # vi app.js var logger = require\('morgan'\); ... 중간 생략 ... app.use\(logger\('combined'\)\) ￭ 로그 파일 저장 설정 예시\) Express의 Morgan 모듈을 사용하는 경우 1\) # vi app.js var fs = require\('fs'\); ... 중간 생략 ... app.use\(logger\({ format: 'default', stream: fs.createWriteStream\('./log/app.log', {'flags': 'w'}\) }\)\);"

    local output
    output=$(cat app.js 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-NodeJS-05" "로그 및 패치 관리" "로그 포맷 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-NodeJS-06: 로그 파일 보관 및 주기적 백업
check_CLD_NodeJS_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 사용자 접속 기록 보관 기간은 '정보통신망 이용 촉진 및 정보보호 등에 관한 법률', '개인정보보호법'등 관련 법률에 근거하여 보관하여야 함 1\) 개인정보 처리 시스템인 경우 접속 기록 보관 주기 : 1년 이상\(5만 명 이상의 정보 주체에 관하여 개인정보를 처리하거나, 민감 정보를 처리하는 경우에는 2년 이상\) 접속 기록에 대한 주기적 점검 : 월 1회 이상 백업 수행 주기 : 개인정보 처리 시스템 외의 별도 저장 장치에 상시로 접속 기록 백업 백업 보관 주기 : 관련 사항 없음\(재해복구 관점 고려\) 2\) 로그 백업 정책에 따라 로그 파일을 정기적으로 백업을 수행"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그 보관 주기를 준수하고 주기적으로"
    cur_state="수동점검 필요"

    add_result "CLD-NodeJS-06" "로그 및 패치 관리" "로그 파일 보관 및 주기적 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-NodeJS-07: 최신 보안 패치 적용
check_CLD_NodeJS_07() {
    local status="양호"
    local detail=""
    local cmd="rpm -qa | grep nodejs; node -v; npm -v"
    local cur_state=""
    local remediation="￭ Node.js 사이트를 통해 주기적으로 버전 점검을 하도록 하며 최신 보안 패치 적용 시 충분한 테스트 후 적용 ￭ NPM 최신 보안 패치 업데이트 1\) npm 업데이트 # npm install –g npm 2\) 업데이트 후 npm 버전 확인 ￭ Express 최신 버전 업데이트 # npm install express"

    local output
    output=$(rpm -qa | grep nodejs 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-NodeJS-07" "로그 및 패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Node.js CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/7] %s 점검 중...                " "$total" "$1"
}


progress "CLD-NodeJS-01"; check_CLD_NodeJS_01
progress "CLD-NodeJS-02"; check_CLD_NodeJS_02
progress "CLD-NodeJS-03"; check_CLD_NodeJS_03
progress "CLD-NodeJS-04"; check_CLD_NodeJS_04
progress "CLD-NodeJS-05"; check_CLD_NodeJS_05
progress "CLD-NodeJS-06"; check_CLD_NodeJS_06
progress "CLD-NodeJS-07"; check_CLD_NodeJS_07

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
    echo '    "platform": "Node.js",'
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

echo "===== Node.js CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
