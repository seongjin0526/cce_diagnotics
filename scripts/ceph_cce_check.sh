#!/bin/bash
###############################################################################
# Ceph CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash ceph_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_ceph_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Ceph helper ---
CEPH_CONF="${CEPH_CONF:-/etc/ceph/ceph.conf}"

run_ceph_cmd() {
    ceph "$@" 2>/dev/null
}


# --- Pre-flight: Ceph 설치 확인 및 경로 탐지 ---
CEPH_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    CEPH_BIN=$(command -v ceph 2>/dev/null)
    local rados_bin
    rados_bin=$(command -v rados 2>/dev/null)

    # 2) 프로세스에서 ceph-mon/ceph-osd 탐지
    if ps -ef 2>/dev/null | grep -qE '[c]eph-mon|[c]eph-osd|[c]eph-mgr'; then
        APP_FOUND="true"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ ! -f "$CEPH_CONF" ]; then
        for f in /etc/ceph/ceph.conf /usr/local/etc/ceph/ceph.conf; do
            if [ -f "$f" ]; then
                CEPH_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$CEPH_BIN" ] && [ -z "$rados_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'ceph-common\|ceph-mon' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'ceph' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$CEPH_BIN" ] || [ -n "$rados_bin" ] || [ -f "$CEPH_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Ceph 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CLD-Ceph-01: Keyring 파일 소유자 및 권한 확인
check_CLD_Ceph_01() {
    local status="양호"
    local detail=""
    local cmd="ls /keyring"
    local cur_state=""
    local remediation="￭ Keyring 소유자 및 파일 권한 변경 1\) # chown root:root [keyring 파일 디렉터리]/keyring 파일 2\) # chmod 400 [keyring 파일 디렉터리]/keyring 파일"

    local output
    output=$(ls /keyring 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Ceph-01" "패치 관리" "Keyring 파일 소유자 및 권한 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Ceph-02: SSH 인증키 파일 관리
check_CLD_Ceph_02() {
    local status="양호"
    local detail=""
    local cmd="ls -ld ~/.ssh; ls -l ~/.ssh"
    local cur_state=""
    local remediation="￭ .ssh 디렉터리 권한 변경 1\) # chmod 700 ~/.ssh ￭ ssh 키 파일 권한 변경 1\) # chmod 600 ~/.ssh/키 파일"

    local output
    output=$(ls -ld ~/.ssh 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Ceph-02" "파일 및 디렉터리" "SSH 인증키 파일 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Ceph-03: Ceph 설정 파일 소유자 및 권한 확인
check_CLD_Ceph_03() {
    local status="양호"
    local detail=""
    local cmd="ls -l /ceph.conf"
    local cur_state=""
    local remediation="￭ Ceph 설정 파일 권한 변경 1\) # chmod o-w [Ceph 설정 디렉터리]/ceph.conf"

    local output
    output=$(ls -l /ceph.conf 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Ceph-03" "파일 및 디렉터리" "Ceph 설정 파일 소유자 및 권한 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Ceph-04: Ceph 인증 프로토콜 적용
check_CLD_Ceph_04() {
    local status="양호"
    local detail=""
    local cmd="cat /ceph.conf"
    local cur_state=""
    local remediation="￭ 설정 파일에서 [global] 영역에 CEPHX 프로토콜 적용 1\) # vi [Ceph 설정 디렉터리]/ceph.conf"

    local output
    output=$(cat /ceph.conf 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Ceph-04" "보안 설정" "Ceph 인증 프로토콜 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Ceph-05: root 이외의 관리자 계정 사용
check_CLD_Ceph_05() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/sudoers"
    local cur_state=""
    local remediation="￭ 별도의 관리자 계정 생성 예시\) 1\) 계정 생성 # useradd admin 2\) 생성된 계정에 관리자 계정 부여 # chmod 660 /etc/sudoers 명령어를 통해 sudoers 파일 쓰기 권한 부여 # vi /etc/sudoers 명령어 입력 후 아래와 같이 작성 # chmod 440 /etc/sudoers 명령어를 통해 sudoers 파일 쓰기 권한 제거"

    local output
    output=$(cat /etc/sudoers 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Ceph-05" "보안 설정" "root 이외의 관리자 계정 사용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Ceph-06: Selinux 활성화
check_CLD_Ceph_06() {
    local status="양호"
    local detail=""
    local cmd="getenforce"
    local cur_state=""
    local remediation="￭ SELinux 활성화 1\) # vi /etc/selinux/config"

    local output
    output=$(getenforce 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Ceph-06" "" "Selinux 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Ceph-07: 최신 보안 패치 적용
check_CLD_Ceph_07() {
    local status="양호"
    local detail=""
    local cmd="ceph -v"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 적용 1\) 최신 보안 패치 업데이트가 발표되었을 경우, 시스템 영향도를 파악하여 충분한 테스트를 진행한 후 적용 권고 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(ceph -v 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Ceph-07" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Ceph CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/7] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Ceph-01"; check_CLD_Ceph_01
progress "CLD-Ceph-02"; check_CLD_Ceph_02
progress "CLD-Ceph-03"; check_CLD_Ceph_03
progress "CLD-Ceph-04"; check_CLD_Ceph_04
progress "CLD-Ceph-05"; check_CLD_Ceph_05
progress "CLD-Ceph-06"; check_CLD_Ceph_06
progress "CLD-Ceph-07"; check_CLD_Ceph_07

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
    echo '    "platform": "Ceph",'
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

echo "===== Ceph CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
