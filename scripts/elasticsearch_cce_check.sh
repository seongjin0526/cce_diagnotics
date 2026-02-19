#!/bin/bash
###############################################################################
# Elasticsearch CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash elasticsearch_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_elasticsearch_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Elasticsearch helper ---
ES_URL="${ES_URL:-http://localhost:9200}"

run_es_api() {
    local endpoint="$1"
    curl -s -m 10 "${ES_URL}${endpoint}" 2>/dev/null
}


# CLD-Elasticsearch-01: Elasticsearch 인증 설정
check_CLD_Elasticsearch_01() {
    local status="양호"
    local detail=""
    local cmd="cat /x-pack/users; cat /users; cat /search-guard-/sgconfig/sg_internal_"
    local cur_state=""
    local remediation="￭ X-Pack 플러그인을 통해 설정 - Elasticsearch v5.x, v6.x 1\) # [Elasticsearch 설치 디렉터리/bin/x-pack] ./users useradd '계정명' -r '계정권한' 실행 - Elasticsearch v7.0 이상 1\) # vi [Elasticsearch 설정 디렉터리/elasticsearch.yml] 2\) security 필드에 아래의 내용 추가 3\) # [Elasticsearch 설치 디렉터리]/bin/elasticsearch-setup-passwords interactive 4\) 사용자 계정 인증 및 인증 창 확인 # curl --user '사용자 계정':'패스워드' localhost:9200 입력 또는 검색창에 http://localhost:9200 입력 ￭ Search-Guard 플러그인을 통해 설정 - Elasticsearch v5.0 이상 1\) # cd [Elasticsearch 설치 디렉터리]/bin/search-guard-*/tools를 통해 디렉터리 이동 2\) # ./hash.sh 명령어를 통해 패스워드 해시값 생성 3\) 출력된 해시값과 계정명을 [Elasticsearch 설치 디렉터리]/plugin/search-guard-*/ sgconfig/sg_internal_users.yml 설정 파일에 기입 ※ 띄어쓰기에 민감하므로 아래 예시된 그림과 같이 라인 간격을 맞춰야 함 4\) [Elasticsearch 설치 디렉터리/bin/search-guard-*/sgconfig/sg_roles_mapping. yml 설정 파일에서 role과 계정 매핑 5\) [Elasticsearch 설치 디렉터리/bin/search-guard-*/tools/sgadmin_demo.sh 스크립트를 실행하여 설정 적용"

    local api_result
    api_result=$(curl localhost:9200 2>/dev/null)
    if [ -n "$api_result" ]; then
        cur_state="$api_result"
        detail="API 응답 확인됨. 수동 검증 필요. "
        status="수동점검"
    else
        cur_state="API 응답 없음"
        detail="API 호출 실패 또는 서비스 미실행. "
        status="N/A"
    fi

    add_result "CLD-Elasticsearch-01" "패치 및 로그 관리" "Elasticsearch 인증 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-02: 디폴트 계정 및 패스워드 변경
check_CLD_Elasticsearch_02() {
    local status="양호"
    local detail=""
    local cmd="curl -u test:test123 -XGET http://localhost:9200/_xpack_security/user"
    local cur_state=""
    local remediation="￭ 디폴트 계정 삭제/비활성화 \(X-Pack 사용 시\) 1\) 디폴트 계정을 비활성화하기 전 새로운 계정 생성 2\) 관리자 권한 부여 3\) 디폴트 계정 비활성화 ￭ 디폴트 계정 삭제/비활성화 \(Search-Guard 사용 시\) 1\) 디폴트 계정을 비활성화하기 전 새로운 계정 생성 2\) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/sgconfig/sg_internal_ users.yml 파일을 수정하여 기존 관리자 계정 영역 삭제 및 신규 계정 및 패스워드 적용 3\) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/sgconfig/sg_roles_ mapping.yml 파일을 수정하여 기존 관리자 계정 삭제 및 신규 계정 적용"

    local api_result
    api_result=$(curl -u test:test123 -XGET http://localhost:9200/_xpack_security/user 2>/dev/null)
    if [ -n "$api_result" ]; then
        cur_state="$api_result"
        detail="API 응답 확인됨. 수동 검증 필요. "
        status="수동점검"
    else
        cur_state="API 응답 없음"
        detail="API 호출 실패 또는 서비스 미실행. "
        status="N/A"
    fi

    add_result "CLD-Elasticsearch-02" "보안 설정" "디폴트 계정 및 패스워드 변경" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-03: 불필요한 계정 제거
check_CLD_Elasticsearch_03() {
    local status="양호"
    local detail=""
    local cmd="cat /x-paxk/user_roles; /bin/x-pack/elasticsearch-users list; cat /users_roles"
    local cur_state=""
    local remediation="- Elasticsearch v5.x, v6.x \(X-Pack 플러그인 사용 시\) 1\) # [Elasticsearch 설치 디렉터리]/bin/x-pack/users userdel '계정명' 실행 - Elasticsearch v7.0 이상 \(X-Pack 플러그인 사용 시\) 1\) # [Elasticsearch 설치 디렉터리]/bin/elasticsearch-users userdel <사용자 명> ￭ 설정 파일 및 명령어를 통해 변경 \(SearchGuard 사용 시\) - Elasticsearch 5.0 이상 SearchGuard 플러그인 사용 시 1\) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/sgconfig/sg_roles_ mapping.yml 파일을 수정하여 불필요한 계정 제거 2\) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/tools/sgadmin_demo. sh을 실행하여 설정 적용"

    local output
    output=$(cat /x-paxk/user_roles 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Elasticsearch-03" "보안 설정" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-04: IP 접근 제한 설정
check_CLD_Elasticsearch_04() {
    local status="양호"
    local detail=""
    local cmd="cat /elasticsearch.yml | grep network.host"
    local cur_state=""
    local remediation="￭ Elasticsearch 설정 파일 안의 network.host 설정 변경 1\) # vi cat [Elasticsearch 디렉터리]/elasticsearch.yml 2\) network.host 인가된 IP로 변경"

    local config_file="/elasticsearch.yml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "network.host" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: network.host 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Elasticsearch-04" "보안 설정" "IP 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-05: 설치 디렉터리 접근 권한 설정
check_CLD_Elasticsearch_05() {
    local status="양호"
    local detail=""
    local cmd="ls -ld"
    local cur_state=""
    local remediation="￭ Elasticsearch 설치 디렉터리 권한 750으로 변경 1\) # chmod 750 [Elasticsearch 설치 디렉터리]"

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

    add_result "CLD-Elasticsearch-05" "디렉터리 및" "설치 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-06: 플러그인 디렉터리 접근 권한 설정
check_CLD_Elasticsearch_06() {
    local status="양호"
    local detail=""
    local cmd="ls- ld /plugins"
    local cur_state=""
    local remediation="￭ Elasticsearch 플러그인 디렉터리 권한 750으로 변경 1\) # chmod 750 [Elasticsearch 설치 디렉터리]/plugins"

    local output
    output=$(ls- ld /plugins 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Elasticsearch-06" "디렉터리 및" "플러그인 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-07: 설정 파일 접근 권한 설정
check_CLD_Elasticsearch_07() {
    local status="양호"
    local detail=""
    local cmd="ls -l /elasticsearch.yml; ls -l /plugins/search-guard-*/sgconfig"
    local cur_state=""
    local remediation="￭ 설정 파일의 권한을 660 이하로 변경 1\) # chmod 660 [Elasticsearch 디렉터리/elasticsearch.yml]"

    local vuln_found=false
    if [ -e "/elasticsearch.yml" ]; then
        local result_elasticsearch_yml
        result_elasticsearch_yml=$(check_file_owner_perm "/elasticsearch.yml" "root" "660")
        cur_state+="/elasticsearch.yml: $result_elasticsearch_yml; "
        case "$result_elasticsearch_yml" in
            VULN*) vuln_found=true; detail+="/elasticsearch.yml 소유자/권한 부적절($result_elasticsearch_yml). " ;;
            GOOD*) detail+="/elasticsearch.yml 소유자/권한 적절($result_elasticsearch_yml). " ;;
            NOT_FOUND) detail+="/elasticsearch.yml 파일 없음. " ;;
        esac
    else
        detail+="/elasticsearch.yml 파일 없음. "
        cur_state+="/elasticsearch.yml: 파일 없음; "
    fi
    if [ -e "/plugins/search-guard-" ]; then
        local result_plugins_search_guard_
        result_plugins_search_guard_=$(check_file_owner_perm "/plugins/search-guard-" "root" "660")
        cur_state+="/plugins/search-guard-: $result_plugins_search_guard_; "
        case "$result_plugins_search_guard_" in
            VULN*) vuln_found=true; detail+="/plugins/search-guard- 소유자/권한 부적절($result_plugins_search_guard_). " ;;
            GOOD*) detail+="/plugins/search-guard- 소유자/권한 적절($result_plugins_search_guard_). " ;;
            NOT_FOUND) detail+="/plugins/search-guard- 파일 없음. " ;;
        esac
    else
        detail+="/plugins/search-guard- 파일 없음. "
        cur_state+="/plugins/search-guard-: 파일 없음; "
    fi
    if [ -e "/sgconfig" ]; then
        local result_sgconfig
        result_sgconfig=$(check_file_owner_perm "/sgconfig" "root" "660")
        cur_state+="/sgconfig: $result_sgconfig; "
        case "$result_sgconfig" in
            VULN*) vuln_found=true; detail+="/sgconfig 소유자/권한 부적절($result_sgconfig). " ;;
            GOOD*) detail+="/sgconfig 소유자/권한 적절($result_sgconfig). " ;;
            NOT_FOUND) detail+="/sgconfig 파일 없음. " ;;
        esac
    else
        detail+="/sgconfig 파일 없음. "
        cur_state+="/sgconfig: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="설정 파일 권한이 660\(-rw-rw----\)" && cur_state="점검 대상 파일 없음"

    add_result "CLD-Elasticsearch-07" "디렉터리 및" "설정 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-08: Search-Guard 스크립트 접근 권한 설정
check_CLD_Elasticsearch_08() {
    local status="양호"
    local detail=""
    local cmd="ls -l /plugins/search-guard-*/tools"
    local cur_state=""
    local remediation="￭ Search-guard 스크립트 파일 권한을 750 이하로 변경 1\) chmod 750 [Elasticsearch 디렉터리]/plugins/search-guard-*/tools/[Search- Guard 스크립트 파일]"

    local output
    output=$(ls -l /plugins/search-guard-*/tools 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Elasticsearch-08" "디렉터리 및" "Search-Guard 스크립트 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-09: 로그 활성화
check_CLD_Elasticsearch_09() {
    local status="양호"
    local detail=""
    local cmd="cat /elasticsearch.yml | grep xpack.security.audit"
    local cur_state=""
    local remediation="￭ 감사로그 활성화 \(Elasticsearch v7.0 이상 X-pack 사용\) 1\) # vi [Elasticsearch 설정 디렉터리]/elasticsearch.yml에 아래 내용 추가 2\) elasticsearch 재시작 3\) /var/log/elasticsearch 내 감사 로그 파일 생성 확인"

    local config_file="/elasticsearch.yml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "xpack.security.audit" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: xpack.security.audit 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Elasticsearch-09" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Elasticsearch-10: 최신 보안 패치 적용
check_CLD_Elasticsearch_10() {
    local status="양호"
    local detail=""
    local cmd="/bin/elasticsearch -v; curl localhost:9200"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 보안 취약점이 존재하지 않는 버전으로 보안 패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local api_result
    api_result=$(curl localhost:9200 2>/dev/null)
    if [ -n "$api_result" ]; then
        cur_state="$api_result"
        detail="API 응답 확인됨. 수동 검증 필요. "
        status="수동점검"
    else
        cur_state="API 응답 없음"
        detail="API 호출 실패 또는 서비스 미실행. "
        status="N/A"
    fi

    add_result "CLD-Elasticsearch-10" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Elasticsearch CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/10] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Elasticsearch-01"; check_CLD_Elasticsearch_01
progress "CLD-Elasticsearch-02"; check_CLD_Elasticsearch_02
progress "CLD-Elasticsearch-03"; check_CLD_Elasticsearch_03
progress "CLD-Elasticsearch-04"; check_CLD_Elasticsearch_04
progress "CLD-Elasticsearch-05"; check_CLD_Elasticsearch_05
progress "CLD-Elasticsearch-06"; check_CLD_Elasticsearch_06
progress "CLD-Elasticsearch-07"; check_CLD_Elasticsearch_07
progress "CLD-Elasticsearch-08"; check_CLD_Elasticsearch_08
progress "CLD-Elasticsearch-09"; check_CLD_Elasticsearch_09
progress "CLD-Elasticsearch-10"; check_CLD_Elasticsearch_10

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
    echo '    "platform": "Elasticsearch",'
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

echo "===== Elasticsearch CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
