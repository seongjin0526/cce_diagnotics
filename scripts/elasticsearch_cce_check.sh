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

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_elasticsearch_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Elasticsearch helper ---
ES_URL="${ES_URL:-http://localhost:9200}"

run_es_api() {
    local endpoint="$1"
    curl -s -m 10 "${ES_URL}${endpoint}" 2>/dev/null
}


# --- Pre-flight: Elasticsearch 설치 확인 및 경로 탐지 ---
ES_CONF="${ES_CONF:-}"
ES_URL="${ES_URL:-http://localhost:9200}"
APP_FOUND="false"

detect_app() {
    local es_bin
    es_bin=$(command -v elasticsearch 2>/dev/null)

    # 1) curl 로 ES 응답 확인
    local es_response
    es_response=$(curl -s -m 5 "$ES_URL" 2>/dev/null)
    if echo "$es_response" | grep -q '"tagline"'; then
        APP_FOUND="true"
    fi

    # 2) 프로세스에서 탐지
    local es_proc
    es_proc=$(ps -ef 2>/dev/null | grep '[e]lasticsearch' | grep -v grep | head -1)
    if [ -n "$es_proc" ]; then
        APP_FOUND="true"
        # -Epath.conf 추출
        local conf_from_proc
        conf_from_proc=$(echo "$es_proc" | grep -oP '\-Epath\.conf=\K[^ ]+' | head -1)
        if [ -n "$conf_from_proc" ] && [ -d "$conf_from_proc" ]; then
            ES_CONF="$conf_from_proc/elasticsearch.yml"
        fi
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$ES_CONF" ]; then
        for f in /etc/elasticsearch/elasticsearch.yml /usr/local/etc/elasticsearch/elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml; do
            if [ -f "$f" ]; then
                ES_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ "$APP_FOUND" = "false" ] && [ -z "$es_bin" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'elasticsearch' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'elasticsearch' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$es_bin" ] || [ -n "$ES_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Elasticsearch 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Elasticsearch-01: Elasticsearch 인증 설정
check_CSAP_Elasticsearch_01() {
    local status="양호"
    local detail=""
    local cmd="cat /x-pack/users; cat /users; cat /search-guard-/sgconfig/sg_internal_"
    local cur_state=""
    local remediation="￭ X-Pack 플러그인을 통해 설정 - Elasticsearch v5.x, v6.x 1) # [Elasticsearch 설치 디렉터리/bin/x-pack] ./users useradd '계정명' -r '계정권한' 실행 - Elasticsearch v7.0 이상 1) # vi [Elasticsearch 설정 디렉터리/elasticsearch.yml] 2) security 필드에 아래의 내용 추가 3) # [Elasticsearch 설치 디렉터리]/bin/elasticsearch-setup-passwords interactive 4) 사용자 계정 인증 및 인증 창 확인 # curl --user '사용자 계정':'패스워드' localhost:9200 입력 또는 검색창에 http://localhost:9200 입력 ￭ Search-Guard 플러그인을 통해 설정 - Elasticsearch v5.0 이상 1) # cd [Elasticsearch 설치 디렉터리]/bin/search-guard-*/tools를 통해 디렉터리 이동 2) # ./hash.sh 명령어를 통해 패스워드 해시값 생성 3) 출력된 해시값과 계정명을 [Elasticsearch 설치 디렉터리]/plugin/search-guard-*/ sgconfig/sg_internal_users.yml 설정 파일에 기입 ※ 띄어쓰기에 민감하므로 아래 예시된 그림과 같이 라인 간격을 맞춰야 함 4) [Elasticsearch 설치 디렉터리/bin/search-guard-*/sgconfig/sg_roles_mapping. yml 설정 파일에서 role과 계정 매핑 5) [Elasticsearch 설치 디렉터리/bin/search-guard-*/tools/sgadmin_demo.sh 스크립트를 실행하여 설정 적용"

    local output
    output=$({
        ( curl localhost:9200 )
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
            detail="인증 아이디 및 패스워드가 설정되어 있는"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="인증 아이디 및 패스워드가 설정되어 있는"
        else
            status="취약"
            detail="인증 아이디 및 패스워드가 설정되어 있는"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Elasticsearch-01" "패치 및 로그 관리" "Elasticsearch 인증 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-02: 디폴트 계정 및 패스워드 변경
check_CSAP_Elasticsearch_02() {
    local status="양호"
    local detail=""
    local cmd="curl -u test:test123 -XGET http://localhost:9200/_xpack_security/user"
    local cur_state=""
    local remediation="￭ 디폴트 계정 삭제/비활성화 (X-Pack 사용 시) 1) 디폴트 계정을 비활성화하기 전 새로운 계정 생성 2) 관리자 권한 부여 3) 디폴트 계정 비활성화 ￭ 디폴트 계정 삭제/비활성화 (Search-Guard 사용 시) 1) 디폴트 계정을 비활성화하기 전 새로운 계정 생성 2) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/sgconfig/sg_internal_ users.yml 파일을 수정하여 기존 관리자 계정 영역 삭제 및 신규 계정 및 패스워드 적용 3) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/sgconfig/sg_roles_ mapping.yml 파일을 수정하여 기존 관리자 계정 삭제 및 신규 계정 적용"

    local output
    output=$({
        ( curl -u test:test123 -XGET http://localhost:9200/_xpack_security/user )
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
            detail="디폴트 계정 및 패스워드를 변경한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="디폴트 계정 및 패스워드를 변경하지 않은"
        else
            status="취약"
            detail="디폴트 계정 및 패스워드를 변경하지 않은"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Elasticsearch-02" "보안 설정" "디폴트 계정 및 패스워드 변경" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-03: 불필요한 계정 제거
check_CSAP_Elasticsearch_03() {
    local status="양호"
    local detail=""
    local cmd="cat /x-paxk/user_roles; /bin/x-pack/elasticsearch-users list; cat /users_roles"
    local cur_state=""
    local remediation="- Elasticsearch v5.x, v6.x (X-Pack 플러그인 사용 시) 1) # [Elasticsearch 설치 디렉터리]/bin/x-pack/users userdel '계정명' 실행 - Elasticsearch v7.0 이상 (X-Pack 플러그인 사용 시) 1) # [Elasticsearch 설치 디렉터리]/bin/elasticsearch-users userdel <사용자 명> ￭ 설정 파일 및 명령어를 통해 변경 (SearchGuard 사용 시) - Elasticsearch 5.0 이상 SearchGuard 플러그인 사용 시 1) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/sgconfig/sg_roles_ mapping.yml 파일을 수정하여 불필요한 계정 제거 2) # [Elasticsearch 설치 디렉터리]/plugins/search-guard-*/tools/sgadmin_demo. sh을 실행하여 설정 적용"

    local output
    output=$({
        ( cat /x-paxk/user_roles )
        ( /bin/x-pack/elasticsearch-users list )
        ( cat /users_roles )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="테스트 계정, 의심스러운 계정, 불필요한"
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

    add_result "CSAP-Elasticsearch-03" "보안 설정" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-04: IP 접근 제한 설정
check_CSAP_Elasticsearch_04() {
    local status="양호"
    local detail=""
    local cmd="cat /elasticsearch.yml | grep network.host"
    local cur_state=""
    local remediation="￭ Elasticsearch 설정 파일 안의 network.host 설정 변경 1) # vi cat [Elasticsearch 디렉터리]/elasticsearch.yml 2) network.host 인가된 IP로 변경"

    cmd="grep -En \"network.host|http.host\" ${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}"
    local cfg
    cfg="${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}"
    if [ -f "$cfg" ]; then
        local output
        output=$(grep -Ein "network.host|http.host" "$cfg" 2>/dev/null | head -20)
        cur_state="${output:-설정 파일에서 관련 항목을 찾지 못함}"
        if printf '%s\n' "$output" | grep -Eiq "0\.0\.0\.0|::|_site_|_global_"; then
            status="취약"
            detail="Elasticsearch가 전체 인터페이스에 바인드되어 있습니다."
        elif [ -n "$output" ]; then
            status="양호"
            detail="Elasticsearch 접근 제한 관련 설정을 수집했습니다."
        else
            status="수동점검"
            detail="network.host/http.host 설정을 찾지 못했습니다. 기본 동작과 운영 환경을 함께 확인해야 합니다."
        fi
    else
        cur_state="Elasticsearch 설정 파일을 찾지 못했습니다."
        detail="Elasticsearch 설정 파일 경로를 자동으로 확인하지 못했습니다."
        status="N/A"
    fi

    add_result "CSAP-Elasticsearch-04" "보안 설정" "IP 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-05: 설치 디렉터리 접근 권한 설정
check_CSAP_Elasticsearch_05() {
    local status="양호"
    local detail=""
    local cmd="ls -ld"
    local cur_state=""
    local remediation="￭ Elasticsearch 설치 디렉터리 권한 750으로 변경 1) # chmod 750 [Elasticsearch 설치 디렉터리]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "750")
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
    [ -z "$detail" ] && detail="설치 디렉터리의 권한이 750(-rwxr-x---)" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Elasticsearch-05" "디렉터리 및" "설치 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-06: 플러그인 디렉터리 접근 권한 설정
check_CSAP_Elasticsearch_06() {
    local status="양호"
    local detail=""
    local cmd="ls -ld /plugins"
    local cur_state=""
    local remediation="￭ Elasticsearch 플러그인 디렉터리 권한 750으로 변경 1) # chmod 750 [Elasticsearch 설치 디렉터리]/plugins"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/plugins
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "750")
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
    local target_spec_2
    target_spec_2=$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "750")
                cur_state+="$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_2). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")/plugins
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "" "750")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_3). " ;;
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
    [ -z "$detail" ] && detail="플러그인 디렉터리 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Elasticsearch-06" "디렉터리 및" "플러그인 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-07: 설정 파일 접근 권한 설정
check_CSAP_Elasticsearch_07() {
    local status="양호"
    local detail=""
    local cmd="ls -l /elasticsearch.yml; ls -l /plugins/search-guard-*/sgconfig"
    local cur_state=""
    local remediation="￭ 설정 파일의 권한을 660 이하로 변경 1) # chmod 660 [Elasticsearch 디렉터리/elasticsearch.yml]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/plugins/search-guard-*/sgconfig
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "660")
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
    local target_spec_2
    target_spec_2=${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "660")
                cur_state+="$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_2). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "" "660")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_3). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")/plugins/search-guard-*/tools
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "" "660")
                cur_state+="$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_4). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_4). " ;;
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
    [ -z "$detail" ] && detail="설정 파일 권한이 660(-rw-rw----)" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Elasticsearch-07" "디렉터리 및" "설정 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-08: Search-Guard 스크립트 접근 권한 설정
check_CSAP_Elasticsearch_08() {
    local status="양호"
    local detail=""
    local cmd="ls -l /plugins/search-guard-*/tools"
    local cur_state=""
    local remediation="￭ Search-guard 스크립트 파일 권한을 750 이하로 변경 1) chmod 750 [Elasticsearch 디렉터리]/plugins/search-guard-*/tools/[Search- Guard 스크립트 파일]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/plugins/search-guard-*/tools
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "750")
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
    local target_spec_2
    target_spec_2=${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "750")
                cur_state+="$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_2). " ;;
                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;
                esac
            else
                detail+="$target_path 파일 없음. "
                cur_state+="$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")/plugins/search-guard-*/tools
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "" "750")
                cur_state+="$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_3). " ;;
                    GOOD*) detail+="$target_path 권한 적절($result_3). " ;;
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
    [ -z "$detail" ] && detail="Search-guard 스크립트 파일 권한이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Elasticsearch-08" "디렉터리 및" "Search-Guard 스크립트 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-09: 로그 활성화
check_CSAP_Elasticsearch_09() {
    local status="양호"
    local detail=""
    local cmd="cat /elasticsearch.yml | grep xpack.security.audit"
    local cur_state=""
    local remediation="￭ 감사로그 활성화 (Elasticsearch v7.0 이상 X-pack 사용) 1) # vi [Elasticsearch 설정 디렉터리]/elasticsearch.yml에 아래 내용 추가 2) elasticsearch 재시작 3) /var/log/elasticsearch 내 감사 로그 파일 생성 확인"

    cmd="ls -ld ${ES_LOG_DIR:-/usr/share/elasticsearch/logs}; ls ${ES_LOG_DIR:-/usr/share/elasticsearch/logs}/*.log"
    local log_dir="${ES_LOG_DIR:-/usr/share/elasticsearch/logs}"
    if [ -d "$log_dir" ]; then
        local output
        output=$(ls -1 "$log_dir" 2>/dev/null | head -20)
        cur_state="${output:-로그 디렉터리 존재}"
        if printf '%s\n' "$output" | grep -Eiq "\.log$|gc\.log"; then
            status="양호"
            detail="Elasticsearch 로그 파일이 생성되고 있습니다."
        else
            status="수동점검"
            detail="로그 디렉터리는 존재하지만 Elasticsearch 로그 파일 존재 여부를 추가 확인해야 합니다."
        fi
    else
        cur_state="로그 디렉터리 없음"
        detail="Elasticsearch 로그 디렉터리를 찾지 못했습니다."
        status="N/A"
    fi

    add_result "CSAP-Elasticsearch-09" "패치 및 로그 관리" "로그 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Elasticsearch-10: 최신 보안 패치 적용
check_CSAP_Elasticsearch_10() {
    local status="양호"
    local detail=""
    local cmd="/bin/elasticsearch -v; curl localhost:9200"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 보안 취약점이 존재하지 않는 버전으로 보안 패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( curl localhost:9200 )
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

    add_result "CSAP-Elasticsearch-10" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Elasticsearch CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/10] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Elasticsearch-01"; check_CSAP_Elasticsearch_01
progress "CSAP-Elasticsearch-02"; check_CSAP_Elasticsearch_02
progress "CSAP-Elasticsearch-03"; check_CSAP_Elasticsearch_03
progress "CSAP-Elasticsearch-04"; check_CSAP_Elasticsearch_04
progress "CSAP-Elasticsearch-05"; check_CSAP_Elasticsearch_05
progress "CSAP-Elasticsearch-06"; check_CSAP_Elasticsearch_06
progress "CSAP-Elasticsearch-07"; check_CSAP_Elasticsearch_07
progress "CSAP-Elasticsearch-08"; check_CSAP_Elasticsearch_08
progress "CSAP-Elasticsearch-09"; check_CSAP_Elasticsearch_09
progress "CSAP-Elasticsearch-10"; check_CSAP_Elasticsearch_10

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
