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

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_node.js_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Pre-flight: Node.js 설치 확인 및 경로 탐지 ---
NODE_BIN=""
NPM_BIN=""
NODE_MAIN="${NODE_MAIN:-}"
NODE_APP_ROOT="${NODE_APP_ROOT:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NODE_BIN=$(command -v node 2>/dev/null)
    NPM_BIN=$(command -v npm 2>/dev/null)

    # 2) 프로세스에서 node 탐지
    local node_proc
    node_proc=$(get_process_snapshot 'node ' | head -1)
    if [ -n "$node_proc" ]; then
        APP_FOUND="true"
        if [ -z "$NODE_MAIN" ]; then
            NODE_MAIN=$(printf '%s
' "$node_proc" | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.js$/) {print $i; exit}}')
        fi
        if [ -n "$NODE_MAIN" ]; then
            NODE_APP_ROOT=$(dirname "$NODE_MAIN")
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
    if [ -z "$NODE_MAIN" ]; then
        for f in /workspace/app.js /workspace/server.js /workspace/docker/test-lab/fixtures/node/server.js; do
            if [ -f "$f" ]; then
                NODE_MAIN="$f"
                NODE_APP_ROOT=$(dirname "$f")
                break
            fi
        done
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
    if [ -n "$NODE_BIN" ] || [ -n "$NODE_MAIN" ]; then
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


# CSAP-NodeJS-01: node 프로세스 권한 제한
check_CSAP_NodeJS_01() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep node | grep -v grep"
    local cur_state=""
    local remediation="￭ root 계정 이외의 계정으로 node 프로세스 실행 1\) # set DEBU=www & npm start dev ￭ production 모드로 변경 1\) # export NODE_ENV=production"

    local output
    output=$({
        ( get_process_snapshot "node" )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="Node 애플리케이션이 root 권한으로 구동"
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
        if printf '%s\n' "$output" | awk 'NR == 1 && $1 == "UID" {next} $1 == "root" {found=1} END {exit found ? 0 : 1}'; then
            status="취약"
            detail="Node 애플리케이션이 root 권한으로 구동"
        elif printf '%s\n' "$output" | grep -Eiq "production|node_env|environment=production|user[[:space:]]*=[[:space:]]*[a-z0-9_-]+"; then
            status="양호"
            detail="Node 애플리케이션이 전용 계정으로 구동"
        else
            status="수동점검"
            detail="비root 구동 여부는 확인했지만 production 모드 여부 자동 판정에는 추가 문맥이 필요합니다. "
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-NodeJS-01" "로그 및 패치 관리" "node 프로세스 권한 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-NodeJS-02: 헤더 정보 노출 방지
check_CSAP_NodeJS_02() {
    local status="양호"
    local detail=""
    local cmd="cat app.js"
    local cur_state=""
    local remediation="￭ node 메인 파일에 헤더 정보 노출 설정 추가 예시\) 1\) # vi app.js"

    local config_file="${NODE_MAIN:-app.js}"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -Ei "app\\.disable\\\([[:space:]]*[\\\"\\']x-powered-by[\\\"\\']|helmet\\\(|x-powered-by" "$actual_config" 2>/dev/null)
        output="$grep_result"
        cur_state="$grep_result"
    if [ -z "$output" ]; then
        status="양호"
        detail="헤더 정보 노출 방지 설정이 적용된 경우"
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
        if printf '%s\n' "$output" | grep -Eiq "app\.disable\([[:space:]]*[\"\']x-powered-by[\"\']|helmet\(|server_tokens[[:space:]]+off|servertokens[[:space:]]+prod|serversignature[[:space:]]+off|expose_php[[:space:]]*=[[:space:]]*off"; then
            status="양호"
            detail="헤더 정보 노출 방지 설정이 적용된 경우"
        elif printf '%s\n' "$output" | grep -Eiq "x-powered-by|server_tokens[[:space:]]+on|expose_php[[:space:]]*=[[:space:]]*on"; then
            status="취약"
            detail="헤더 정보 노출 방지 설정이 적용되어 있지"
        else
            status="수동점검"
            detail="헤더 정보 노출 방지 설정이 적용된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"
    fi

    add_result "CSAP-NodeJS-02" "보안 설정" "헤더 정보 노출 방지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-NodeJS-03: 오류 메시지 설정
check_CSAP_NodeJS_03() {
    local status="양호"
    local detail=""
    local cmd="cat app.js; cat views/error.jade"
    local cur_state=""
    local remediation="￭ 일원화된 오류 메시지 설정 예시\) 1\) # vi views/error/jade ￭ 에러 내용을 알 수 없는 일원화된 오류 메시지"

    local output
    output=$({
        ( cat app.js )
        ( cat views/error.jade )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="필수 에러 코드를 유추 불가능하도록"
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
            detail="필수 에러 코드를 유추 불가능하도록"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="필수 에러 코드를 유추 불가능하도록"
        else
            status="취약"
            detail="필수 에러 코드를 유추 불가능하도록"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-NodeJS-03" "보안 설정" "오류 메시지 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-NodeJS-04: 로그 디렉터리 및 파일 권한 설정
check_CSAP_NodeJS_04() {
    local status="양호"
    local detail=""
    local cmd="ls -ld; ls -ld"
    local cur_state=""
    local remediation="￭ 로그 디렉터리 및 로그 파일 접근 권한 변경 1\) 로그 디렉터리 접근 권한 변경 # chown nodeLnode [node 애플리케이션 로그 디렉터리] # chown 750 [node 애플리케이션 로그 디렉터리] ￭ 로그 파일 접근 권한 변경 # chown node:node [node 애플리케이션 로그 파일] # chmod 640 [node 애플리케이션 로그 디렉터리]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=${NODE_APP_ROOT:-/workspace}/logs
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "750")
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
    target_spec_2=${NODE_APP_ROOT:-/workspace}/log
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "750")
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="로그 디렉터리 및 파일의 소유자가 node" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-NodeJS-04" "보안 설정" "로그 디렉터리 및 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-NodeJS-05: 로그 포맷 설정
check_CSAP_NodeJS_05() {
    local status="양호"
    local detail=""
    local cmd="cat app.js"
    local cur_state=""
    local remediation="￭ 실시간 콘솔 로그 설정 예시\) Express의 Morgan 모듈을 사용하는 경우 1\) # vi app.js var logger = require\('morgan'\); ... 중간 생략 ... app.use\(logger\('combined'\)\) ￭ 로그 파일 저장 설정 예시\) Express의 Morgan 모듈을 사용하는 경우 1\) # vi app.js var fs = require\('fs'\); ... 중간 생략 ... app.use\(logger\({ format: 'default', stream: fs.createWriteStream\('./log/app.log', {'flags': 'w'}\) }\)\);"

    local output
    output=$({
        ( cat app.js )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="로그 포맷 설정값이 default\(또는"
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
            detail="로그 포맷 설정값이 default\(또는"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="로그 포맷 설정값이 default\(또는"
        else
            status="취약"
            detail="로그 포맷 설정값이 default\(또는"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-NodeJS-05" "로그 및 패치 관리" "로그 포맷 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-NodeJS-06: 로그 파일 보관 및 주기적 백업
check_CSAP_NodeJS_06() {
    local status="양호"
    local detail=""
    local cmd="base=\${NODE_APP_ROOT:-/workspace/docker/test-lab/fixtures/node}; if [ -d \"\$base\" ]; then out=\$\(find \"\$base\" -maxdepth 2 \\\( -name logs -o -name '*.log' \\\) 2>/dev/null | head -20\); if [ -n \"\$out\" ]; then printf '%s\\n' \"\$out\"; else echo \"DEFAULT_BAD|로그 파일 또는 로그 디렉터리를 찾지 못했습니다.\"; fi; else echo \"FILE_MISSING|점검 대상 경로를 찾지 못했습니다.\"; fi"
    local cur_state=""
    local remediation="￭ 사용자 접속 기록 보관 기간은 '정보통신망 이용 촉진 및 정보보호 등에 관한 법률', '개인정보보호법'등 관련 법률에 근거하여 보관하여야 함 1\) 개인정보 처리 시스템인 경우 접속 기록 보관 주기 : 1년 이상\(5만 명 이상의 정보 주체에 관하여 개인정보를 처리하거나, 민감 정보를 처리하는 경우에는 2년 이상\) 접속 기록에 대한 주기적 점검 : 월 1회 이상 백업 수행 주기 : 개인정보 처리 시스템 외의 별도 저장 장치에 상시로 접속 기록 백업 백업 보관 주기 : 관련 사항 없음\(재해복구 관점 고려\) 2\) 로그 백업 정책에 따라 로그 파일을 정기적으로 백업을 수행"

    local output
    output=$({
        ( base=${NODE_APP_ROOT:-/workspace/docker/test-lab/fixtures/node}; if [ -d "$base" ]; then out=$(find "$base" -maxdepth 2 \( -name logs -o -name '*.log' \) 2>/dev/null | head -20); if [ -n "$out" ]; then printf '%s\n' "$out"; else echo "DEFAULT_BAD|로그 파일 또는 로그 디렉터리를 찾지 못했습니다."; fi; else echo "FILE_MISSING|점검 대상 경로를 찾지 못했습니다."; fi )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="로그 보관 주기를 준수하고 주기적으로"
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

    add_result "CSAP-NodeJS-06" "로그 및 패치 관리" "로그 파일 보관 및 주기적 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-NodeJS-07: 최신 보안 패치 적용
check_CSAP_NodeJS_07() {
    local status="양호"
    local detail=""
    local cmd="rpm -qa | grep nodejs; node -v; npm -v"
    local cur_state=""
    local remediation="￭ Node.js 사이트를 통해 주기적으로 버전 점검을 하도록 하며 최신 보안 패치 적용 시 충분한 테스트 후 적용 ￭ NPM 최신 보안 패치 업데이트 1\) npm 업데이트 # npm install –g npm 2\) 업데이트 후 npm 버전 확인 ￭ Express 최신 버전 업데이트 # npm install express"

    local output
    output=$({
        ( get_process_snapshot "nodejs" )
        ( node -v )
        ( npm -v )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="최신 보안 패치를 적용한 경우"
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

    add_result "CSAP-NodeJS-07" "로그 및 패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Node.js CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/7] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-NodeJS-01"; check_CSAP_NodeJS_01
progress "CSAP-NodeJS-02"; check_CSAP_NodeJS_02
progress "CSAP-NodeJS-03"; check_CSAP_NodeJS_03
progress "CSAP-NodeJS-04"; check_CSAP_NodeJS_04
progress "CSAP-NodeJS-05"; check_CSAP_NodeJS_05
progress "CSAP-NodeJS-06"; check_CSAP_NodeJS_06
progress "CSAP-NodeJS-07"; check_CSAP_NodeJS_07

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
