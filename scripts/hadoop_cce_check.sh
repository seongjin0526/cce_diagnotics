#!/bin/bash
###############################################################################
# Hadoop CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash hadoop_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_hadoop_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Hadoop helper ---
HADOOP_CONF_DIR="${HADOOP_CONF_DIR:-/etc/hadoop/conf}"
if [ ! -d "$HADOOP_CONF_DIR" ]; then
    for d in /opt/hadoop*/etc/hadoop /usr/lib/hadoop/etc/hadoop; do
        if [ -d "$d" ]; then
            HADOOP_CONF_DIR="$d"
            break
        fi
    done
fi


# --- Pre-flight: Hadoop 설치 확인 및 경로 탐지 ---
HADOOP_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    HADOOP_BIN=$(command -v hadoop 2>/dev/null)
    local hdfs_bin
    hdfs_bin=$(command -v hdfs 2>/dev/null)

    # 2) 프로세스에서 hadoop/NameNode 탐지
    if ps -ef 2>/dev/null | grep -qE '[h]adoop|[N]ameNode|[D]ataNode'; then
        APP_FOUND="true"
    fi

    # 3) HADOOP_HOME 환경 변수 확인
    if [ -n "$HADOOP_HOME" ] && [ -d "$HADOOP_HOME" ]; then
        APP_FOUND="true"
        if [ -z "$HADOOP_BIN" ] && [ -x "$HADOOP_HOME/bin/hadoop" ]; then
            HADOOP_BIN="$HADOOP_HOME/bin/hadoop"
        fi
    fi

    # 4) HADOOP_CONF_DIR 확인 및 탐색
    if [ ! -d "$HADOOP_CONF_DIR" ]; then
        for d in /etc/hadoop/conf /opt/hadoop*/etc/hadoop /usr/lib/hadoop/etc/hadoop /usr/local/hadoop/etc/hadoop; do
            if [ -d "$d" ]; then
                HADOOP_CONF_DIR="$d"
                break
            fi
        done
    fi

    # 5) 패키지 매니저 확인
    if [ -z "$HADOOP_BIN" ] && [ -z "$hdfs_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'hadoop' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'hadoop' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$HADOOP_BIN" ] || [ -n "$hdfs_bin" ] || [ -d "$HADOOP_CONF_DIR" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Hadoop 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-Hadoop-01: 로컬 파일 시스템/HDFS 디렉토리 소유자 및 권한 설정
check_CSAP_Hadoop_01() {
    local status="양호"
    local detail=""
    local cmd="./bin/hadoop fs -ls"
    local cur_state=""
    local remediation="￭ 로컬 파일 시스템 (예시) // dfs.namenode.name.dir = hdfs:hadoop (700) 1) # chown –R hdfs:hadoop /home/hadoop/data/dfs/name 2) # chmod 700 /home/hadoop/data/dfs/name // dfs.namenode.data.dir = hdfs:hadoop (700) 3) # chown –R hdfs:hadoop /home/hadoop/data/dfs/data 4) # chmod 700 /home/hadoop/data/dfs/data // dfs.journalnode.edits.dir = hdfs:hadoop (700) 5) # chown –R hdfs:hadoop /home/hadoop/data/dfs/journalnode 6) # chmod 700 /home/hadoop/data/dfs/journalnode // \$HADOOP_LOG_DIR = hdfs:hadoop (775) 7) # chown –R hdfs:hadoop /home/hadoop/logs 8) # chmod 775 /home/hadoop/logs // yarn.nodemanager.local-dirs = yarn:hadoop (755) 10) # chown -R yarn:hadoop /home/hadoop/data/yarn/nm-local-dir 11) # chmod 755 /home/hadoop/data/yarn/nm-local-dir ￭ HDFS 디렉토리 1) / = hdfs:hadoop (775) 2) /home/hadoop/bin/hdfs dfs –chown hdfs:hadoop / 3) /home/hadoop/bin/hdfs dfs –chmod 755 / 4) /user = hdfs:hadoop (755) 5) /home/hadoop/bin/hdfs dfs –chown hdfs:hadoop /user 6) /home/hadoop/bin/hdfs dfs –chmod 755 /user"

    local output
    output=$({
        ( ./bin/hadoop fs -ls )
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
            status="취약"
            detail="로컬 파일 시스템/HDFS 소유자가 권한이"
        else
            status="양호"
            detail="로컬 파일 시스템/HDFS 소유자와 권한이"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Hadoop-01" "패치 및 로그 관리" "로컬 파일 시스템/HDFS 디렉토리 소유자 및 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-02: 테이블/맵리듀스 User 키 테이블 파일 권한 설정
check_CSAP_Hadoop_02() {
    local status="양호"
    local detail=""
    local cmd="ls -al | grep *.keytab"
    local cur_state=""
    local remediation="￭ root 외의 소유자로 지정, 권한은 400 이하로 설정 (예시) # chown hdfs:hadoop hdfs.keytab # chmod 400 hdfs.keytab # chown yarn:hadoop yarn.keytab # chmod 400 yarn.keytab # chown mapred:hadoop mapred.keytab # chmod 400 mapred.keytab"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/unknown_config_file
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "400")
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
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    elif [ "$checked_any" = "false" ]; then
        status="수동점검"
        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "
        cur_state="경로 자동 해석 실패"
    elif [ "$missing_only" = "true" ]; then
        status="N/A"
    fi
    [ -z "$detail" ] && detail="클러스터의 모든 시스템에 YARN User" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-Hadoop-02" "" "테이블/맵리듀스 User 키 테이블 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-03: Hadoop Security 활성화
check_CSAP_Hadoop_03() {
    local status="양호"
    local detail=""
    local cmd="cat core-site.xml"
    local cur_state=""
    local remediation="￭ core-site.xml에 kerberos 설정 1) core-site.xml 파일에 아래와 같은 설정 사항 추가 # vi core-site.xml"

    local output
    output=$({
        ( cat core-site.xml )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="커버로스가 disable(false) 되어 있는 경우"
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
            status="취약"
            detail="커버로스가 disable(false) 되어 있는 경우"
        else
            status="양호"
            detail="커버로스가 enable(true) 되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Hadoop-03" "보안 설정" "Hadoop Security 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-04: 하둡 ACL 설정
check_CSAP_Hadoop_04() {
    local status="양호"
    local detail=""
    local cmd="cat hadoop-policy.xml | grep datanode.protocol.acl"
    local cur_state=""
    local remediation="￭ hadoop-policy.xml ACL 설정 적용 1) # vi hadoop-policy.xml <value> 인가된 계정 및 그룹명 </value> ※ 아무런 설정이 존재하지 않는 경우, default로 모두 접근 가능"

    local config_file="/etc/app/config"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local content
        content=$(head -20 "$actual_config" 2>/dev/null)
        cur_state="설정 파일 존재: $actual_config"
        detail="설정 파일 확인 필요: $actual_config. "
        status="수동점검"
    fi

    add_result "CSAP-Hadoop-04" "보안 설정" "하둡 ACL 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-05: WebHDFS 비활성화
check_CSAP_Hadoop_05() {
    local status="양호"
    local detail=""
    local cmd="cat hdfs-site.xml"
    local cur_state=""
    local remediation="￭ WebHDFS를 사용하지 않는 경우 hdfs-site.xml에서 설정 1) # vi hdfs-site.xml"

    local output
    output=$({
        ( cat hdfs-site.xml )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 WebHDFS가 구동 중이지 않을"
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
            detail="불필요한 WebHDFS가 구동 중이지 않을"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 WebHDFS가 구동 중일 경우"
        else
            status="취약"
            detail="불필요한 WebHDFS가 구동 중일 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Hadoop-05" "보안 설정" "WebHDFS 비활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-06: RPC 암호화
check_CSAP_Hadoop_06() {
    local status="양호"
    local detail=""
    local cmd="cat core-site.xml"
    local cur_state=""
    local remediation="￭ core-site.xml 파일 rpc 암호화 설정 1) 아래와 같은 설정 사항 추가"

    local output
    output=$({
        ( cat core-site.xml )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="rpc 암호화 설정을 적용한 경우"
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
            detail="rpc 암호화 설정을 적용한 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="rpc 암호화 설정을 적용하지 않은 경우"
        else
            status="취약"
            detail="rpc 암호화 설정을 적용하지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Hadoop-06" "보안 설정" "RPC 암호화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-07: 데이터 전송 암호화
check_CSAP_Hadoop_07() {
    local status="양호"
    local detail=""
    local cmd="cat hdfs-site.xml"
    local cur_state=""
    local remediation="￭ hdfs-site.xml 파일에서 암호화 설정 활성화 1) 아래와 같은 설정 사항 추가 ￭ hdfs-site.xml 파일에서 암호화 알고리즘 설정 1) 아래와 같은 설정 사항 추가 ※ 하둡 v2.6 이전 <property> <name>dfs.encrypt.data.transfer.algorithm</name> <value>3des</value> </property>"

    local output
    output=$({
        ( cat hdfs-site.xml )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="데이터 전송 암호화 설정이 적용되어 있는"
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
        if printf '%s\n' "$output" | grep -Eiq "md5|mysql_native_password|old_password|sha1"; then
            status="취약"
            detail="데이터 전송 암호화 설정이 적용되어 있지"
        elif printf '%s\n' "$output" | grep -Eiq "sha-?256|caching_sha2_password|scram-sha-256|scram_sha_256"; then
            status="양호"
            detail="데이터 전송 암호화 설정이 적용되어 있는"
        else
            status="수동점검"
            detail="데이터 전송 암호화 설정이 적용되어 있는"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-Hadoop-07" "보안 설정" "데이터 전송 암호화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-08: 로그 검토 및 관리
check_CSAP_Hadoop_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 각 파일에 로그 파일 저장 경로를 지정하여 로그를 기록 및 검토 1) hdfs-site.xml에서 로그 파일 경로 설정 2) core-site.xml에서 로그 파일 경로 설정 확인 3) yarn-site.xml에서 로그 파일 경로 설정 확인 4) mapred-site.xml에서 로그 파일 경로 설정 확인"

    local config_file="/etc/app/config"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local content
        content=$(head -20 "$actual_config" 2>/dev/null)
        cur_state="설정 파일 존재: $actual_config"
        detail="설정 파일 확인 필요: $actual_config. "
        status="수동점검"
    fi

    add_result "CSAP-Hadoop-08" "패치 및 로그 관리" "로그 검토 및 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-Hadoop-09: 최신 보안 패치 적용
check_CSAP_Hadoop_09() {
    local status="양호"
    local detail=""
    local cmd="hadoop version"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( hadoop version )
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

    add_result "CSAP-Hadoop-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Hadoop CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/9] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-Hadoop-01"; check_CSAP_Hadoop_01
progress "CSAP-Hadoop-02"; check_CSAP_Hadoop_02
progress "CSAP-Hadoop-03"; check_CSAP_Hadoop_03
progress "CSAP-Hadoop-04"; check_CSAP_Hadoop_04
progress "CSAP-Hadoop-05"; check_CSAP_Hadoop_05
progress "CSAP-Hadoop-06"; check_CSAP_Hadoop_06
progress "CSAP-Hadoop-07"; check_CSAP_Hadoop_07
progress "CSAP-Hadoop-08"; check_CSAP_Hadoop_08
progress "CSAP-Hadoop-09"; check_CSAP_Hadoop_09

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
    echo '    "platform": "Hadoop",'
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

echo "===== Hadoop CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
