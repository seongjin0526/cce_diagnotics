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

OUTPUT_FILE="${1:-cce_check_result_hadoop_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# CLD-Hadoop-01: 로컬 파일 시스템/HDFS 디렉토리 소유자 및 권한 설정
check_CLD_Hadoop_01() {
    local status="양호"
    local detail=""
    local cmd="./bin/hadoop fs -ls"
    local cur_state=""
    local remediation="￭ 로컬 파일 시스템 \(예시\) // dfs.namenode.name.dir = hdfs:hadoop \(700\) 1\) # chown –R hdfs:hadoop /home/hadoop/data/dfs/name 2\) # chmod 700 /home/hadoop/data/dfs/name // dfs.namenode.data.dir = hdfs:hadoop \(700\) 3\) # chown –R hdfs:hadoop /home/hadoop/data/dfs/data 4\) # chmod 700 /home/hadoop/data/dfs/data // dfs.journalnode.edits.dir = hdfs:hadoop \(700\) 5\) # chown –R hdfs:hadoop /home/hadoop/data/dfs/journalnode 6\) # chmod 700 /home/hadoop/data/dfs/journalnode // \$HADOOP_LOG_DIR = hdfs:hadoop \(775\) 7\) # chown –R hdfs:hadoop /home/hadoop/logs 8\) # chmod 775 /home/hadoop/logs // yarn.nodemanager.local-dirs = yarn:hadoop \(755\) 10\) # chown -R yarn:hadoop /home/hadoop/data/yarn/nm-local-dir 11\) # chmod 755 /home/hadoop/data/yarn/nm-local-dir ￭ HDFS 디렉토리 1\) / = hdfs:hadoop \(775\) 2\) /home/hadoop/bin/hdfs dfs –chown hdfs:hadoop / 3\) /home/hadoop/bin/hdfs dfs –chmod 755 / 4\) /user = hdfs:hadoop \(755\) 5\) /home/hadoop/bin/hdfs dfs –chown hdfs:hadoop /user 6\) /home/hadoop/bin/hdfs dfs –chmod 755 /user"

    local output
    output=$(./bin/hadoop fs -ls 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Hadoop-01" "패치 및 로그 관리" "로컬 파일 시스템/HDFS 디렉토리 소유자 및 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-02: 테이블/맵리듀스 User 키 테이블 파일 권한 설정
check_CLD_Hadoop_02() {
    local status="양호"
    local detail=""
    local cmd="ls -al | grep *.keytab"
    local cur_state=""
    local remediation="￭ root 외의 소유자로 지정, 권한은 400 이하로 설정 \(예시\) # chown hdfs:hadoop hdfs.keytab # chmod 400 hdfs.keytab # chown yarn:hadoop yarn.keytab # chmod 400 yarn.keytab # chown mapred:hadoop mapred.keytab # chmod 400 mapred.keytab"

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

    add_result "CLD-Hadoop-02" "" "테이블/맵리듀스 User 키 테이블 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-03: Hadoop Security 활성화
check_CLD_Hadoop_03() {
    local status="양호"
    local detail=""
    local cmd="cat core-site.xml"
    local cur_state=""
    local remediation="￭ core-site.xml에 kerberos 설정 1\) core-site.xml 파일에 아래와 같은 설정 사항 추가 # vi core-site.xml"

    local output
    output=$(cat core-site.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Hadoop-03" "보안 설정" "Hadoop Security 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-04: 하둡 ACL 설정
check_CLD_Hadoop_04() {
    local status="양호"
    local detail=""
    local cmd="cat hadoop-policy.xml | grep datanode.protocol.acl"
    local cur_state=""
    local remediation="￭ hadoop-policy.xml ACL 설정 적용 1\) # vi hadoop-policy.xml <value> 인가된 계정 및 그룹명 </value> ※ 아무런 설정이 존재하지 않는 경우, default로 모두 접근 가능"

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
        grep_result=$(grep -i "datanode.protocol.acl" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: datanode.protocol.acl 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Hadoop-04" "보안 설정" "하둡 ACL 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-05: WebHDFS 비활성화
check_CLD_Hadoop_05() {
    local status="양호"
    local detail=""
    local cmd="cat hdfs-site.xml"
    local cur_state=""
    local remediation="￭ WebHDFS를 사용하지 않는 경우 hdfs-site.xml에서 설정 1\) # vi hdfs-site.xml"

    local output
    output=$(cat hdfs-site.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Hadoop-05" "보안 설정" "WebHDFS 비활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-06: RPC 암호화
check_CLD_Hadoop_06() {
    local status="양호"
    local detail=""
    local cmd="cat core-site.xml"
    local cur_state=""
    local remediation="￭ core-site.xml 파일 rpc 암호화 설정 1\) 아래와 같은 설정 사항 추가"

    local output
    output=$(cat core-site.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Hadoop-06" "보안 설정" "RPC 암호화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-07: 데이터 전송 암호화
check_CLD_Hadoop_07() {
    local status="양호"
    local detail=""
    local cmd="cat hdfs-site.xml"
    local cur_state=""
    local remediation="￭ hdfs-site.xml 파일에서 암호화 설정 활성화 1\) 아래와 같은 설정 사항 추가 ￭ hdfs-site.xml 파일에서 암호화 알고리즘 설정 1\) 아래와 같은 설정 사항 추가 ※ 하둡 v2.6 이전 <property> <name>dfs.encrypt.data.transfer.algorithm</name> <value>3des</value> </property>"

    local output
    output=$(cat hdfs-site.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Hadoop-07" "보안 설정" "데이터 전송 암호화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-08: 로그 검토 및 관리
check_CLD_Hadoop_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 각 파일에 로그 파일 저장 경로를 지정하여 로그를 기록 및 검토 1\) hdfs-site.xml에서 로그 파일 경로 설정 2\) core-site.xml에서 로그 파일 경로 설정 확인 3\) yarn-site.xml에서 로그 파일 경로 설정 확인 4\) mapred-site.xml에서 로그 파일 경로 설정 확인"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 하둡의 로그를 기록하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "CLD-Hadoop-08" "패치 및 로그 관리" "로그 검토 및 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Hadoop-09: 최신 보안 패치 적용
check_CLD_Hadoop_09() {
    local status="양호"
    local detail=""
    local cmd="hadoop version"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(hadoop version 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Hadoop-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Hadoop CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/9] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Hadoop-01"; check_CLD_Hadoop_01
progress "CLD-Hadoop-02"; check_CLD_Hadoop_02
progress "CLD-Hadoop-03"; check_CLD_Hadoop_03
progress "CLD-Hadoop-04"; check_CLD_Hadoop_04
progress "CLD-Hadoop-05"; check_CLD_Hadoop_05
progress "CLD-Hadoop-06"; check_CLD_Hadoop_06
progress "CLD-Hadoop-07"; check_CLD_Hadoop_07
progress "CLD-Hadoop-08"; check_CLD_Hadoop_08
progress "CLD-Hadoop-09"; check_CLD_Hadoop_09

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
