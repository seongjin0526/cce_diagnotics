#!/bin/bash
###############################################################################
# Kubernetes(Worker) CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash k8s_worker_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_kubernetes(worker)_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Kubernetes helper ---
run_kubectl() {
    kubectl "$@" 2>/dev/null
}


# CLD-K8sWorker-01: Kubelet 인증 제어
check_CLD_K8sWorker_01() {
    local status="양호"
    local detail=""
    local cmd="cat | grep anonymous-auth\\|read-only-port |; cat"
    local cur_state=""
    local remediation="￭ Kubelet service 파일을 사용하는 경우 1\) vi 명령어를 통해 —anonymous-auth 설정을 false로 —read-only-port 설정을 0으로 설정 \$ vi [kubelet service 경로] Environment=\"KUBELET_SYSTEM_PODS_ARGS=--anonymous-auth=false --read-only-prot=0\" 설정 추가 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service ￭ Kubelet config 파일을 사용하는 경우 1\) vi 명령어를 통해 --anonymous-auth 설정을 false로 --read-only-port 설정을 0으로 설정 \$ vi [kubelet config 파일 경로] 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service"

    status="수동점검"
    detail="서비스 상태 수동 확인 필요. 비인증 접근이 차단된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sWorker-01" "패치 관리" "Kubelet 인증 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sWorker-02: Kubelet 권한 제어
check_CLD_K8sWorker_02() {
    local status="양호"
    local detail=""
    local cmd="cat | grep authorization-mode | grep -v #; cat"
    local cur_state=""
    local remediation="￭ Kubelet service 파일을 사용하는 경우 1\) vi 명령어를 통해 --authorization-mode 설정에 모드 설정 \$ vi [kubelet service 파일 경로] Environment=\"KUBELET_SYSTEM_PODS_ARGS=--anonymous-auth=false --read-only-prot=0\" 설정 추가 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service ￭ Kubelet config 파일을 사용하는 경우 1\) vi 명령어를 통해 --authorization-mode 설정에 모드 설정 \$ vi [kubelet config 파일 경로] 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service"

    status="수동점검"
    detail="서비스 상태 수동 확인 필요. API server 권한이 AlwaysAllow 값으로"
    cur_state="수동점검 필요"

    add_result "CLD-K8sWorker-02" "" "Kubelet 권한 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sWorker-03: Kubelet SSL/TLS 적용
check_CLD_K8sWorker_03() {
    local status="양호"
    local detail=""
    local cmd="cat; cat; cat"
    local cur_state=""
    local remediation="￭ kubelet config 파일에서 클라이언트 CA 인증서 설정 1\) \$ cat [kubelet config 파일 경로] clientCAFile : [CA 인증서 파일 경로] ￭ kubelet config 파일에서 TLS 인증서와 Private key가 설정되어 있는지 확인 1\) \$ cat [kubelet config 파일 경로] tlsCertFile : [인증서 파일 경로] tlsPrivateKeyFile : [Private key 파일 경로] ￭ kubelet config 파일에서 인증서 교환주기 설정이 되어 있는지 확인 1\) \$ cat [kubelet config 파일 경로] tlsCertFile : [인증서 파일 경로] tlsPrivateKeyFile : [Private key 파일 경로] ￭ kubelet config 파일에서 TLS 통신에 사용되는 TLS 버전 및 cipher suites 확인 1\) \$ cat [kubelet config 파일 경로] TLSCipherSuites : TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_128_GCM_SHA256 ￭ kubelet service 파일에서 hostname이 변경되지 않도록 설정되어 있는지 확인 1\) \$ cat [kubelet service 파일 경로]를 확인하여 --hostname-override 설정이 존재하는지 확인\(존재하지 않아야 함\)"

    status="수동점검"
    detail="서비스 상태 수동 확인 필요. kubelet SSL/TLS 통신을 위한 설정\(인증서,"
    cur_state="수동점검 필요"

    add_result "CLD-K8sWorker-03" "" "Kubelet SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sWorker-04: Kernel 파라미터 설정
check_CLD_K8sWorker_04() {
    local status="양호"
    local detail=""
    local cmd="cat | grep authorization-mode | grep -v #; cat"
    local cur_state=""
    local remediation="￭ kubelet service 파일을 사용하는 경우 1\) --protect-kernel-defaults 설정이 true로 설정 \$ vi [kubelet service 파일 경로] Environment=\"KUBELET_SYSTEM_PODS_ARGS=--protect-kernel-defaults =true\" 설정 추가 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service ￭ Kubelet config 파일을 사용하는 경우 1\) vi 명령어를 통해 protectKernelDefaults 설정을 true로 설정 \$ vi [kubelet config 파일 경로] 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service"

    status="수동점검"
    detail="서비스 상태 수동 확인 필요. Kubelet Default Kernel 값을 보호하는"
    cur_state="수동점검 필요"

    add_result "CLD-K8sWorker-04" "" "Kernel 파라미터 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sWorker-05: 환경설정 파일 권한 설정
check_CLD_K8sWorker_05() {
    local status="양호"
    local detail=""
    local cmd="stat -c %a:%U:%G /etc/kubernetes/kubelet.conf; stat -c %a:%U:%G /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.; stat -c %a:%U:%G /var/lib/kubelet/config.yaml"
    local cur_state=""
    local remediation="￭ 설정파일의 소유자 및 소유 그룹이 root가 아닌 경우 root로 조치 \$ chown root:root [변경할 파일명] ￭ 설정파일의 접근 권한이 644를 초과하는 경우 644 이하로 조치 \$ chmod 644 [변경할 파일명]"

    local output
    output=$(stat -c %a:%U:%G /etc/kubernetes/kubelet.conf 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-K8sWorker-05" "파일 권한 설정" "환경설정 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sWorker-06: 인증서 파일 권한 설정
check_CLD_K8sWorker_06() {
    local status="양호"
    local detail=""
    local cmd="ls -al"
    local cur_state=""
    local remediation="￭ 인증서 파일 권한과 소유자가 root로 되어 있는지 확인 \$ chown root:root [변경할 파일명] ￭ 인증서 파일의 접근 권한이 644를 초과하는 경우 644 이하로 조치 \$ chmod 644 [변경할 파일명]"

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

    add_result "CLD-K8sWorker-06" "파일 권한 설정" "인증서 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sWorker-07: 최신 보안 패치 적용
check_CLD_K8sWorker_07() {
    local status="양호"
    local detail=""
    local cmd="kubectl version"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 확인 후 업데이트 및 패치 수행 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(kubectl version 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-K8sWorker-07" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Kubernetes(Worker) CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/7] %s 점검 중...                " "$total" "$1"
}


progress "CLD-K8sWorker-01"; check_CLD_K8sWorker_01
progress "CLD-K8sWorker-02"; check_CLD_K8sWorker_02
progress "CLD-K8sWorker-03"; check_CLD_K8sWorker_03
progress "CLD-K8sWorker-04"; check_CLD_K8sWorker_04
progress "CLD-K8sWorker-05"; check_CLD_K8sWorker_05
progress "CLD-K8sWorker-06"; check_CLD_K8sWorker_06
progress "CLD-K8sWorker-07"; check_CLD_K8sWorker_07

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
    echo '    "platform": "Kubernetes(Worker)",'
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

echo "===== Kubernetes(Worker) CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
