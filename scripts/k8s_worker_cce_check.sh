#!/bin/sh
###############################################################################
# Kubernetes(Worker) CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash k8s_worker_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_kubernetes(worker)_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

TEMP_DIR="/tmp/cce_check_$$"
mkdir -p "$TEMP_DIR"
trap "rm -rf $TEMP_DIR" EXIT

# --- JSON helper functions (ESXi BusyBox compatible) ---
RESULTS_FILE="$TEMP_DIR/results.txt"
: > "$RESULTS_FILE"

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
    code="$1"
    status="$2"
    title="$3"
    command="$4"
    current_state="$5"
    detail="$6"
    command_text=$(normalize_trace_value "$command")
    current_state_text=$(normalize_trace_value "$current_state")
    detail_text=$(normalize_trace_value "$detail")
    printf '\n[TRACE] code=%s status=%s title=%s\n' "$code" "$status" "$title"
    printf '[TRACE] command=%s\n' "${command_text:--}"
    printf '[TRACE] current_state=%s\n' "${current_state_text:--}"
    printf '[TRACE] detail=%s\n' "${detail_text:--}"
}

add_result() {
    code="$1"
    category="$2"
    title="$3"
    importance="$4"
    status="$5"
    detail="$6"
    source="$7"
    command="$8"
    current_state="$9"
    shift 9
    remediation="$1"
    raw_detail="$detail"
    raw_command="$command"
    raw_current_state="$current_state"

    # Escape strings for JSON
    detail=$(sanitize_json_value "$detail")
    title=$(sanitize_json_value "$title")
    command=$(sanitize_json_value "$command")
    current_state=$(sanitize_json_value "$current_state")
    remediation=$(sanitize_json_value "$remediation")

    echo "{\"code\":\"$code\",\"category\":\"$category\",\"title\":\"$title\",\"importance\":\"$importance\",\"status\":\"$status\",\"detail\":\"$detail\",\"source\":\"$source\",\"command\":\"$command\",\"current_state\":\"$current_state\",\"remediation\":\"$remediation\"}" >> "$RESULTS_FILE"
    log_result_trace "$code" "$status" "$title" "$raw_command" "$raw_current_state" "$raw_detail"
}

# --- Utility functions (ESXi compatible) ---
check_file_owner_perm() {
    file="$1"
    expected_owner="$2"
    max_perm="$3"

    if [ ! -e "$file" ]; then
        echo "NOT_FOUND"
        return
    fi

    owner=$(ls -ld "$file" 2>/dev/null | awk '{print $3}')
    perm_str=$(ls -ld "$file" 2>/dev/null | awk '{print $1}')
    perm=$(stat -c '%a' "$file" 2>/dev/null || echo "000")

    owner_ok="false"
    if [ -z "$expected_owner" ] || [ "$owner" = "$expected_owner" ]; then
        owner_ok="true"
    fi

    perm_ok="false"
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
    svc="$1"
    if /etc/init.d/"$svc" status 2>/dev/null | grep -qi "running"; then
        echo "active"
    elif ps | grep -v grep | grep -q "$svc"; then
        echo "active"
    else
        echo "inactive"
    fi
}


# --- Kubernetes helper ---
run_kubectl() {
    kubectl "$@" 2>/dev/null
}


# --- Pre-flight: Kubernetes Worker 설치 확인 및 경로 탐지 ---
KUBECTL_BIN=""
KUBELET_CONF="${KUBELET_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    KUBECTL_BIN=$(command -v kubectl 2>/dev/null)
    local kubelet_bin
    kubelet_bin=$(command -v kubelet 2>/dev/null)

    # 2) 프로세스에서 kubelet 탐지
    local kubelet_proc
    kubelet_proc=$(ps -ef 2>/dev/null | grep '[k]ubelet' | head -1)
    if [ -n "$kubelet_proc" ]; then
        APP_FOUND="true"
        # --config 추출
        local conf_from_proc
        conf_from_proc=$(echo "$kubelet_proc" | sed -n 's/.*--config[= ]\([^ ]*\).*/\1/p')
        if [ -n "$conf_from_proc" ] && [ -f "$conf_from_proc" ]; then
            KUBELET_CONF="$conf_from_proc"
        fi
    fi

    # 3) 공통 설정 경로 탐색
    if [ -z "$KUBELET_CONF" ]; then
        for f in /var/lib/kubelet/config.yaml /etc/kubernetes/kubelet.conf; do
            if [ -f "$f" ]; then
                KUBELET_CONF="$f"
                break
            fi
        done
    fi

    # 판정
    if [ -n "$kubelet_bin" ] || [ -n "$KUBELET_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Kubernetes(Worker) 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-K8sWorker-01: Kubelet 인증 제어
check_CSAP_K8sWorker_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ Kubelet service 파일을 사용하는 경우 1\) vi 명령어를 통해 —anonymous-auth 설정을 false로 —read-only-port 설정을 0으로 설정 \$ vi [kubelet service 경로] Environment=\"KUBELET_SYSTEM_PODS_ARGS=--anonymous-auth=false --read-only-prot=0\" 설정 추가 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service ￭ Kubelet config 파일을 사용하는 경우 1\) vi 명령어를 통해 --anonymous-auth 설정을 false로 --read-only-port 설정을 0으로 설정 \$ vi [kubelet config 파일 경로] 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 비인증 접근이 차단된 경우"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sWorker-01" "패치 관리" "Kubelet 인증 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sWorker-02: Kubelet 권한 제어
check_CSAP_K8sWorker_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ Kubelet service 파일을 사용하는 경우 1\) vi 명령어를 통해 --authorization-mode 설정에 모드 설정 \$ vi [kubelet service 파일 경로] Environment=\"KUBELET_SYSTEM_PODS_ARGS=--anonymous-auth=false --read-only-prot=0\" 설정 추가 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service ￭ Kubelet config 파일을 사용하는 경우 1\) vi 명령어를 통해 --authorization-mode 설정에 모드 설정 \$ vi [kubelet config 파일 경로] 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 권한이 AlwaysAllow 값으로"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sWorker-02" "" "Kubelet 권한 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sWorker-03: Kubelet SSL/TLS 적용
check_CSAP_K8sWorker_03() {
    local status="양호"
    local detail=""
    local cmd="cat --hostname-override"
    local cur_state=""
    local remediation="￭ kubelet config 파일에서 클라이언트 CA 인증서 설정 1\) \$ cat [kubelet config 파일 경로] clientCAFile : [CA 인증서 파일 경로] ￭ kubelet config 파일에서 TLS 인증서와 Private key가 설정되어 있는지 확인 1\) \$ cat [kubelet config 파일 경로] tlsCertFile : [인증서 파일 경로] tlsPrivateKeyFile : [Private key 파일 경로] ￭ kubelet config 파일에서 인증서 교환주기 설정이 되어 있는지 확인 1\) \$ cat [kubelet config 파일 경로] tlsCertFile : [인증서 파일 경로] tlsPrivateKeyFile : [Private key 파일 경로] ￭ kubelet config 파일에서 TLS 통신에 사용되는 TLS 버전 및 cipher suites 확인 1\) \$ cat [kubelet config 파일 경로] TLSCipherSuites : TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_128_GCM_SHA256 ￭ kubelet service 파일에서 hostname이 변경되지 않도록 설정되어 있는지 확인 1\) \$ cat [kubelet service 파일 경로]를 확인하여 --hostname-override 설정이 존재하는지 확인\(존재하지 않아야 함\)"

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

    add_result "CSAP-K8sWorker-03" "" "Kubelet SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sWorker-04: Kernel 파라미터 설정
check_CSAP_K8sWorker_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ kubelet service 파일을 사용하는 경우 1\) --protect-kernel-defaults 설정이 true로 설정 \$ vi [kubelet service 파일 경로] Environment=\"KUBELET_SYSTEM_PODS_ARGS=--protect-kernel-defaults =true\" 설정 추가 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service ￭ Kubelet config 파일을 사용하는 경우 1\) vi 명령어를 통해 protectKernelDefaults 설정을 true로 설정 \$ vi [kubelet config 파일 경로] 2\) kubelet 서비스 재시작 \$ systemctl daemon-reload \$ systemctl restart kubelet.service"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Kubelet Default Kernel 값을 보호하는"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sWorker-04" "" "Kernel 파라미터 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sWorker-05: 환경설정 파일 권한 설정
check_CSAP_K8sWorker_05() {
    local status="양호"
    local detail=""
    local cmd="stat -c %a:%U:%G /etc/kubernetes/kubelet.conf; stat -c %a:%U:%G /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.; stat -c %a:%U:%G /var/lib/kubelet/config.yaml"
    local cur_state=""
    local remediation="￭ 설정파일의 소유자 및 소유 그룹이 root가 아닌 경우 root로 조치 \$ chown root:root [변경할 파일명] ￭ 설정파일의 접근 권한이 644를 초과하는 경우 644 이하로 조치 \$ chmod 644 [변경할 파일명]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/kubernetes/kubelet.conf
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_2
    target_spec_2=/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_2). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_2). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=/var/lib/kubelet/config.yaml
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_3). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_3). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_4). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_4). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
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
    [ -z "$detail" ] && detail="환경설정 파일의 소유자 및 소유 그룹이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-K8sWorker-05" "파일 권한 설정" "환경설정 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sWorker-06: 인증서 파일 권한 설정
check_CSAP_K8sWorker_06() {
    local status="양호"
    local detail=""
    local cmd="ls -al"
    local cur_state=""
    local remediation="￭ 인증서 파일 권한과 소유자가 root로 되어 있는지 확인 \$ chown root:root [변경할 파일명] ￭ 인증서 파일의 접근 권한이 644를 초과하는 경우 644 이하로 조치 \$ chmod 644 [변경할 파일명]"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/kubernetes/kubelet.conf
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_2
    target_spec_2=/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_2). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_2). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=/var/lib/kubelet/config.yaml
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "644")
                cur_state="${cur_state}$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_3). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_3). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
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
    [ -z "$detail" ] && detail="인증서 파일의 소유자 및 소유 그룹이" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-K8sWorker-06" "파일 권한 설정" "인증서 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sWorker-07: 최신 보안 패치 적용
check_CSAP_K8sWorker_07() {
    local status="양호"
    local detail=""
    local cmd="kubectl version"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 확인 후 업데이트 및 패치 수행 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( kubectl version )
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

    add_result "CSAP-K8sWorker-07" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Kubernetes(Worker) CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/7] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-K8sWorker-01"; check_CSAP_K8sWorker_01
progress "CSAP-K8sWorker-02"; check_CSAP_K8sWorker_02
progress "CSAP-K8sWorker-03"; check_CSAP_K8sWorker_03
progress "CSAP-K8sWorker-04"; check_CSAP_K8sWorker_04
progress "CSAP-K8sWorker-05"; check_CSAP_K8sWorker_05
progress "CSAP-K8sWorker-06"; check_CSAP_K8sWorker_06
progress "CSAP-K8sWorker-07"; check_CSAP_K8sWorker_07

echo ""
echo ""

###############################################################################
# Generate JSON output
###############################################################################

# System info
SYS_HOSTNAME=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr '
' '  ' | sed 's/  */ /g; s/^ //; s/ $//' )
SYS_OS="VMware ESXi"
SYS_KERNEL=$(uname -r 2>/dev/null)
SYS_DATE=$(date '+%Y-%m-%d %H:%M:%S')
SYS_IP=$(esxcli network ip interface ipv4 get 2>/dev/null | awk 'NR>1 {print $2}' | head -1)

# Count results
total_checks=0
good_count=0
vuln_count=0
na_count=0
manual_count=0

while IFS= read -r line; do
    total_checks=$((total_checks + 1))
    case "$line" in
        *'"status":"양호"'*) good_count=$((good_count + 1)) ;;
        *'"status":"취약"'*) vuln_count=$((vuln_count + 1)) ;;
        *'"status":"N/A"'*) na_count=$((na_count + 1)) ;;
        *'"status":"수동점검"'*) manual_count=$((manual_count + 1)) ;;
    esac
done < "$RESULTS_FILE"

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
    while IFS= read -r line; do
        if [ "$first" = "true" ]; then
            echo "    $line"
            first=false
        else
            echo "    ,$line"
        fi
    done < "$RESULTS_FILE"

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
