#!/bin/sh
###############################################################################
# Kubernetes(Master) CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash k8s_master_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_kubernetes(master)_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Pre-flight: Kubernetes Master 설치 확인 및 경로 탐지 ---
KUBECTL_BIN=""
K8S_MANIFEST_DIR="${K8S_MANIFEST_DIR:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    KUBECTL_BIN=$(command -v kubectl 2>/dev/null)

    # 2) 프로세스에서 kube-apiserver 탐지
    local apiserver_proc
    apiserver_proc=$(ps -ef 2>/dev/null | grep '[k]ube-apiserver' | head -1)
    if [ -n "$apiserver_proc" ]; then
        APP_FOUND="true"
    fi

    # 3) 매니페스트 디렉토리 탐색
    for d in /etc/kubernetes/manifests /etc/kubernetes; do
        if [ -d "$d" ]; then
            K8S_MANIFEST_DIR="$d"
            break
        fi
    done

    # 4) kubeconfig 확인
    if [ -f /etc/kubernetes/admin.conf ] || [ -f "$HOME/.kube/config" ]; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$KUBECTL_BIN" ] || [ -n "$K8S_MANIFEST_DIR" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Kubernetes(Master) 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-K8sMaster-01: API sever 비인증 접근 차단
check_CSAP_K8sMaster_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 비인증 접근 차단 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 - --anonynous-auth=false 2\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 - --service-account-lookup=true"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 비인증 접근을 차단한 경우"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-01" "패치 관리" "API sever 비인증 접근 차단" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-02: API server 취약한 방식의 인증 사용 제한
check_CSAP_K8sMaster_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 취약한 방식의 인증 사용 제한 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 확인 - --token-auth-file 파라미터가 존재할 경우, 해당 파라미터 삭제"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API sever"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-02" "" "API server 취약한 방식의 인증 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-03: API sever 서비스 API 외부 오픈 금지
check_CSAP_K8sMaster_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 서비스 API 외부 오픈 금지 1\) scheduler API 서비스 etc/kubernetes/manifests/kube-scheduler.yaml 파일 내 아래와 같이 설정 2\) controller manager API 서비스 etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래와 같이 설정"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 서비스 API가 외부에서 접근"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-03" "" "API sever 서비스 API 외부 오픈 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-04: API server 권한 제어
check_CSAP_K8sMaster_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ API server 권한 제어 설정 1\) authorization-mode 인자 값을 AlwaysAllow가 아닌 값으로 수정 - --authorization-mode=Node, RBAC \(예시\)"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 권한이 AlwaysAllow 값으로"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-04" "API Server" "API server 권한 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-05: Admission Control Plugin 설정
check_CSAP_K8sMaster_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ Admission Control 설정 검토 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 --enable-admission-plugins=AlwaysAdmin \(제거\) --enable-admission-plugins=AlwaysPullImages \(추가\) --enable-admission-plugins=NodeRestriction \(추가\) --enable-admission-plugins=SecurityContextDeny \(추가\) --enable-admission-plugins=PodSecurityPolicy --disable-admission-plugins=NamespaceLifecycle \(제거\) --enable-admission-plugins=EventRateLimit \(추가\) --admission-control-config-file = <path> \(추가\)"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Admission Control Plugin 설정이"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-05" "API Server" "Admission Control Plugin 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-06: API server SSL/TLS 적용
check_CSAP_K8sMaster_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ SSL/TLS 적용을 통한 네트워크 구간 데이터 보호 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터를 제거 또는 0이 아닌 값으로 설정 - --secure-port ￭ 인증서 관리 \(API Server to kubelet\) 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 파일 추가 - --kubelet-certificate-authority=<인증서 파일> - --kubelet-client-certificate=<client 인증서 파일> - --kubelet-client-key=<client 키 파일> - --kubelet-account-key-file=<servive account 키 파일> ￭ 인증서 관리 \(API Server\) 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 파일 추가 - --tls-cert-file=<tls 인증서 파일> - --tls-private-key-file=<tls 키 파일> - --client-ca-file=<client ca 인증서 파일> ￭ 안전한 SSL/TLS 버전 사용 \(예시\) 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 추가 - --tls-cipher-suites=TLS_ECDSA_WITH_AED_128_GCM_SHA256,TLS_ECDHE_ RSA_WITH_AES_128_GCM_SHA256"

    local config_file="/etc/kubernetes/manifests/kube-apiserver.yaml"
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

    add_result "CSAP-K8sMaster-06" "API Server" "API server SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-07: API Server 로그 관리
check_CSAP_K8sMaster_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 로그 설정 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 설정 - --auditlog-path - --audit-policy-file - --audit-log-maxage - --audit-log-maxbackup - --audit-log-maxsize"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 로그가 활성화된 경우"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-07" "" "API Server 로그 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-08: Controller 인증 제어
check_CSAP_K8sMaster_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 컨트롤러에 대해 개별 서비스 계정 자격증명 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터에 설정 - --use-service-account-credentials=true ￭ 컨트롤러 계정 자격증명에 사용되는 인증서 관리 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터에 파일 추가 - --service-account-private-key-file= < >"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Controller 인증 제어 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-08" "Controller Manager" "Controller 인증 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-09: Controller Manager SSL/TLS 적용
check_CSAP_K8sMaster_09() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ SSL/TLS 적용을 통한 클라이언트 인증 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터에 파일 추가 - --root-ca-file=<> ￭ 인증서 관리 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터 문구 추가 - --feature-gates=RotateKubeletServerCertificate=true"

    local config_file="/etc/kubernetes/manifests/kube-controller-manager.yaml"
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

    add_result "CSAP-K8sMaster-09" "Controller Manager" "Controller Manager SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-10: etcd 암호화 적용
check_CSAP_K8sMaster_10() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep kube-apiserver"
    local cur_state=""
    local remediation="￭ etcd 암호화 적용 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 파일 추가 - --encryption-provider-config=<> ￭ 안전한 암호화 방식 사용 1\) 아래 명령어 실행 후, --encryption-provider-config 값 확인 # ps –ef | grep kube-apiserver"

    local config_file="/etc/kubernetes/manifests/kube-apiserver.yaml"
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

    add_result "CSAP-K8sMaster-10" "etcd Configuration" "etcd 암호화 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-11: etcd SSL/TLS 적용
check_CSAP_K8sMaster_11() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ SSL/TLS 적용을 통한 클라이언트 인증\(etcd peer 및 클라이언트\) 1\) /etc/kubernetes/manifests/etcd.yaml 파일 내 아래와 같이 설정 --client-cert-auth=true 추가 --peer-client-cert-auth=true 수정 \(etcd server의 경우 적용 필요 없음\) ￭ 인증서 관리\(etcd peer 및 클라이언트\) \(인증서설정 예시\) 1\) /etc/kubernetes/manifests/etcd.yaml 파일 내 아래와 같이 설정 --cert-file=<인증서 파일> 추가 --key-file=<키 파일> 추가 --peer-cert-file=<peer 인증서 파일> --peer-key-file=<peer 키 파일> 추가 2\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 --etcd-certfile=<etcd cert 인증서 파일> 추가 --etcd-keyfile=<etcd 키 파일> 추가 --etcd-cafile=<etcd ca 인증서 파일> 추가 ￭ 인증서 관리\(자체 서명인증서 사용금지\) 1\) /etc/kubernetes/manifests/etcd.yaml 파일 내 아래와 같이 설정 --auto-tls=false --peer-auto-tls=false or 제거 \(etcd server의 경우 적용 필요 없음\) --trusted-ca-file=<인증서 파일> 추가"

    local config_file="/etc/kubernetes/manifests/etcd.yaml"
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

    add_result "CSAP-K8sMaster-11" "etcd Configuration" "etcd SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-12: 컨테이너 권한 제어
check_CSAP_K8sMaster_12() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 컨테이너 권한 제어 1\) pod 생성 *.yaml 파일 내에 SecurityContext 설정값 수정 \(예시\) -allowPrivilegeEscalation: false \(추가\) -runAsUser: 0이 아닌 값 \(추가\) -runAsNonRoot: true \(추가\) -capabilities.drop: \(추가\) drop: [\"ALL\"] -seccomprofiles: \(추가\) type: \"ReuntimeDefault\" 2\) namespace 생성 시, namespace에 PodSecurityAdmission 정책을 아래와 같이 적용\(enforce, warn 인수는 privileged가 아닌 restricted로 설정\) # kubectl label —overwrite ns test-restricted pod-security.kubernetes.io/enforce= restricted pod-security.kubernetes.io/warn=restricted"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. PodSecurityAdmission 정책을 통해"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-12" "PodSecurityAdmission" "컨테이너 권한 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-13: 네임스페이스 공유 금지
check_CSAP_K8sMaster_13() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 네임스페이스 공유 금지 1\) pod 생성 *.yaml 파일 내 spec 필드에서 아래의 설정값 유무 확인 - hostNetwork: false 또는 파라미터 제거 - hostPID: false 또는 파라미터 제거 - hostIPC: false 또는 파라미터 제거"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 네임스페이스 공유 금지 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-13" "PodSecurityAdmission" "네임스페이스 공유 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-14: 환경설정 파일 권한 설정
check_CSAP_K8sMaster_14() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/kubernetes/manifests/kube-apiserver.yaml; ls -al /etc/kubernetes/manifests/kube-controller-manager.yaml; ls -al /etc/kubernetes/manifests/kube-scheduler.yaml"
    local cur_state=""
    local remediation="￭ kube-apiserver.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/kube-apiserver.yaml ￭ kube-controller-manager.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/kube-controller-manager.yaml ￭ kube-scheduler.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/kube-scheduler.yaml ￭ etcd.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/etcd.yaml ￭ admin.conf 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/admin.conf ￭ scheduler.conf 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/scheduler.conf ￭ controller-manager.conf 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/controller-manager.conf"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/kubernetes/manifests/kube-apiserver.yaml
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_2
    target_spec_2=/etc/kubernetes/manifests/kube-controller-manager.yaml
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_2). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=/etc/kubernetes/manifests/kube-scheduler.yaml
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_3). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_3). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/etc/kubernetes/manifests/etcd.yaml
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_4). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_4). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_5
    target_spec_5=/etc/kubernetes/manifests/admin.conf
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_5). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_5). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_6
    target_spec_6=/etc/kubernetes/admin.conf
    local resolved_target_6
    resolved_target_6="$target_spec_6"
    if [ -n "$resolved_target_6" ]; then
        for target_path in $resolved_target_6; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_6
                result_6=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_6; "
                case "$result_6" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_6). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_6). " ;;
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

    add_result "CSAP-K8sMaster-14" "파일 권한 설정" "환경설정 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-15: 인증서 파일 권한 설정
check_CSAP_K8sMaster_15() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/kubernetes/pki/*.crt; ls -al /etc/kubernetes/pki/*.key; ls -al /var/;ib/kubernetes/ pem"
    local cur_state=""
    local remediation="￭ pki 인증서 파일 접근 권한 확인 # chmod 644 /etc/kubernetes/pki/*.crt ￭ pki 키 파일 접근 권한 확인 # chmod 600 /etc/kubernetes/pki/*.key ￭ Hardway로 설치된 경우\(예시\) # chmod 600 /var/lib/kubernetes/*.pem"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/etc/kubernetes/pki/*.crt
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_1; "
                case "$result_1" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_1). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_1). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_2
    target_spec_2=/etc/kubernetes/pki/*.key
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_2; "
                case "$result_2" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_2). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_2). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_3
    target_spec_3=/var/
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_3; "
                case "$result_3" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_3). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_3). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_4
    target_spec_4=/kubernetes/
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_4; "
                case "$result_4" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_4). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_4). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_5
    target_spec_5=/etc/kubernetes/manifests/kube-apiserver.yaml
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_5). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_5). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_6
    target_spec_6=/etc/kubernetes/manifests/kube-controller-manager.yaml
    local resolved_target_6
    resolved_target_6="$target_spec_6"
    if [ -n "$resolved_target_6" ]; then
        for target_path in $resolved_target_6; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_6
                result_6=$(check_file_owner_perm "$target_path" "" "644")
                cur_state="${cur_state}$target_path: $result_6; "
                case "$result_6" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 권한 부적절($result_6). " ;;
                    GOOD*) detail="${detail}$target_path 권한 적절($result_6). " ;;
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
    [ -z "$detail" ] && detail="파일의 소유자 및 소유 그룹이 root이고," && cur_state="점검 대상 파일 없음"

    add_result "CSAP-K8sMaster-15" "파일 권한 설정" "인증서 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-16: etcd 데이터 디렉터리 권한 설정
check_CSAP_K8sMaster_16() {
    local status="양호"
    local detail=""
    local cmd="ls -ald /var/lib/etcd"
    local cur_state=""
    local remediation="￭ etcd 디렉터리 소유자 및 소유자 그룹 root, 접근 권한 700 이하로 설정 # chmod 700 /var/lib/etcd # chown root:root /var/lib/etcd"

    local vuln_found=false
    local checked_any=false
    local missing_only=true
    local target_spec_1
    target_spec_1=/var/lib/etcd
    local resolved_target_1
    resolved_target_1="$target_spec_1"
    if [ -n "$resolved_target_1" ]; then
        for target_path in $resolved_target_1; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_1
                result_1=$(check_file_owner_perm "$target_path" "root" "700")
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
    target_spec_2=/etc/kubernetes/manifests/kube-apiserver.yaml
    local resolved_target_2
    resolved_target_2="$target_spec_2"
    if [ -n "$resolved_target_2" ]; then
        for target_path in $resolved_target_2; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_2
                result_2=$(check_file_owner_perm "$target_path" "root" "700")
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
    target_spec_3=/etc/kubernetes/manifests/kube-controller-manager.yaml
    local resolved_target_3
    resolved_target_3="$target_spec_3"
    if [ -n "$resolved_target_3" ]; then
        for target_path in $resolved_target_3; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_3
                result_3=$(check_file_owner_perm "$target_path" "root" "700")
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
    target_spec_4=/etc/kubernetes/manifests/kube-scheduler.yaml
    local resolved_target_4
    resolved_target_4="$target_spec_4"
    if [ -n "$resolved_target_4" ]; then
        for target_path in $resolved_target_4; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_4
                result_4=$(check_file_owner_perm "$target_path" "root" "700")
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
    local target_spec_5
    target_spec_5=/etc/kubernetes/manifests/etcd.yaml
    local resolved_target_5
    resolved_target_5="$target_spec_5"
    if [ -n "$resolved_target_5" ]; then
        for target_path in $resolved_target_5; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_5
                result_5=$(check_file_owner_perm "$target_path" "root" "700")
                cur_state="${cur_state}$target_path: $result_5; "
                case "$result_5" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_5). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_5). " ;;
                    NOT_FOUND) detail="${detail}$target_path 파일 없음. " ;;
                esac
            else
                detail="${detail}$target_path 파일 없음. "
                cur_state="${cur_state}$target_path: 파일 없음; "
            fi
        done
    fi
    local target_spec_6
    target_spec_6=/etc/kubernetes/admin.conf
    local resolved_target_6
    resolved_target_6="$target_spec_6"
    if [ -n "$resolved_target_6" ]; then
        for target_path in $resolved_target_6; do
            [ -z "$target_path" ] && continue
            checked_any=true
            if [ -e "$target_path" ]; then
                missing_only=false
                local result_6
                result_6=$(check_file_owner_perm "$target_path" "root" "700")
                cur_state="${cur_state}$target_path: $result_6; "
                case "$result_6" in
                    VULN*) vuln_found=true; detail="${detail}$target_path 소유자/권한 부적절($result_6). " ;;
                    GOOD*) detail="${detail}$target_path 소유자/권한 적절($result_6). " ;;
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
    [ -z "$detail" ] && detail="etcd 데이터 디렉터리의 소유자 및 소유" && cur_state="점검 대상 파일 없음"

    add_result "CSAP-K8sMaster-16" "파일 권한 설정" "etcd 데이터 디렉터리 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-K8sMaster-17: 최신 보안 패치 적용
check_CSAP_K8sMaster_17() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 최신 보안 업데이트 적용 여부 확인 1\) # kubectl version 2\) 기간 산정해서 보안 패치 적용\(정기 PM 등\) ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 최신 보안 패치가 적용되거나 보안"
    cur_state="수동점검 필요"

    add_result "CSAP-K8sMaster-17" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Kubernetes(Master) CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/17] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-K8sMaster-01"; check_CSAP_K8sMaster_01
progress "CSAP-K8sMaster-02"; check_CSAP_K8sMaster_02
progress "CSAP-K8sMaster-03"; check_CSAP_K8sMaster_03
progress "CSAP-K8sMaster-04"; check_CSAP_K8sMaster_04
progress "CSAP-K8sMaster-05"; check_CSAP_K8sMaster_05
progress "CSAP-K8sMaster-06"; check_CSAP_K8sMaster_06
progress "CSAP-K8sMaster-07"; check_CSAP_K8sMaster_07
progress "CSAP-K8sMaster-08"; check_CSAP_K8sMaster_08
progress "CSAP-K8sMaster-09"; check_CSAP_K8sMaster_09
progress "CSAP-K8sMaster-10"; check_CSAP_K8sMaster_10
progress "CSAP-K8sMaster-11"; check_CSAP_K8sMaster_11
progress "CSAP-K8sMaster-12"; check_CSAP_K8sMaster_12
progress "CSAP-K8sMaster-13"; check_CSAP_K8sMaster_13
progress "CSAP-K8sMaster-14"; check_CSAP_K8sMaster_14
progress "CSAP-K8sMaster-15"; check_CSAP_K8sMaster_15
progress "CSAP-K8sMaster-16"; check_CSAP_K8sMaster_16
progress "CSAP-K8sMaster-17"; check_CSAP_K8sMaster_17

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
    echo '    "platform": "Kubernetes(Master)",'
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

echo "===== Kubernetes(Master) CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
