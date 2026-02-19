#!/bin/bash
###############################################################################
# Kubernetes(Master) CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash k8s_master_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_kubernetes(master)_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Pre-flight: Kubernetes Master 설치 확인 및 경로 탐지 ---
KUBECTL_BIN=""
K8S_MANIFEST_DIR=""
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


# CLD-K8sMaster-01: API sever 비인증 접근 차단
check_CLD_K8sMaster_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 비인증 접근 차단 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 - --anonynous-auth=false 2\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 - --service-account-lookup=true"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 비인증 접근을 차단한 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-01" "패치 관리" "API sever 비인증 접근 차단" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-02: API server 취약한 방식의 인증 사용 제한
check_CLD_K8sMaster_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 취약한 방식의 인증 사용 제한 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 확인 - --token-auth-file 파라미터가 존재할 경우, 해당 파라미터 삭제"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API sever"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-02" "" "API server 취약한 방식의 인증 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-03: API sever 서비스 API 외부 오픈 금지
check_CLD_K8sMaster_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 서비스 API 외부 오픈 금지 1\) scheduler API 서비스 etc/kubernetes/manifests/kube-scheduler.yaml 파일 내 아래와 같이 설정 2\) controller manager API 서비스 etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래와 같이 설정"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 서비스 API가 외부에서 접근"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-03" "" "API sever 서비스 API 외부 오픈 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-04: API server 권한 제어
check_CLD_K8sMaster_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ API server 권한 제어 설정 1\) authorization-mode 인자 값을 AlwaysAllow가 아닌 값으로 수정 - --authorization-mode=Node, RBAC \(예시\)"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 권한이 AlwaysAllow 값으로"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-04" "API Server" "API server 권한 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-05: Admission Control Plugin 설정
check_CLD_K8sMaster_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ Admission Control 설정 검토 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 --enable-admission-plugins=AlwaysAdmin \(제거\) --enable-admission-plugins=AlwaysPullImages \(추가\) --enable-admission-plugins=NodeRestriction \(추가\) --enable-admission-plugins=SecurityContextDeny \(추가\) --enable-admission-plugins=PodSecurityPolicy --disable-admission-plugins=NamespaceLifecycle \(제거\) --enable-admission-plugins=EventRateLimit \(추가\) --admission-control-config-file = <path> \(추가\)"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Admission Control Plugin 설정이"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-05" "API Server" "Admission Control Plugin 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-06: API server SSL/TLS 적용
check_CLD_K8sMaster_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ SSL/TLS 적용을 통한 네트워크 구간 데이터 보호 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터를 제거 또는 0이 아닌 값으로 설정 - --secure-port ￭ 인증서 관리 \(API Server to kubelet\) 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 파일 추가 - --kubelet-certificate-authority=<인증서 파일> - --kubelet-client-certificate=<client 인증서 파일> - --kubelet-client-key=<client 키 파일> - --kubelet-account-key-file=<servive account 키 파일> ￭ 인증서 관리 \(API Server\) 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 파일 추가 - --tls-cert-file=<tls 인증서 파일> - --tls-private-key-file=<tls 키 파일> - --client-ca-file=<client ca 인증서 파일> ￭ 안전한 SSL/TLS 버전 사용 \(예시\) 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 추가 - --tls-cipher-suites=TLS_ECDSA_WITH_AED_128_GCM_SHA256,TLS_ECDHE_ RSA_WITH_AES_128_GCM_SHA256"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server SSL/TLS가 적용된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-06" "API Server" "API server SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-07: API Server 로그 관리
check_CLD_K8sMaster_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 로그 설정 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 설정 - --auditlog-path - --audit-policy-file - --audit-log-maxage - --audit-log-maxbackup - --audit-log-maxsize"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. API server 로그가 활성화된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-07" "" "API Server 로그 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-08: Controller 인증 제어
check_CLD_K8sMaster_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 컨트롤러에 대해 개별 서비스 계정 자격증명 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터에 설정 - --use-service-account-credentials=true ￭ 컨트롤러 계정 자격증명에 사용되는 인증서 관리 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터에 파일 추가 - --service-account-private-key-file= < >"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Controller 인증 제어 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-08" "Controller Manager" "Controller 인증 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-09: Controller Manager SSL/TLS 적용
check_CLD_K8sMaster_09() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ SSL/TLS 적용을 통한 클라이언트 인증 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터에 파일 추가 - --root-ca-file=<> ￭ 인증서 관리 1\) /etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 아래의 파라미터 문구 추가 - --feature-gates=RotateKubeletServerCertificate=true"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. Controller Manager SSL/TLS 설정이"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-09" "Controller Manager" "Controller Manager SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-10: etcd 암호화 적용
check_CLD_K8sMaster_10() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep kube-apiserver"
    local cur_state=""
    local remediation="￭ etcd 암호화 적용 1\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래의 파라미터에 파일 추가 - --encryption-provider-config=<> ￭ 안전한 암호화 방식 사용 1\) 아래 명령어 실행 후, --encryption-provider-config 값 확인 # ps –ef | grep kube-apiserver"

    local output
    output=$(ps -ef | grep kube-apiserver 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-K8sMaster-10" "etcd Configuration" "etcd 암호화 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-11: etcd SSL/TLS 적용
check_CLD_K8sMaster_11() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ SSL/TLS 적용을 통한 클라이언트 인증\(etcd peer 및 클라이언트\) 1\) /etc/kubernetes/manifests/etcd.yaml 파일 내 아래와 같이 설정 --client-cert-auth=true 추가 --peer-client-cert-auth=true 수정 \(etcd server의 경우 적용 필요 없음\) ￭ 인증서 관리\(etcd peer 및 클라이언트\) \(인증서설정 예시\) 1\) /etc/kubernetes/manifests/etcd.yaml 파일 내 아래와 같이 설정 --cert-file=<인증서 파일> 추가 --key-file=<키 파일> 추가 --peer-cert-file=<peer 인증서 파일> --peer-key-file=<peer 키 파일> 추가 2\) /etc/kubernetes/manifests/kube-apiserver.yaml 파일 내 아래와 같이 설정 --etcd-certfile=<etcd cert 인증서 파일> 추가 --etcd-keyfile=<etcd 키 파일> 추가 --etcd-cafile=<etcd ca 인증서 파일> 추가 ￭ 인증서 관리\(자체 서명인증서 사용금지\) 1\) /etc/kubernetes/manifests/etcd.yaml 파일 내 아래와 같이 설정 --auto-tls=false --peer-auto-tls=false or 제거 \(etcd server의 경우 적용 필요 없음\) --trusted-ca-file=<인증서 파일> 추가"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. etcd SSL/TLS 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-11" "etcd Configuration" "etcd SSL/TLS 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-12: 컨테이너 권한 제어
check_CLD_K8sMaster_12() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 컨테이너 권한 제어 1\) pod 생성 *.yaml 파일 내에 SecurityContext 설정값 수정 \(예시\) -allowPrivilegeEscalation: false \(추가\) -runAsUser: 0이 아닌 값 \(추가\) -runAsNonRoot: true \(추가\) -capabilities.drop: \(추가\) drop: [\"ALL\"] -seccomprofiles: \(추가\) type: \"ReuntimeDefault\" 2\) namespace 생성 시, namespace에 PodSecurityAdmission 정책을 아래와 같이 적용\(enforce, warn 인수는 privileged가 아닌 restricted로 설정\) # kubectl label —overwrite ns test-restricted pod-security.kubernetes.io/enforce= restricted pod-security.kubernetes.io/warn=restricted"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. PodSecurityAdmission 정책을 통해"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-12" "PodSecurityAdmission" "컨테이너 권한 제어" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-13: 네임스페이스 공유 금지
check_CLD_K8sMaster_13() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 네임스페이스 공유 금지 1\) pod 생성 *.yaml 파일 내 spec 필드에서 아래의 설정값 유무 확인 - hostNetwork: false 또는 파라미터 제거 - hostPID: false 또는 파라미터 제거 - hostIPC: false 또는 파라미터 제거"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 네임스페이스 공유 금지 설정이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-13" "PodSecurityAdmission" "네임스페이스 공유 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-14: 환경설정 파일 권한 설정
check_CLD_K8sMaster_14() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/kubernetes/manifests/kube-apiserver.yaml; ls -al /etc/kubernetes/manifests/kube-controller-manager.yaml; ls -al /etc/kubernetes/manifests/kube-scheduler.yaml"
    local cur_state=""
    local remediation="￭ kube-apiserver.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/kube-apiserver.yaml ￭ kube-controller-manager.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/kube-controller-manager.yaml ￭ kube-scheduler.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/kube-scheduler.yaml ￭ etcd.yaml 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/etcd.yaml ￭ admin.conf 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/admin.conf ￭ scheduler.conf 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/scheduler.conf ￭ controller-manager.conf 소유자 및 소유 그룹은 root, 접근 권한은 644 이하로 설정 # ls –al /etc/kubernetes/manifests/controller-manager.conf"

    local output
    output=$(ls -al /etc/kubernetes/manifests/kube-apiserver.yaml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-K8sMaster-14" "파일 권한 설정" "환경설정 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-15: 인증서 파일 권한 설정
check_CLD_K8sMaster_15() {
    local status="양호"
    local detail=""
    local cmd="ls -al /etc/kubernetes/pki/*.crt; ls -al /etc/kubernetes/pki/*.key; ls -al /var/;ib/kubernetes/ pem"
    local cur_state=""
    local remediation="￭ pki 인증서 파일 접근 권한 확인 # chmod 644 /etc/kubernetes/pki/*.crt ￭ pki 키 파일 접근 권한 확인 # chmod 600 /etc/kubernetes/pki/*.key ￭ Hardway로 설치된 경우\(예시\) # chmod 600 /var/lib/kubernetes/*.pem"

    local output
    output=$(ls -al /etc/kubernetes/pki/*.crt 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-K8sMaster-15" "파일 권한 설정" "인증서 파일 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-16: etcd 데이터 디렉터리 권한 설정
check_CLD_K8sMaster_16() {
    local status="양호"
    local detail=""
    local cmd="ls -ald /var/lib/etcd"
    local cur_state=""
    local remediation="￭ etcd 디렉터리 소유자 및 소유자 그룹 root, 접근 권한 700 이하로 설정 # chmod 700 /var/lib/etcd # chown root:root /var/lib/etcd"

    local output
    output=$(ls -ald /var/lib/etcd 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-K8sMaster-16" "파일 권한 설정" "etcd 데이터 디렉터리 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-K8sMaster-17: 최신 보안 패치 적용
check_CLD_K8sMaster_17() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 최신 보안 업데이트 적용 여부 확인 1\) # kubectl version 2\) 기간 산정해서 보안 패치 적용\(정기 PM 등\) ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 최신 보안 패치가 적용되거나 보안"
    cur_state="수동점검 필요"

    add_result "CLD-K8sMaster-17" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Kubernetes(Master) CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/17] %s 점검 중...                " "$total" "$1"
}


progress "CLD-K8sMaster-01"; check_CLD_K8sMaster_01
progress "CLD-K8sMaster-02"; check_CLD_K8sMaster_02
progress "CLD-K8sMaster-03"; check_CLD_K8sMaster_03
progress "CLD-K8sMaster-04"; check_CLD_K8sMaster_04
progress "CLD-K8sMaster-05"; check_CLD_K8sMaster_05
progress "CLD-K8sMaster-06"; check_CLD_K8sMaster_06
progress "CLD-K8sMaster-07"; check_CLD_K8sMaster_07
progress "CLD-K8sMaster-08"; check_CLD_K8sMaster_08
progress "CLD-K8sMaster-09"; check_CLD_K8sMaster_09
progress "CLD-K8sMaster-10"; check_CLD_K8sMaster_10
progress "CLD-K8sMaster-11"; check_CLD_K8sMaster_11
progress "CLD-K8sMaster-12"; check_CLD_K8sMaster_12
progress "CLD-K8sMaster-13"; check_CLD_K8sMaster_13
progress "CLD-K8sMaster-14"; check_CLD_K8sMaster_14
progress "CLD-K8sMaster-15"; check_CLD_K8sMaster_15
progress "CLD-K8sMaster-16"; check_CLD_K8sMaster_16
progress "CLD-K8sMaster-17"; check_CLD_K8sMaster_17

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
