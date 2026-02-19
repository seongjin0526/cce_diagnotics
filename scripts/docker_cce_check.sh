#!/bin/bash
###############################################################################
# Docker CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash docker_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_docker_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Docker helper ---
run_docker_cmd() {
    docker "$@" 2>/dev/null
}


# --- Pre-flight: Docker 설치 확인 및 경로 탐지 ---
DOCKER_BIN=""
DOCKER_CONF=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    DOCKER_BIN=$(command -v docker 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$DOCKER_BIN" ]; then
        ps -ef 2>/dev/null | grep -q '[d]ockerd' && APP_FOUND="true"
    fi

    # 3) 공통 설정 파일 경로 탐색
    for f in /etc/docker/daemon.json ~/.docker/daemon.json; do
        if [ -f "$f" ]; then
            DOCKER_CONF="$f"
            break
        fi
    done

    # 4) 패키지 매니저 확인
    if [ -z "$DOCKER_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'docker-ce\|docker.io' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'docker-ce\|docker' && APP_FOUND="true"
        fi
    fi

    # 5) Docker 소켓 확인
    if [ -S /var/run/docker.sock ]; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$DOCKER_BIN" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Docker 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CLD-Docker-01: 도커 최신 보안 패치 적용
check_CLD_Docker_01() {
    local status="양호"
    local detail=""
    local cmd="docker version; dpkg -l | grep docker.io; rpm -qa | grep docker.io"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(docker version 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-01" "컨테이너 런타임" "도커 최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-02: 도커 그룹에 불필요한 사용자 제거
check_CLD_Docker_02() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/group | grep docker; cat /etc/group | grep docker; cat /etc/group | grep root"
    local cur_state=""
    local remediation="￭ 도커 그룹에서 불필요한 사용자 제거 1\) # vi /etc/group 입력 후, 불필요한 사용자 계정 제거 ￭ 도커 그룹 이름이 dockerroot인 경우 1\) root 그룹, dockerroot 그룹 모두 불필요한 사용자 계정 제거 # vi /etc/group"

    local output
    output=$(cat /etc/group | grep docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-02" "Host 설정" "도커 그룹에 불필요한 사용자 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-03: Docker daemon audit 설정
check_CLD_Docker_03() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /usr/bin/docker; cat | grep /usr/bin/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1\) auditd 설치 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3\) audit 데몬 재시작 # service auditd restart"

    local output
    output=$(auditctl -l | grep /usr/bin/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-03" "Host 설정" "Docker daemon audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-04: /var/lib/docker audit 설정
check_CLD_Docker_04() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /var/lib/docker; cat | grep /var/lib/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1\) auditd 설치 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3\) audit 데몬 재시작 # service auditd restart"

    local output
    output=$(auditctl -l | grep /var/lib/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-04" "Host 설정" "/var/lib/docker audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-05: /etc/docker audit 설정
check_CLD_Docker_05() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /etc/docker; cat | grep /etc/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1\) auditd 설치 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3\) audit 데몬 재시작 # service auditd restart"

    local output
    output=$(auditctl -l | grep /etc/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-05" "Host 설정" "/etc/docker audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-06: docker.service audit 설정
check_CLD_Docker_06() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /lib/systemd/system/docker.service; cat | /lib/systemd/system/docker.service"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1\) auditd 설치 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3\) audit 데몬 재시작 # service auditd restart"

    local output
    output=$(auditctl -l | grep /lib/systemd/system/docker.service 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-06" "Host 설정" "docker.service audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-07: docker.socket audit 설정
check_CLD_Docker_07() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /lib/systemd/system/docker.socket; cat | /lib/systemd/system/docker.socket"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1\) auditd 설치 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 3\) audit 데몬 재시작 # service auditd restart"

    local output
    output=$(auditctl -l | grep /lib/systemd/system/docker.socket 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-07" "Host 설정" "docker.socket audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-08: /etc/default/docker audit 설정
check_CLD_Docker_08() {
    local status="양호"
    local detail=""
    local cmd="auditctl -l | grep /etc/default/docker; cat | /etc/default/docker"
    local cur_state=""
    local remediation="￭ audit 설정 적용 1\) auditd 설치 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 \(Debian 계열\) 2\) /etc/audit/rules.d/audit.rules 파일에 아래의 내용 추가 \(RedHat 계열\) -w /etc/default/docker –k docker 3\) audit 데몬 재시작 # service auditd restart"

    local output
    output=$(auditctl -l | grep /etc/default/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-08" "Host 설정" "/etc/default/docker audit 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-09: default bridege를 통한 컨테이너간 네트워크 트래픽 제한
check_CLD_Docker_09() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker; docker network ls --quiet | xargs docker network inspect --format {{"
    local cur_state=""
    local remediation="￭ 아래와 같은 옵션으로 데몬 재시작 1\) # dockerd --icc=true ￭ /etc/default/docker 파일에 아래와 같은 옵션 추가 후 데몬 재시작 1\) dockerd, docker.socket, docker.service 중지 2\) /etc/default/docker에 DOCKER_OPTS=\"--icc=false\" 문구 추가 3\) /lib/systemd/system/docker.service에 아래의 내용 추가 4\) docker.socket, docker.service, dockerd 재시작 5\) # ps –ef | grep docker 명령어 입력하여 --icc=false 옵션 적용 확인"

    local output
    output=$(ps -ef | grep docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-09" "" "default bridege를 통한 컨테이너간 네트워크 트래픽 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-10: 도커 클라이언트 인증 활성화
check_CLD_Docker_10() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker; docker plugin ls; docker search hello-world"
    local cur_state=""
    local remediation="￭ 인증 플러그인 설치 ￭ 다음과 같은 절차로 인증 설정 1\) 인증 플러그인 설치 2\) 인증 정책 설정 3\) 아래와 같은 옵션으로 데몬 시작 \(방법1\) docker daemon --authorization-plugin=<PLUGIN_ID> \(방법2\) /etc/default/docker 파일에 아래와 같은 옵션 추가 후 데몬 재시작 DOCKER_OPTS=\" --authorization-plugin-<PLUGIN_ID>\" \(방법3\) /etc/docker/daemon.json 파일에 아래와 같은 옵션 추가 후 데몬 재시작 { \"authorization-plugins\": [ \"PLUGIN_ID\" ]}"

    local output
    output=$(ps -ef | grep docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-10" "도커 데몬 설정" "도커 클라이언트 인증 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-11: legacty registry (v1) 비활성화
check_CLD_Docker_11() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker"
    local cur_state=""
    local remediation="￭ 아래와 같은 옵션으로 데몬 시작 1\) # docker daemon —disable-legacy-registry 2\) /etc/default/docker 파일에 아래의 옵션 추가 후 데몬 재시작 Docker_OPTS=\"--disable-legacy-registry\""

    local output
    output=$(ps -ef | grep docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-11" "" "legacty registry \(v1\) 비활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-12: 추가 권한 획득으로부터 컨테이너 제한
check_CLD_Docker_12() {
    local status="양호"
    local detail=""
    local cmd="docker ps —quiet —all; docker inspect | grep SecurityOpt; docker ps --quiet --all | xargs docker inspect --format {{ .Id }}:"
    local cur_state=""
    local remediation="￭ 컨테이너 옵션 실행 1\) # docker run --security-opt=no-new-privileges"

    local output
    output=$(docker ps —quiet —all 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-12" "도커 데몬 설정" "추가 권한 획득으로부터 컨테이너 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-13: docker.service 소유권 설정
check_CLD_Docker_13() {
    local status="양호"
    local detail=""
    local cmd="ls -l /lib/systemd/system/docker.service; stat -c %U:%G /lib/systemd/system/docker.service"
    local cur_state=""
    local remediation="￭ docker.service 파일의 소유자 및 소유 그룹을 root:root로 변경 1\) # chown root:root /lib/systemd/system/docker.service"

    local vuln_found=false
    if [ -e "/lib/systemd/system/docker.service" ]; then
        local result_lib_systemd_system_docker_service
        result_lib_systemd_system_docker_service=$(check_file_owner_perm "/lib/systemd/system/docker.service" "root" "644")
        cur_state+="/lib/systemd/system/docker.service: $result_lib_systemd_system_docker_service; "
        case "$result_lib_systemd_system_docker_service" in
            VULN*) vuln_found=true; detail+="/lib/systemd/system/docker.service 소유자/권한 부적절($result_lib_systemd_system_docker_service). " ;;
            GOOD*) detail+="/lib/systemd/system/docker.service 소유자/권한 적절($result_lib_systemd_system_docker_service). " ;;
            NOT_FOUND) detail+="/lib/systemd/system/docker.service 파일 없음. " ;;
        esac
    else
        detail+="/lib/systemd/system/docker.service 파일 없음. "
        cur_state+="/lib/systemd/system/docker.service: 파일 없음; "
    fi
    if [ -e "/lib/systemd/system/docker.service" ]; then
        local result_lib_systemd_system_docker_service
        result_lib_systemd_system_docker_service=$(check_file_owner_perm "/lib/systemd/system/docker.service" "root" "644")
        cur_state+="/lib/systemd/system/docker.service: $result_lib_systemd_system_docker_service; "
        case "$result_lib_systemd_system_docker_service" in
            VULN*) vuln_found=true; detail+="/lib/systemd/system/docker.service 소유자/권한 부적절($result_lib_systemd_system_docker_service). " ;;
            GOOD*) detail+="/lib/systemd/system/docker.service 소유자/권한 적절($result_lib_systemd_system_docker_service). " ;;
            NOT_FOUND) detail+="/lib/systemd/system/docker.service 파일 없음. " ;;
        esac
    else
        detail+="/lib/systemd/system/docker.service 파일 없음. "
        cur_state+="/lib/systemd/system/docker.service: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="docker.service 파일의 소유자 및" && cur_state="점검 대상 파일 없음"

    add_result "CLD-Docker-13" "도커 데몬 설정 파일" "docker.service 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-14: docker.service 파일 접근 권한 설정
check_CLD_Docker_14() {
    local status="양호"
    local detail=""
    local cmd="systemctl show -p FragmentPath docker.service; ls -l /lib/systemd/system/docker.service"
    local cur_state=""
    local remediation="￭ docker.service 파일 접근 권한 수정 1\) # chmod 644 /lib/systemd/system/docker.service"

    local svc_status
    svc_status=$(is_service_active "-p")
    cur_state="-p=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="-p 서비스 활성화 상태. "
    else
        detail="-p 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CLD-Docker-14" "도커 데몬 설정 파일" "docker.service 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-15: docker.socket 소유권 설정
check_CLD_Docker_15() {
    local status="양호"
    local detail=""
    local cmd="systemctl show -p FragmentPath docker.socket; ls -l /lib/systemd/system/docker.socket; stat -c %U:%G /lib/systemd/system/docker.socket"
    local cur_state=""
    local remediation="￭ docker.socket 파일 소유자 및 소유 그룹 수정 1\) # chown root:root /lib/systemd/system/docker.socket"

    local svc_status
    svc_status=$(is_service_active "-p")
    cur_state="-p=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="-p 서비스 활성화 상태. "
    else
        detail="-p 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CLD-Docker-15" "도커 데몬 설정 파일" "docker.socket 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-16: docker.socket 파일 접근 권한 설정
check_CLD_Docker_16() {
    local status="양호"
    local detail=""
    local cmd="systemctl show -p FragmentPath docker.socket; ls -l /lib/systemd/system/docker.socket"
    local cur_state=""
    local remediation="￭ docker.socket 파일 접근 권한 수정 1\) # chmod 644 /lib/systemd/system/docker.socket"

    local svc_status
    svc_status=$(is_service_active "-p")
    cur_state="-p=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="-p 서비스 활성화 상태. "
    else
        detail="-p 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CLD-Docker-16" "도커 데몬 설정 파일" "docker.socket 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-17: /etc/docker 디렉터리 소유권 설정
check_CLD_Docker_17() {
    local status="양호"
    local detail=""
    local cmd="ls -ld /etc/docker; stat -c %U:%G /etc/docker"
    local cur_state=""
    local remediation="￭ /etc/docker 디렉터리 소유자 및 소유 그룹 수정 1\) # chown root:root /etc/docker"

    local output
    output=$(ls -ld /etc/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-17" "도커 데몬 설정 파일" "/etc/docker 디렉터리 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-18: /etc/docker 디렉터리 접근 권한 설정
check_CLD_Docker_18() {
    local status="양호"
    local detail=""
    local cmd="ls -ld /etc/docker; stat -c %a /etc/docker"
    local cur_state=""
    local remediation="￭ /etc/docker 디렉터리 접근 권한 수정 1\) # chmod 755 /etc/docker"

    local output
    output=$(ls -ld /etc/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-18" "" "/etc/docker 디렉터리 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-19: /var/run/docker.sock 파일 소유권 설정
check_CLD_Docker_19() {
    local status="양호"
    local detail=""
    local cmd="ls -l /var/run/docker.sock; stat -c %U:%G /var/run/docker.sock"
    local cur_state=""
    local remediation="￭ /var/dun/docker.sock 파일 소유자 및 소유 그룹 수정 1\) # chown root:docker /var/run/docker.sock \(Debian 계열\) 2\) # chown root:docker /run/docker.sock \(RedHat 계열\)"

    local output
    output=$(ls -l /var/run/docker.sock 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-19" "도커 데몬 설정 파일" "/var/run/docker.sock 파일 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-20: /var/run/docker.sock 파일 접근 권한 설정
check_CLD_Docker_20() {
    local status="양호"
    local detail=""
    local cmd="ls -l /var/run/docker.sock; stat -c %a /var/run/docker.sock"
    local cur_state=""
    local remediation="￭ /var/dun/docker.sock 파일 접근 권한 수정 1\) # chmod 660 /var/run/docker.sock"

    local output
    output=$(ls -l /var/run/docker.sock 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-20" "도커 데몬 설정 파일" "/var/run/docker.sock 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-21: daemon.json 파일 소유권 설정
check_CLD_Docker_21() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/docker/daemon.json; stat -c %U:%G /etc/docker/daemon.json"
    local cur_state=""
    local remediation="￭ daemon.json 파일 소유자 및 소유 그룹 수정 1\) # chown root:root /etc/docker/daemon.json"

    local output
    output=$(ls -l /etc/docker/daemon.json 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-21" "도커 데몬 설정 파일" "daemon.json 파일 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-22: daemon.json 파일 접근 권한 설정
check_CLD_Docker_22() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/docker/daemon.json; stat -c %a /etc/docker/daemon.json"
    local cur_state=""
    local remediation="￭ daemon.json 파일 접근 권한 수정 1\) # chmod 644 /etc/docker/daemon.json"

    local output
    output=$(ls -l /etc/docker/daemon.json 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-22" "도커 데몬 설정 파일" "daemon.json 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-23: /etc/default/docker 파일 소유권 설정
check_CLD_Docker_23() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/default/docker; stat -c %U:%G /etc/default/docker"
    local cur_state=""
    local remediation="￭ /etc/default/docker 파일 소유자 및 소유 그룹 수정 1\) # chown root:root /etc/default/docker \(Debian 계열\) 2\) # chown root:root /etc/sysconfig/docker \(RedHat 계열\)"

    local output
    output=$(ls -l /etc/default/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-23" "도커 데몬 설정 파일" "/etc/default/docker 파일 소유권 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-24: /etc/default/docker 파일 접근 권한 설정
check_CLD_Docker_24() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/default/docker; stat -c %a /etc/default/docker"
    local cur_state=""
    local remediation="￭ /etc/default/docker 파일 접근 권한 수정 1\) # chmod 644 /etc/default/docker \(Debian 계열\) 2\) # chmod 644 /etc/sysconfig/docker \(RedHat 계열\)"

    local output
    output=$(ls -l /etc/default/docker 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-24" "도커 데몬 설정 파일" "/etc/default/docker 파일 접근 권한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-25: root가 아닌 user로 컨테이너 실행
check_CLD_Docker_25() {
    local status="양호"
    local detail=""
    local cmd="docker ps --quiet --all | xargs docker inspect --format {{ .Id }}:"
    local cur_state=""
    local remediation="￭ Dockerfile에 아래의 내용 추가 1\) RUN useradd –d /home/username –m s /bin/bash username USER username"

    local output
    output=$(docker ps --quiet --all | xargs docker inspect --format {{ .Id }}: 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-25" "컨테이너 이미지 및" "root가 아닌 user로 컨테이너 실행" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-26: 도커를 위한 컨텐츠 신뢰성 활성화
check_CLD_Docker_26() {
    local status="양호"
    local detail=""
    local cmd="echo \$DOCKER_CONTENT_TRUST"
    local cur_state=""
    local remediation="￭ 사용하는 shell에 아래의 내용을 추가 1\) # export DOCKER_CONTENT_TRUST=1"

    local output
    output=$(echo $DOCKER_CONTENT_TRUST 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Docker-26" "컨테이너 이미지 및" "도커를 위한 컨텐츠 신뢰성 활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-27: 컨테이너 SELinux 보안 옵션 설정
check_CLD_Docker_27() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep docker | grep selinux-enabled; docker ps --quiet --all | xargs docker inspect --format {{ .Id }}:"
    local cur_state=""
    local remediation="￭ SELinux 활성화 1\) /etc/default/docker 파일 내 DOCKER_OPTS=\"--selinux-enabled\" 설정 2\) /lib/systemd/system/docker.service 파일에 아래의 내용 수정 3\) docker 데몬 재시작 4\) --selinux-enabled 옵션 활성화 확인"

    local output
    output=$(ps -ef | grep docker | grep selinux-enabled 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-27" "컨테이너 런타임" "컨테이너 SELinux 보안 옵션 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-28: 컨테이너에서 ssh 사용 금지
check_CLD_Docker_28() {
    local status="양호"
    local detail=""
    local cmd="docker ps —quiet; docker exec ps -el"
    local cur_state=""
    local remediation="￭ 컨테이너에서 ssh를 제거하고 docker exec, docker attach 명령어 통해 컨테이너 접속 1\) # docker exec —interactive —tty \$INSTANCE_ID sh 2\) # docker attach \$INSTANCE_ID"

    local output
    output=$(docker ps —quiet 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-28" "컨테이너 런타임" "컨테이너에서 ssh 사용 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-29: 컨테이너에 PREVILEGED 포트 매핑 금지
check_CLD_Docker_29() {
    local status="양호"
    local detail=""
    local cmd="docker ps —quiet —all; docker inspect | grep -A 50 NetworkSettings | grep Ports; docker ps -a"
    local cur_state=""
    local remediation="￭ privileged가 아닌 포트로 매핑 1\) 컨테이너 시작 시, 컨테이너 포트를 호스트의 privileged 포트가 아닌 포트로 매핑 2\) Docker 파일에서 privileged 포트 매핑 선언을 호스팅하는 컨테이너가 없는지 확인"

    local output
    output=$(docker ps —quiet —all 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-29" "" "컨테이너에 PREVILEGED 포트 매핑 금지" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-30: PIDs cgroup 제한
check_CLD_Docker_30() {
    local status="양호"
    local detail=""
    local cmd="docker ps --quiet --all | xargs docker inspect --format {{ .Id }}:PidsLimit="
    local cur_state=""
    local remediation="￭ 컨테이너 시작 시 —pids-limit 플래그를 사용 \(예시\) 1\) # docker run –it —pids-limit 100 <image_id>"

    local output
    output=$(docker ps --quiet --all | xargs docker inspect --format {{ .Id }}:PidsLimit= 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-30" "컨테이너 런타임" "PIDs cgroup 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-31: 도커의 default bridge docker() 사용 제한
check_CLD_Docker_31() {
    local status="양호"
    local detail=""
    local cmd="ifconfig | grep docker"
    local cur_state=""
    local remediation="￭ Default bridge docker\(\) 비활성화 1\) /etc/default/docker 파일 내 DOCKER_OPTS=\"--icc=false\" 설정 2\) /lib/systemd/system/docker.service 파일에 아래의 내용 수정 3\) docker 데몬 재시작 4\) # docker network inspect bridge 5\) 사용자 정의 네트워크 생성, 지정 \(예시\) / daemon.json 작성 시, \"icc=false\" 옵션 추가 # docker network create my-net 6\) 아래 명령어를 입력하여 docker\(\) 제거 확인 및 사용자 정의 네트워크 확인 # docker network ls"

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

    add_result "CLD-Docker-31" "컨테이너 런타임" "도커의 default bridge docker\(\) 사용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Docker-32: 호스트의 user namespaces 공유 제한
check_CLD_Docker_32() {
    local status="양호"
    local detail=""
    local cmd="docker ps --quiet --all | xargs docker inspect --format {{ .Id }}"
    local cur_state=""
    local remediation="￭ 호스트, 컨테이너 user namespaces 공유 제한 1\) # docker run --rm -it --userns=host ubuntu bash \(취약\) 2\) # docker run --rm -it ubuntu bash \(양호\)"

    local output
    output=$(docker ps --quiet --all | xargs docker inspect --format {{ .Id }} 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-Docker-32" "" "호스트의 user namespaces 공유 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Docker CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/32] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Docker-01"; check_CLD_Docker_01
progress "CLD-Docker-02"; check_CLD_Docker_02
progress "CLD-Docker-03"; check_CLD_Docker_03
progress "CLD-Docker-04"; check_CLD_Docker_04
progress "CLD-Docker-05"; check_CLD_Docker_05
progress "CLD-Docker-06"; check_CLD_Docker_06
progress "CLD-Docker-07"; check_CLD_Docker_07
progress "CLD-Docker-08"; check_CLD_Docker_08
progress "CLD-Docker-09"; check_CLD_Docker_09
progress "CLD-Docker-10"; check_CLD_Docker_10
progress "CLD-Docker-11"; check_CLD_Docker_11
progress "CLD-Docker-12"; check_CLD_Docker_12
progress "CLD-Docker-13"; check_CLD_Docker_13
progress "CLD-Docker-14"; check_CLD_Docker_14
progress "CLD-Docker-15"; check_CLD_Docker_15
progress "CLD-Docker-16"; check_CLD_Docker_16
progress "CLD-Docker-17"; check_CLD_Docker_17
progress "CLD-Docker-18"; check_CLD_Docker_18
progress "CLD-Docker-19"; check_CLD_Docker_19
progress "CLD-Docker-20"; check_CLD_Docker_20
progress "CLD-Docker-21"; check_CLD_Docker_21
progress "CLD-Docker-22"; check_CLD_Docker_22
progress "CLD-Docker-23"; check_CLD_Docker_23
progress "CLD-Docker-24"; check_CLD_Docker_24
progress "CLD-Docker-25"; check_CLD_Docker_25
progress "CLD-Docker-26"; check_CLD_Docker_26
progress "CLD-Docker-27"; check_CLD_Docker_27
progress "CLD-Docker-28"; check_CLD_Docker_28
progress "CLD-Docker-29"; check_CLD_Docker_29
progress "CLD-Docker-30"; check_CLD_Docker_30
progress "CLD-Docker-31"; check_CLD_Docker_31
progress "CLD-Docker-32"; check_CLD_Docker_32

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
    echo '    "platform": "Docker",'
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

echo "===== Docker CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
