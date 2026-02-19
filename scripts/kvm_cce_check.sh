#!/bin/bash
###############################################################################
# KVM CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash kvm_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_kvm_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- KVM helper ---
run_virsh() {
    virsh "$@" 2>/dev/null
}


# CLD-KVM-01: 불필요한 계정 제거
check_CLD_KVM_01() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:"
    local cur_state=""
    local remediation="￭ 계정 삭제 1\) 계정 목록 확인 후, 불필요한 계정\(인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 담당자가 실제 업무에 필요 없다고 판단하는 계정\)은 삭제 또는 잠금/만료 설정"

    local output
    output=$(grep /bin/bash /etc/passwd | cut -f1 -d: 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-KVM-01" "보안 설정" "불필요한 계정 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-KVM-02: Session Timeout 설정
check_CLD_KVM_02() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/profile | grep TMOUT"
    local cur_state=""
    local remediation="￭ Sesstion Timeout 설정 1\) \$ vi /etc/profile 2\) readonly TMOUT=600; export TMOUT ￭ 설정 적용 1\) source /etc/profile"

    local output
    output=$(cat /etc/profile | grep TMOUT 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-KVM-02" "보안 설정" "Session Timeout 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-KVM-03: IP 접근 제한 설정
check_CLD_KVM_03() {
    local status="양호"
    local detail=""
    local cmd="iptables -L -n -v; iptables -t -nat -L; iptables -L FORWARD"
    local cur_state=""
    local remediation="￭ iptables 기본 정책을 DROP 설정 후, 접근 허용 IP 등록 1\) iptables –P 명령어를 입력하여 기본 정책 변경\(DROP\) # iptables –P INPUT DROP 2\) iptables –A 명령어를 입력하여 특정 서비스에 대한 접근 허용 IP 등록 # iptables –A INPUT –p tcp –s [접근 허용 IP] --dport [포트 번호] -j ACCEPT 3\) 설정 내용 저장 # service iptables save"

    local output
    output=$(iptables -L -n -v 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-KVM-03" "보안 설정" "IP 접근 제한 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-KVM-04: Default Bridge 제거
check_CLD_KVM_04() {
    local status="양호"
    local detail=""
    local cmd="virsh net-list"
    local cur_state=""
    local remediation="￭ Default Bridge 제거 후, 별도 네트워크 브릿지 생성하여 사용 1\) virsh net-destroy default 2\) virsh net-undefine default 3\) service libvirtd restart"

    local output
    output=$(virsh net-list 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-KVM-04" "보안 설정" "Default Bridge 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-KVM-05: 로그의 정기적 관리 및 백업
check_CLD_KVM_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 로그 기록 및 백업 1\) 로그를 기록하고 있지 않을 경우 로그 기록 및 백업 정책을 세워 로그를 주기적으로 남겨야 하며 로그 파일 또한 주기적으로 백업을 진행해야 함"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그를 기록하고 있으며 로그 파일 백업이"
    cur_state="수동점검 필요"

    add_result "CLD-KVM-05" "보안 설정" "로그의 정기적 관리 및 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-KVM-06: 최신 보안 패치 적용
check_CLD_KVM_06() {
    local status="양호"
    local detail=""
    local cmd="libvirtd —version; virsh version; kvm —version"
    local cur_state=""
    local remediation="￭ 최신 보안 패치 적용 ￭ 인터뷰를 통해 주기적으로 최신 보안 패치 적용 여부 확인"

    local output
    output=$(libvirtd —version 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음 또는 대상 미설치. "
        status="N/A"
    else
        detail="명령 실행 결과 확인. 수동 검증 필요. "
        status="수동점검"
    fi

    add_result "CLD-KVM-06" "보안 설정" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# HV-01: 계정 로그오프/세션 관리
check_HV_01() {
    local status="양호"
    local detail=""
    local cmd="echo \$TMOUT; vi /etc/profile; source /etc/profile"
    local cur_state=""
    local remediation="600초\(10분\) 동안 입력이 없을 경우 접속된 클라이언트 세션을 끊도록 설정 [상세 조치 사례] l XenServer, KVM [사용자 Shell Session Timeout 설정] Step 1\) 호스트에 접속 Step 2\) echo \$TMOUT 명령어를 이용하여 사용자 Shell Session Timeout 설정 확인 \$ echo \$TMOUT Step 3\) Session Timeout 10분을 초과하는 경우 아래 두 라인 추가 \$ vi /etc/profile readonly TMOUT=600; export TMOUT Step 4\) 변경된 설정 적용 \$ source /etc/profile"

    local output
    output=$(echo $TMOUT 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "HV-01" "가상화 장비 > 1. 계정 관리" "계정 로그오프/세션 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-02: 가상화 장비 외부접속 차단
check_HV_02() {
    local status="양호"
    local detail=""
    local cmd="iptables -nL --line-number; iptables -I RH-Firewall-1-INPUT 1 -p tcp -s --dport 22 -j; iptables -I RH-Firewall-1-INPUT 2 -p tcp -s 0.0.0.0/0 --dport 22 -j DROP"
    local cur_state=""
    local remediation="호스트에서 제공하는 방화벽 애플리케이션을 이용하여 서비스 접속 허용 IP 등록 설정 [상세 조치 사례] l XenServer, KVM [IPTables를 통한 접근 통제] Step 1\) 호스트 접속 \$ iptables -nL --line-number Chain INPUT \(policy ACCEPT\) num target prot opt source destination 1 xapi_nbd_input_chain tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:10809 2 ACCEPT 47 -- 0.0.0.0/0 0.0.0.0/0 3 RH-Firewall-1-INPUT all -- 0.0.0.0/0 0.0.0.0/0 … 중간 생략 … Chain RH-Firewall-1-INPUT \(2 references\) num target prot opt source destination 1 ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 2 ACCEPT icmp -- 0.0.0.0/0 0.0.0.0/0 icmptype 255 3 ACCEPT udp -- 0.0.0.0/0 0.0.0.0/0 udp dpt:67 4 ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 ctstate RELATED,ESTABLISHED 5 ACCEPT udp -- 0.0.0.0/0 0.0.0.0/0 ctstate NEW udp dpt:694 11. 가상화 장비 Step 2\) IPTables 정책 목록을 통해 접속 IP 제한 설정 확인 Step 3\) SSH 원격 접속을 허용된 IP로만 제한 \$ iptables -I RH-Firewall-1-INPUT 1 -p tcp -s <허용 IP> --dport 22 -j ACCEPT \$ iptables -I RH-Firewall-1-INPUT 2 -p tcp -s 0.0.0.0/0 --dport 22 -j DROP Step 4\) IPTables의 변경된 정책 저장 및 서비스 재시작 \$ service iptables save \$ service iptables restart"

    status="수동점검"
    detail="서비스 상태 수동 확인 필요. 허용된 IP에서만 관리 콘솔 및 원격 접속이 가능하도록 제한된 경우"
    cur_state="수동점검 필요"

    add_result "HV-02" "가상화 장비 > 1. 계정 관리" "가상화 장비 외부접속 차단" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-04: 가상화 장비 계정 권한 관리
check_HV_04() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:; userdel -r"
    local cur_state=""
    local remediation="불필요한 공용 계정 및 퇴사자 계정 제거 [상세 조치 사례] l XenServer, KVM Step 1\) 호스트 접속 Step 2\) 등록되어 있는 계정 확인 \$ grep /bin/bash /etc/passwd | cut -f1 -d: root user1 Step 3\) 불필요한 계정이 존재하는 경우 해당 계정 삭제 \$ userdel -r <계정명>"

    local output
    output=$(grep /bin/bash /etc/passwd | cut -f1 -d: 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "HV-04" "가상화 장비 > 1. 계정 관리" "가상화 장비 계정 권한 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-05: 가상화 장비 사용자 인증 강화
check_HV_05() {
    local status="양호"
    local detail=""
    local cmd="grep /bin/bash /etc/passwd | cut -f1 -d:; gpasswd -d user1 users"
    local cur_state=""
    local remediation="불필요한 권한이 부여된 계정에 대한 권한 제거 [상세 조치 사례] l KVM Step 1\) 호스트에 접속 Step 2\) bash 계정 목록 확인 \$ grep /bin/bash /etc/passwd | cut -f1 -d: root user1 Step 3\) 불필요한 계정 제거 \$ gpasswd -d user1 users"

    local output
    output=$(grep /bin/bash /etc/passwd | cut -f1 -d: 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "HV-05" "가상화 장비 > 1. 계정 관리" "가상화 장비 사용자 인증 강화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-06: 비밀번호 관리정책 설정
check_HV_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="로그인 계정 비밀번호를 관리 정책에 맞게 설정 [상세 조치 사례] l KVM [RHEL 8 이후 버전 기반 리눅스] Step 1\) 아래 경로 설정 파일 확인 /etc/security/faillock.conf 11. 가상화 장비 /etc/security/pwquality.conf Step 2\) 비밀번호 정책 설정이 되어 있지 않으면 적용 설정 비밀번호 정책 설정 예시\(UNIX 기반\) 예시\)password requisite pam_cracklib.so try_first_pass retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그인 계정 비밀번호 관리 정책이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "HV-06" "가상화 장비 > 1. 계정 관리" "비밀번호 관리정책 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-07: 계정 잠금 임계값 설정
check_HV_07() {
    local status="양호"
    local detail=""
    local cmd="vi /etc/pam.d/system-auth"
    local cur_state=""
    local remediation="로그인 시도 실패 횟수 제한 설정 [상세 조치 사례] l KVM Step 1\) 예시\) RHEL 8 이후 버전 기반 리눅스 아래 경로 설정 파일 확인 /etc/security/faillock.conf /etc/security/pwquality.conf Step 2\) 비밀번호 정책 설정이 되어있지 않으면 적용 설정 비밀번호 정책 설정 예시 # vi /etc/pam.d/system-auth auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root account required /lib/security/pam_tally.so no_magic_root reset 812"

    local output
    output=$(vi /etc/pam.d/system-auth 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "HV-07" "가상화 장비 > 1. 계정 관리" "계정 잠금 임계값 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-08: 시스템 사용 주의사항 출력 설정
check_HV_08() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/ssh/sshd_config | grep Banner; vi /etc/sshd/sshd_config; echo ptp_kvm > /etc/modules-load.d/ptp_kvm.conf"
    local cur_state=""
    local remediation="시스템 사용 주의사항 출력 설정 [상세 조치 사례] l KVM Step 1\) 배너 설정 여부 확인 # cat /etc/ssh/sshd_config | grep \"Banner\" Step 2\) /etc/sshd/sshd_config 파일에 배너 내용 삽입 # vi /etc/sshd/sshd_config Banner /etc/issue.net \(예시\) This system is for the use of authorized users only. l KVM Step 1\) PHC 사용 여부 확인 Step 2\) 사용하지 않으면 활성화 적용 # echo ptp_kvm > /etc/modules-load.d/ptp_kvm.conf Step 3\) /dev/ptp0 시계를 chrony 구성에 대한 참조로 추가 설정 # echo \"refclock PHC /dev/ptp0 poll 2\" >> /etc/chrony.conf Step 4\) chrony 데몬 다시 시작 # systemctl restart chronyd"

    local config_file="/etc/ssh/sshd_config"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "Banner" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: Banner 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "HV-08" "가상화 장비 > 2. 시스템 서비스 관리" "시스템 사용 주의사항 출력 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-10: SNMP Community String 복잡성 적용
check_HV_10() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="SNMP Community String을 복잡도를 만족하는 값으로 설정 [상세 조치 사례] l KVM Step 1\) SNMP 파일에서 Community String 값 확인 sudo vi /etc/snmp/snmpd.conf Step 2\) Community String 설정 후 snmp 서비스 재시작 sudo systemctl enable snmpd sudo systemctl start snmpd"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. SNMP Community String이 복잡도를 만족하는 경우"
    cur_state="수동점검 필요"

    add_result "HV-10" "가상화 장비 > 2. 시스템 서비스 관리" "SNMP Community String 복잡성 적용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-14: 원격 로그 서버 이용
check_HV_14() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="원격 로그 서버 또는 스토리지 연동 설정 [상세 조치 사례] l KVM Step 1\) 원격 로그 서버 사용 확인 Step 2\) \(호스트 서버\) /etc/rsyslog.conf 파일 확인 Step 3\) 원격 로그 서버 전송 지시어 확인 Step 4\) logger 명령어를 통해 전송 여부 확인"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 원격 로그 서버 또는 스토리지가 연동 설정된 경우"
    cur_state="수동점검 필요"

    add_result "HV-14" "가상화 장비 > 2. 시스템 서비스 관리" "원격 로그 서버 이용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# HV-15: 시스템 주요 이벤트 로그 설정
check_HV_15() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/libvirt/libvirtd.conf; log_level =; systemctl restart libvirtd.service"
    local cur_state=""
    local remediation="로그 기록 정책을 내부 정책에 부합하게 설정 [상세 조치 사례] l KVM Step 1\) 호스트에 접속 Step 2\) libvirt 설정파일을 확인하여 로그 레벨 확인 \$ cat /etc/libvirt/libvirtd.conf Step 3\) libvirt 설정파일의 log_level 설정 구문 수정 \$ log_level = Step 4\) 변경 사항 적용을 위해 libvirt 데몬 재시작 \$ systemctl restart libvirtd.service ※ log.level 설정값 레벨 로깅 수준 설명 ERROR 오류 메시지만 기록함 WARNING 경고 및 오류를 기록함 INFO 디버그 항목이 아닌 모든 항목을 기록함 DEBUG 디버그 항목 및 모든 항목을 기록함 836"

    local svc_status
    svc_status=$(is_service_active "libvirtd.service")
    cur_state="libvirtd.service=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="libvirtd.service 서비스 활성화 상태. "
    else
        detail="libvirtd.service 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "HV-15" "가상화 장비 > 2. 시스템 서비스 관리" "시스템 주요 이벤트 로그 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== KVM CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/16] %s 점검 중...                " "$total" "$1"
}


progress "CLD-KVM-01"; check_CLD_KVM_01
progress "CLD-KVM-02"; check_CLD_KVM_02
progress "CLD-KVM-03"; check_CLD_KVM_03
progress "CLD-KVM-04"; check_CLD_KVM_04
progress "CLD-KVM-05"; check_CLD_KVM_05
progress "CLD-KVM-06"; check_CLD_KVM_06
progress "HV-01"; check_HV_01
progress "HV-02"; check_HV_02
progress "HV-04"; check_HV_04
progress "HV-05"; check_HV_05
progress "HV-06"; check_HV_06
progress "HV-07"; check_HV_07
progress "HV-08"; check_HV_08
progress "HV-10"; check_HV_10
progress "HV-14"; check_HV_14
progress "HV-15"; check_HV_15

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
    echo '    "platform": "KVM",'
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

echo "===== KVM CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
