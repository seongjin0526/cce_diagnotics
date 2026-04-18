#!/bin/bash
###############################################################################
# Linux CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash linux_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# --- JSON helper functions ---
results=()

normalize_trace_value() {
    printf '%s' "$1" | tr '\t\r\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//'
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
    local status="$5"       # "양호" / "취약" / "N/A" / "수동점검"
    local detail="$6"
    local source="$7"       # "기반시설" / "클라우드" / "공통"
    local command="$8"       # 수행 명령어
    local current_state="$9" # 현재 상태 (명령어 실행 결과)
    local remediation="${10}" # 조치방법
    local raw_detail="$detail"
    local raw_command="$command"
    local raw_current_state="$current_state"

    # Escape strings for JSON
    detail=$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    command=$(echo "$command" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g' | tr '\n' ' ' | sed 's/  */ /g')

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

status_rank() {
    case "$1" in
        "취약") echo 3 ;;
        "수동점검") echo 2 ;;
        "양호") echo 1 ;;
        *) echo 0 ;;
    esac
}

merge_status() {
    local current="$1"
    local candidate="$2"

    if [ "$(status_rank "$candidate")" -gt "$(status_rank "$current")" ]; then
        echo "$candidate"
    else
        echo "$current"
    fi
}

mail_sendmail_active() {
    ps -ef 2>/dev/null | grep -v grep | grep -qE '[s]endmail'
}

mail_postfix_active() {
    systemctl is-active postfix &>/dev/null || \
    ps -ef 2>/dev/null | grep -v grep | grep -qE '[p]ostfix'
}

mail_exim_active() {
    systemctl is-active exim &>/dev/null || \
    systemctl is-active exim4 &>/dev/null || \
    ps -ef 2>/dev/null | grep -v grep | grep -qE '[e]xim([0-9]|4)?'
}

last_permission_digit() {
    local perm="$1"
    printf '%s' "$perm" | sed 's/.*\(.\)$/\1/'
}

mail_exim_config() {
    for f in /etc/exim/exim.conf /etc/exim4/exim4.conf; do
        if [ -f "$f" ]; then
            printf '%s\n' "$f"
            return 0
        fi
    done
    return 1
}

###############################################################################
# 1. 계정 관리
###############################################################################

# ISMS-U-01: root 계정 원격 접속 제한
check_U01() {
    local status="양호"
    local detail=""
    local cmd="grep -i '^PermitRootLogin' /etc/ssh/sshd_config; systemctl is-active telnet.socket"
    local cur_state=""
    local remediation="/etc/ssh/sshd_config 파일에서 PermitRootLogin no 설정 후 systemctl restart sshd 실행. Telnet 서비스 비활성화 권장."

    # Check SSH PermitRootLogin
    if [ -f /etc/ssh/sshd_config ]; then
        local ssh_root
        ssh_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        cur_state="PermitRootLogin=${ssh_root:-미설정}"
        if [ -z "$ssh_root" ]; then
            detail="SSH PermitRootLogin 설정 없음(기본값 사용). "
            status="취약"
        elif echo "$ssh_root" | grep -iq "no"; then
            detail="SSH PermitRootLogin=no. "
        elif echo "$ssh_root" | grep -iq "prohibit-password\|without-password"; then
            detail="SSH PermitRootLogin=$ssh_root (패스워드 인증 차단). "
        else
            detail="SSH PermitRootLogin=$ssh_root. "
            status="취약"
        fi
    else
        detail="SSH 설정파일 없음. "
        cur_state="/etc/ssh/sshd_config 파일 없음"
    fi

    # Check Telnet
    if systemctl is-active telnet.socket &>/dev/null || \
       systemctl is-active xinetd &>/dev/null && [ -f /etc/xinetd.d/telnet ]; then
        local telnet_disabled
        telnet_disabled=$(grep -i "disable" /etc/xinetd.d/telnet 2>/dev/null | grep -i "yes")
        if [ -z "$telnet_disabled" ]; then
            if [ -f /etc/securetty ]; then
                local pts_entries
                pts_entries=$(grep -c "^pts/" /etc/securetty 2>/dev/null)
                if [ "$pts_entries" -gt 0 ]; then
                    detail+="Telnet 활성화, securetty에 pts 항목 ${pts_entries}개 존재. "
                    status="취약"
                else
                    detail+="Telnet 활성화, securetty에 pts 항목 없음. "
                fi
            else
                detail+="Telnet 활성화, /etc/securetty 파일 없음(최신 배포판). "
            fi
            cur_state+="; Telnet=active"
        fi
    else
        detail+="Telnet 서비스 비활성화. "
        cur_state+="; Telnet=inactive"
    fi

    add_result "ISMS-U-01" "계정 관리" "root 계정 원격 접속 제한" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-02: 비밀번호 관리정책 설정
check_U02() {
    local status="양호"
    local detail=""
    local cmd="grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_MIN_LEN' /etc/login.defs; grep -E '^minlen|^dcredit|^ucredit|^lcredit|^ocredit' /etc/security/pwquality.conf"
    local cur_state=""
    local remediation="/etc/login.defs에서 PASS_MAX_DAYS 90, PASS_MIN_DAYS 1, PASS_MIN_LEN 8 설정. /etc/security/pwquality.conf에서 minlen=8, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1 설정."

    # Check /etc/login.defs
    if [ -f /etc/login.defs ]; then
        local pass_max
        pass_max=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        local pass_min
        pass_min=$(grep -E "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        local pass_len
        pass_len=$(grep -E "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')

        detail="login.defs: MAX_DAYS=${pass_max:-미설정}, MIN_DAYS=${pass_min:-미설정}, MIN_LEN=${pass_len:-미설정}. "
        cur_state="PASS_MAX_DAYS=${pass_max:-미설정}, PASS_MIN_DAYS=${pass_min:-미설정}, PASS_MIN_LEN=${pass_len:-미설정}"

        if [ -n "$pass_max" ] && [ "$pass_max" -le 90 ] 2>/dev/null && [ "$pass_max" -gt 0 ]; then
            :
        else
            status="취약"
        fi
    else
        detail="login.defs 파일 없음. "
        cur_state="/etc/login.defs 파일 없음"
        status="취약"
    fi

    # Check pwquality.conf
    if [ -f /etc/security/pwquality.conf ]; then
        local minlen
        minlen=$(grep -E "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        local dcredit
        dcredit=$(grep -E "^dcredit" /etc/security/pwquality.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        local ucredit
        ucredit=$(grep -E "^ucredit" /etc/security/pwquality.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        local lcredit
        lcredit=$(grep -E "^lcredit" /etc/security/pwquality.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        local ocredit
        ocredit=$(grep -E "^ocredit" /etc/security/pwquality.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')

        detail+="pwquality.conf: minlen=${minlen:-미설정}, dcredit=${dcredit:-미설정}, ucredit=${ucredit:-미설정}, lcredit=${lcredit:-미설정}, ocredit=${ocredit:-미설정}. "
        cur_state+="; pwquality: minlen=${minlen:-미설정}, dcredit=${dcredit:-미설정}, ucredit=${ucredit:-미설정}, lcredit=${lcredit:-미설정}, ocredit=${ocredit:-미설정}"

        if [ -z "$minlen" ] || [ "${minlen:-0}" -lt 8 ]; then
            status="취약"
        fi
    else
        local pam_pwqual=""
        for f in /etc/pam.d/system-auth /etc/pam.d/common-password; do
            if [ -f "$f" ]; then
                pam_pwqual=$(grep "pam_pwquality\|pam_cracklib" "$f" 2>/dev/null)
                if [ -n "$pam_pwqual" ]; then
                    detail+="PAM($f): $(echo "$pam_pwqual" | head -1). "
                    cur_state+="; PAM: $(echo "$pam_pwqual" | head -1)"
                    break
                fi
            fi
        done
        if [ -z "$pam_pwqual" ]; then
            detail+="패스워드 복잡도 설정 없음. "
            cur_state+="; 패스워드 복잡도 설정 없음"
            status="취약"
        fi
    fi

    add_result "ISMS-U-02" "계정 관리" "비밀번호 관리정책 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-03: 계정 잠금 임계값 설정
check_U03() {
    local status="취약"
    local detail=""
    local deny_val=""
    local cmd="grep -E '^deny' /etc/security/faillock.conf; grep -E 'pam_faillock|pam_tally' /etc/pam.d/system-auth /etc/pam.d/common-auth"
    local cur_state=""
    local remediation="/etc/security/faillock.conf에서 deny=5 설정 또는 /etc/pam.d/system-auth(common-auth)에 pam_faillock.so deny=5 설정."

    # Check faillock.conf (RHEL 8+)
    if [ -f /etc/security/faillock.conf ]; then
        deny_val=$(grep -E "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        if [ -n "$deny_val" ]; then
            detail="faillock.conf: deny=${deny_val}. "
            cur_state="faillock.conf: deny=${deny_val}"
            if [ "$deny_val" -le 10 ] 2>/dev/null; then
                status="양호"
            fi
        fi
    fi

    # Check PAM files
    for f in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
        if [ -f "$f" ]; then
            local pam_deny
            pam_deny=$(grep -E "pam_faillock|pam_tally" "$f" 2>/dev/null | grep -oP 'deny=\K[0-9]+' | head -1)
            if [ -n "$pam_deny" ]; then
                detail+="$f: deny=${pam_deny}. "
                cur_state+="${f}: deny=${pam_deny}; "
                if [ "$pam_deny" -le 10 ] 2>/dev/null; then
                    status="양호"
                fi
            fi
        fi
    done

    if [ -z "$detail" ]; then
        detail="계정 잠금 임계값 미설정. "
        cur_state="계정 잠금 임계값 미설정"
    fi

    add_result "ISMS-U-03" "계정 관리" "계정 잠금 임계값 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-04: 비밀번호 파일 보호
check_U04() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/shadow; awk -F: '\$2 != \"x\" && \$2 != \"!\" && \$2 != \"*\" && \$2 != \"!!\" {print \$1}' /etc/passwd"
    local cur_state=""
    local remediation="pwconv 명령으로 shadow 패스워드 체계 적용. /etc/passwd 파일의 두번째 필드가 x인지 확인."

    if [ -f /etc/shadow ]; then
        detail="/etc/shadow 파일 존재. "
        cur_state="/etc/shadow 파일 존재"
    else
        detail="/etc/shadow 파일 없음. "
        cur_state="/etc/shadow 파일 없음"
        status="취약"
    fi

    local plain_pw
    plain_pw=$(awk -F: '$2 != "x" && $2 != "!" && $2 != "*" && $2 != "!!" {print $1}' /etc/passwd 2>/dev/null)
    if [ -n "$plain_pw" ]; then
        detail+="shadow 미사용 계정: $plain_pw. "
        cur_state+="; shadow 미사용 계정: $plain_pw"
        status="취약"
    else
        detail+="모든 계정 shadow 비밀번호 사용. "
        cur_state+="; 모든 계정 shadow 사용"
    fi

    add_result "ISMS-U-04" "계정 관리" "비밀번호 파일 보호" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-05: root 이외의 UID가 '0' 금지
check_U05() {
    local status="양호"
    local detail=""
    local cmd="awk -F: '\$3 == 0' /etc/passwd"
    local cur_state=""
    local remediation="root 외 UID=0인 계정의 UID를 변경하거나 불필요 시 계정 삭제."

    local uid0_accounts
    uid0_accounts=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
    cur_state="UID=0 계정: root$([ -n "$uid0_accounts" ] && echo ", $uid0_accounts")"
    if [ -n "$uid0_accounts" ]; then
        detail="UID=0 계정: root, $uid0_accounts. "
        status="취약"
    else
        detail="root 외 UID=0 계정 없음. "
    fi

    add_result "ISMS-U-05" "계정 관리" "root 이외의 UID가 0 금지" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-06: 사용자 계정 su 기능 제한
check_U06() {
    local status="취약"
    local detail=""
    local cmd="grep 'pam_wheel.so' /etc/pam.d/su; stat -c '%a' /usr/bin/su"
    local cur_state=""
    local remediation="/etc/pam.d/su 파일에서 'auth required pam_wheel.so' 주석 해제. wheel 그룹에 su 허용 사용자 등록 (usermod -aG wheel 사용자)."

    # Check PAM su configuration
    if [ -f /etc/pam.d/su ]; then
        local pam_wheel
        pam_wheel=$(grep -E "^auth\s+required\s+pam_wheel.so" /etc/pam.d/su 2>/dev/null)
        if [ -n "$pam_wheel" ]; then
            detail="PAM su에 pam_wheel.so 설정됨: $(echo "$pam_wheel" | head -1). "
            cur_state="pam_wheel.so 설정됨"
            status="양호"
        else
            detail="PAM su에 pam_wheel.so 미설정 또는 주석 처리됨. "
            cur_state="pam_wheel.so 미설정"
        fi
    else
        detail="/etc/pam.d/su 파일 없음. "
        cur_state="/etc/pam.d/su 파일 없음"
    fi

    # Check su binary permission
    local su_perm
    su_perm=$(stat -c '%a' /usr/bin/su 2>/dev/null || stat -c '%a' /bin/su 2>/dev/null)
    if [ -n "$su_perm" ]; then
        detail+="su 명령어 권한: ${su_perm}. "
        cur_state+="; su 권한=${su_perm}"
    fi

    add_result "ISMS-U-06" "계정 관리" "사용자 계정 su 기능 제한" "상" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-07: 불필요한 계정 제거
check_U07() {
    local status="수동점검"
    local detail=""
    local cmd="awk -F: '\$7 !~ /nologin|false/ && \$3 >= 1000 {print \$1}' /etc/passwd"
    local cur_state=""
    local remediation="불필요한 계정 삭제 (userdel 계정명) 또는 쉘을 /sbin/nologin으로 변경 (usermod -s /sbin/nologin 계정명)."

    local shell_accounts
    shell_accounts=$(awk -F: '$7 !~ /nologin|false|sync|shutdown|halt/ && $3 >= 1000 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ', ')

    local default_accounts
    default_accounts=$(awk -F: '$7 !~ /nologin|false|sync|shutdown|halt/ && $1 ~ /^(games|gopher|ftp|news|lp|uucp|nuucp)$/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ', ')

    detail="로그인 가능 일반계정: ${shell_accounts:-없음}. "
    cur_state="로그인 가능 계정: ${shell_accounts:-없음}"
    if [ -n "$default_accounts" ]; then
        detail+="불필요 가능성 있는 기본계정: ${default_accounts}. "
        cur_state+="; 불필요 기본계정: ${default_accounts}"
        status="취약"
    else
        detail+="불필요한 기본계정 미발견(수동 확인 필요). "
    fi

    add_result "ISMS-U-07" "계정 관리" "불필요한 계정 제거" "하" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-08: 관리자 그룹에 최소한의 계정 포함
check_U08() {
    local status="수동점검"
    local detail=""
    local cmd="grep '^root:' /etc/group"
    local cur_state=""
    local remediation="root 그룹(GID=0)에서 불필요한 계정 제거. gpasswd -d 사용자 root 명령 사용."

    local root_group_members
    root_group_members=$(awk -F: '$1 == "root" {print $4}' /etc/group 2>/dev/null)
    detail="root 그룹 멤버: ${root_group_members:-없음}. "
    cur_state="root 그룹 멤버: ${root_group_members:-없음}"

    if [ -z "$root_group_members" ]; then
        status="양호"
    fi

    add_result "ISMS-U-08" "계정 관리" "관리자 그룹에 최소한의 계정 포함" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-09: 계정이 존재하지 않는 GID 금지
check_U09() {
    local status="수동점검"
    local detail=""
    local cmd="awk -F: '{print \$3}' /etc/group; awk -F: '{print \$4}' /etc/passwd"
    local cur_state=""
    local remediation="사용하지 않는 그룹 삭제 (groupdel 그룹명)."

    local used_gids
    used_gids=$(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u)

    local unused_groups=""
    while IFS=: read -r name _ gid _; do
        if ! echo "$used_gids" | grep -qw "$gid" 2>/dev/null; then
            local members
            members=$(awk -F: -v g="$name" '$1 == g {print $4}' /etc/group)
            if [ -z "$members" ]; then
                unused_groups+="$name($gid) "
            fi
        fi
    done < /etc/group

    if [ -n "$unused_groups" ]; then
        detail="사용되지 않는 그룹: ${unused_groups:0:200}. "
        cur_state="미사용 그룹: ${unused_groups:0:200}"
    else
        detail="미사용 그룹 없음. "
        cur_state="미사용 그룹 없음"
        status="양호"
    fi

    add_result "ISMS-U-09" "계정 관리" "계정이 존재하지 않는 GID 금지" "하" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-10: 동일한 UID 금지
check_U10() {
    local status="양호"
    local detail=""
    local cmd="awk -F: '{print \$3}' /etc/passwd | sort | uniq -d"
    local cur_state=""
    local remediation="중복 UID 계정의 UID를 고유한 값으로 변경 (usermod -u 새UID 계정명) 또는 불필요한 계정 삭제."

    local dup_uids
    dup_uids=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)
    if [ -n "$dup_uids" ]; then
        local dup_info=""
        for uid in $dup_uids; do
            local users
            users=$(awk -F: -v u="$uid" '$3 == u {print $1}' /etc/passwd | tr '\n' ',')
            dup_info+="UID=$uid: $users "
        done
        detail="중복 UID 발견: $dup_info. "
        cur_state="중복 UID: $dup_info"
        status="취약"
    else
        detail="중복 UID 없음. "
        cur_state="중복 UID 없음"
    fi

    add_result "ISMS-U-10" "계정 관리" "동일한 UID 금지" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-11: 사용자 Shell 점검
check_U11() {
    local status="양호"
    local detail=""
    local cmd="awk -F: '\$1 ~ /^(daemon|bin|sys|adm|nobody|games|lp|uucp)$/ {print \$1\":\"\$7}' /etc/passwd"
    local cur_state=""
    local remediation="로그인 불필요 계정의 쉘을 /sbin/nologin 또는 /bin/false로 변경 (usermod -s /sbin/nologin 계정명)."

    local bad_shell_accounts
    bad_shell_accounts=$(awk -F: '$7 !~ /nologin|false|sync|shutdown|halt/ && $1 ~ /^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher|lp|uucp)$/ {print $1":"$7}' /etc/passwd 2>/dev/null | tr '\n' ', ')

    if [ -n "$bad_shell_accounts" ]; then
        detail="로그인 불필요 계정에 쉘 부여됨: $bad_shell_accounts. "
        cur_state="$bad_shell_accounts"
        status="취약"
    else
        detail="로그인 불필요 계정 쉘 설정 적절. "
        cur_state="로그인 불필요 계정 쉘 설정 적절"
    fi

    add_result "ISMS-U-11" "계정 관리" "사용자 Shell 점검" "하" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-12: 세션 종료 시간 설정
check_U12() {
    local status="취약"
    local detail=""
    local cmd="grep -E 'TMOUT' /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc"
    local cur_state=""
    local remediation="/etc/profile 또는 /etc/profile.d/ 에 'export TMOUT=300' 추가 (300초=5분 권장, 최대 600초)."

    local tmout=""
    for f in /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc; do
        if [ -f "$f" ]; then
            local val
            val=$(grep -E "^(export\s+)?TMOUT=" "$f" 2>/dev/null | grep -oP 'TMOUT=\K[0-9]+' | tail -1)
            if [ -n "$val" ]; then
                tmout="$val"
                detail+="$f: TMOUT=$val. "
                cur_state+="$f: TMOUT=$val; "
            fi
        fi
    done

    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null && [ "$tmout" -gt 0 ]; then
        status="양호"
    elif [ -n "$tmout" ]; then
        detail+="TMOUT 값이 600초 초과. "
    else
        detail="TMOUT 미설정. "
        cur_state="TMOUT 미설정"
    fi

    add_result "ISMS-U-12" "계정 관리" "세션 종료 시간 설정" "하" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-13: 안전한 비밀번호 암호화 알고리즘 사용
check_U13() {
    local status="양호"
    local detail=""
    local cmd="awk -F: '\$2 ~ /^\\\$/ {split(\$2,a,\"\$\"); print a[2]}' /etc/shadow | sort -u"
    local cur_state=""
    local remediation="SHA-512 이상 해시 알고리즘 사용. /etc/login.defs에서 ENCRYPT_METHOD SHA512 설정. 기존 MD5 계정은 비밀번호 재설정 필요."

    if [ -r /etc/shadow ]; then
        local hash_types
        hash_types=$(awk -F: '$2 ~ /^\$/ {split($2,a,"$"); print a[2]}' /etc/shadow 2>/dev/null | sort -u | tr '\n' ',')

        detail="사용 중인 해시 알고리즘 ID: ${hash_types:-없음}. "
        cur_state="해시 알고리즘 ID: ${hash_types:-없음} (1=MD5, 5=SHA-256, 6=SHA-512, y=yescrypt)"

        if echo "$hash_types" | grep -qE "^1,|,1,|,1$|^1$"; then
            detail+="MD5 사용 계정 존재. "
            status="취약"
        fi
        if echo "$hash_types" | grep -qE "6|5|y|2b"; then
            detail+="SHA-256/SHA-512/yescrypt/bcrypt 사용. "
        fi
    else
        detail="/etc/shadow 읽기 불가. "
        cur_state="/etc/shadow 읽기 불가"
        status="수동점검"
    fi

    add_result "ISMS-U-13" "계정 관리" "안전한 비밀번호 암호화 알고리즘 사용" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

###############################################################################
# 2. 파일 및 디렉토리 관리
###############################################################################

# ISMS-U-14: root 홈, 패스 디렉터리 권한 및 패스 설정
check_U14() {
    local status="양호"
    local detail=""
    local cmd="echo \$PATH"
    local cur_state=""
    local remediation="PATH 환경변수에서 '.' (현재 디렉토리)을 제거. /etc/profile, ~/.bash_profile 등에서 PATH 수정."

    local path_val
    path_val=$(echo "$PATH")
    cur_state="PATH=$path_val"

    if echo ":$path_val:" | grep -q ":\.:" 2>/dev/null; then
        detail="PATH에 '.' 포함: $path_val. "
        status="취약"
    elif echo "$path_val" | grep -q "^\.\:" 2>/dev/null; then
        detail="PATH 맨 앞에 '.' 포함. "
        status="취약"
    else
        detail="PATH에 '.' 미포함. "
    fi

    add_result "ISMS-U-14" "파일 및 디렉터리 관리" "root 홈, 패스 디렉터리 권한 및 패스 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-15: 파일 및 디렉터리 소유자 설정
check_U15() {
    local status="양호"
    local detail=""
    local cmd="find /etc /tmp /bin /sbin /usr -nouser -o -nogroup"
    local cur_state=""
    local remediation="소유자 없는 파일에 적절한 소유자 지정 (chown 사용자:그룹 파일경로) 또는 불필요 시 삭제."

    local noowner_files
    noowner_files=$(find /etc /tmp /bin /sbin /usr 2>/dev/null \( -nouser -o -nogroup \) -xdev 2>/dev/null | head -20)

    if [ -n "$noowner_files" ]; then
        local count
        count=$(echo "$noowner_files" | wc -l)
        detail="소유자 없는 파일/디렉터리 ${count}개 발견: $(echo "$noowner_files" | head -5 | tr '\n' ', '). "
        cur_state="소유자 없는 파일 ${count}개: $(echo "$noowner_files" | head -5 | tr '\n' ', ')"
        status="취약"
    else
        detail="소유자 없는 파일/디렉터리 없음. "
        cur_state="소유자 없는 파일 없음"
    fi

    add_result "ISMS-U-15" "파일 및 디렉터리 관리" "파일 및 디렉터리 소유자 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-16: /etc/passwd 파일 소유자 및 권한 설정
check_U16() {
    local result
    result=$(check_file_owner_perm "/etc/passwd" "root" 644)
    local status="양호"
    if [[ "$result" == VULN* ]]; then status="취약"; fi
    if [[ "$result" == NOT_FOUND* ]]; then status="N/A"; fi
    local cmd="ls -l /etc/passwd"
    local cur_state
    cur_state=$(ls -l /etc/passwd 2>/dev/null | awk '{print $1, $3, $4, $9}')
    local remediation="chown root /etc/passwd && chmod 644 /etc/passwd"
    add_result "ISMS-U-16" "파일 및 디렉터리 관리" "/etc/passwd 파일 소유자 및 권한 설정" "상" "$status" "$result" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-17: 시스템 시작 스크립트 권한 설정
check_U17() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/init.d/ /etc/rc.d/init.d/ /etc/rc.d/"
    local cur_state=""
    local remediation="시작 스크립트 소유자를 root로 변경하고 other 쓰기 권한 제거 (chown root 파일; chmod o-w 파일)."

    local vuln_scripts=""
    for dir in /etc/init.d /etc/rc.d/init.d /etc/rc.d; do
        if [ -d "$dir" ]; then
            while IFS= read -r f; do
                local owner perm
                owner=$(stat -c '%U' "$f" 2>/dev/null)
                perm=$(stat -c '%a' "$f" 2>/dev/null)
                if [ "$owner" != "root" ] || [ "$((perm % 10 & 2))" -ne 0 ] 2>/dev/null && [ "$((perm % 10 & 2))" -gt 0 ]; then
                    vuln_scripts+="$f(owner=$owner,perm=$perm) "
                fi
            done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null)
        fi
    done

    if [ -n "$vuln_scripts" ]; then
        detail="취약한 시작 스크립트: ${vuln_scripts:0:200}. "
        cur_state="${vuln_scripts:0:200}"
        status="취약"
    else
        detail="시스템 시작 스크립트 권한 적절. "
        cur_state="시작 스크립트 권한 적절"
    fi

    add_result "ISMS-U-17" "파일 및 디렉터리 관리" "시스템 시작 스크립트 권한 설정" "상" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-18: /etc/shadow 파일 소유자 및 권한 설정
check_U18() {
    local result
    result=$(check_file_owner_perm "/etc/shadow" "root" 400)
    local status="양호"
    if [[ "$result" == VULN* ]]; then status="취약"; fi
    if [[ "$result" == NOT_FOUND* ]]; then status="취약"; fi
    local cmd="ls -l /etc/shadow"
    local cur_state
    cur_state=$(ls -l /etc/shadow 2>/dev/null | awk '{print $1, $3, $4, $9}')
    local remediation="chown root /etc/shadow && chmod 400 /etc/shadow"
    add_result "ISMS-U-18" "파일 및 디렉터리 관리" "/etc/shadow 파일 소유자 및 권한 설정" "상" "$status" "$result" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-19: /etc/hosts 파일 소유자 및 권한 설정
check_U19() {
    local result
    result=$(check_file_owner_perm "/etc/hosts" "root" 644)
    local status="양호"
    if [[ "$result" == VULN* ]]; then status="취약"; fi
    if [[ "$result" == NOT_FOUND* ]]; then status="N/A"; fi
    local cmd="ls -l /etc/hosts"
    local cur_state
    cur_state=$(ls -l /etc/hosts 2>/dev/null | awk '{print $1, $3, $4, $9}')
    local remediation="chown root /etc/hosts && chmod 644 /etc/hosts"
    add_result "ISMS-U-19" "파일 및 디렉터리 관리" "/etc/hosts 파일 소유자 및 권한 설정" "상" "$status" "$result" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-20: /etc/(x)inetd.conf 파일 소유자 및 권한 설정
check_U20() {
    local status="N/A"
    local detail=""
    local cmd="ls -l /etc/inetd.conf /etc/xinetd.conf"
    local cur_state=""
    local remediation="chown root /etc/(x)inetd.conf && chmod 600 /etc/(x)inetd.conf"

    for f in /etc/inetd.conf /etc/xinetd.conf; do
        if [ -f "$f" ]; then
            local result
            result=$(check_file_owner_perm "$f" "root" 600)
            cur_state+="$f: $result; "
            if [[ "$result" == VULN* ]]; then
                status="취약"
                detail+="$f: $result. "
            elif [[ "$result" == GOOD* ]]; then
                if [ "$status" != "취약" ]; then status="양호"; fi
                detail+="$f: $result. "
            fi
        fi
    done

    if [ "$status" = "N/A" ]; then
        detail="(x)inetd.conf 파일 없음. "
        cur_state="(x)inetd.conf 파일 없음"
    fi

    add_result "ISMS-U-20" "파일 및 디렉터리 관리" "/etc/(x)inetd.conf 파일 소유자 및 권한 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-21: /etc/(r)syslog.conf 파일 소유자 및 권한 설정
check_U21() {
    local status="N/A"
    local detail=""
    local cmd="ls -l /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    local cur_state=""
    local remediation="chown root /etc/rsyslog.conf && chmod 644 /etc/rsyslog.conf"

    for f in /etc/syslog.conf /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
        if [ -f "$f" ]; then
            local result
            result=$(check_file_owner_perm "$f" "root" 644)
            cur_state+="$f: $result; "
            if [[ "$result" == VULN* ]]; then
                status="취약"
                detail+="$f: $result. "
            elif [[ "$result" == GOOD* ]]; then
                if [ "$status" != "취약" ]; then status="양호"; fi
                detail+="$f: $result. "
            fi
        fi
    done

    if [ "$status" = "N/A" ]; then
        detail="(r)syslog.conf 파일 없음. "
        cur_state="(r)syslog.conf 파일 없음"
    fi

    add_result "ISMS-U-21" "파일 및 디렉터리 관리" "/etc/(r)syslog.conf 파일 소유자 및 권한 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-22: /etc/services 파일 소유자 및 권한 설정
check_U22() {
    local result
    result=$(check_file_owner_perm "/etc/services" "root" 644)
    local status="양호"
    if [[ "$result" == VULN* ]]; then status="취약"; fi
    if [[ "$result" == NOT_FOUND* ]]; then status="N/A"; fi
    local cmd="ls -l /etc/services"
    local cur_state
    cur_state=$(ls -l /etc/services 2>/dev/null | awk '{print $1, $3, $4, $9}')
    local remediation="chown root /etc/services && chmod 644 /etc/services"
    add_result "ISMS-U-22" "파일 및 디렉터리 관리" "/etc/services 파일 소유자 및 권한 설정" "상" "$status" "$result" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-23: SUID, SGID, Sticky bit 설정 파일 점검
check_U23() {
    local status="수동점검"
    local detail=""
    local cmd="find / -xdev -user root -type f \\( -perm -4000 -o -perm -2000 \\)"
    local cur_state=""
    local remediation="불필요한 SUID/SGID 파일에서 특수 권한 제거 (chmod -s 파일경로). 업무에 필요한 파일만 SUID/SGID 유지."

    local suid_files
    suid_files=$(find / -xdev -user root -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -30)

    # Check against known dangerous SUID files
    local dangerous_suids="/usr/bin/newgrp /usr/sbin/traceroute /usr/bin/chfn /usr/bin/write /usr/bin/wall"
    local found_dangerous=""
    for df in $dangerous_suids; do
        if echo "$suid_files" | grep -q "$df"; then
            found_dangerous+="$df "
        fi
    done

    local count
    count=$(echo "$suid_files" | grep -c . 2>/dev/null)
    detail="SUID/SGID 파일 ${count}개 발견. "
    cur_state="SUID/SGID 파일 ${count}개"
    if [ -n "$found_dangerous" ]; then
        detail+="주의 필요 파일: $found_dangerous. "
        cur_state+="; 주의 필요: $found_dangerous"
    fi

    add_result "ISMS-U-23" "파일 및 디렉터리 관리" "SUID, SGID, Sticky bit 설정 파일 점검" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-24: 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
check_U24() {
    local status="양호"
    local detail=""
    local vuln_files=""
    local cmd="ls -l ~/.profile ~/.bashrc ~/.bash_profile 등 환경변수 파일"
    local cur_state=""
    local remediation="환경변수 파일 소유자를 해당 사용자로 변경하고 other 쓰기 권한 제거 (chmod o-w 파일)."

    while IFS=: read -r user _ _ _ _ home shell; do
        if [ "$home" = "/" ] || [ -z "$home" ]; then continue; fi
        if echo "$shell" | grep -qE "nologin|false"; then continue; fi
        if [ ! -d "$home" ]; then continue; fi

        for f in .profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc; do
            local filepath="$home/$f"
            if [ -f "$filepath" ]; then
                local owner perm
                owner=$(stat -c '%U' "$filepath" 2>/dev/null)
                perm=$(stat -c '%a' "$filepath" 2>/dev/null)
                local other_w=$((perm % 10 & 2))
                if [ "$owner" != "root" ] && [ "$owner" != "$user" ]; then
                    vuln_files+="$filepath(owner=$owner) "
                fi
                if [ "$other_w" -gt 0 ]; then
                    vuln_files+="$filepath(perm=$perm) "
                fi
            fi
        done
    done < /etc/passwd

    if [ -n "$vuln_files" ]; then
        detail="취약 환경변수 파일: ${vuln_files:0:200}. "
        cur_state="${vuln_files:0:200}"
        status="취약"
    else
        detail="환경변수 파일 소유자/권한 적절. "
        cur_state="환경변수 파일 소유자/권한 적절"
    fi

    add_result "ISMS-U-24" "파일 및 디렉터리 관리" "사용자, 시스템 환경변수 파일 소유자 및 권한 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-25: world writable 파일 점검
check_U25() {
    local status="수동점검"
    local detail=""
    local cmd="find / -xdev -type f -perm -0002 ! -path '/tmp/*' ! -path '/proc/*'"
    local cur_state=""
    local remediation="world writable 파일에서 other 쓰기 권한 제거 (chmod o-w 파일경로)."

    local ww_files
    ww_files=$(find / -xdev -type f -perm -0002 ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -20)

    local count
    count=$(echo "$ww_files" | grep -c . 2>/dev/null)
    if [ -n "$ww_files" ] && [ "$count" -gt 0 ]; then
        detail="world writable 파일 ${count}개 발견: $(echo "$ww_files" | head -5 | tr '\n' ', '). "
        cur_state="world writable 파일 ${count}개: $(echo "$ww_files" | head -5 | tr '\n' ', ')"
        status="취약"
    else
        detail="world writable 파일 없음(tmp 제외). "
        cur_state="world writable 파일 없음"
        status="양호"
    fi

    add_result "ISMS-U-25" "파일 및 디렉터리 관리" "world writable 파일 점검" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-26: /dev에 존재하지 않는 device 파일 점검
check_U26() {
    local status="양호"
    local detail=""
    local cmd="find /dev -type f"
    local cur_state=""
    local remediation="/dev 디렉토리 내 비정상 일반 파일 삭제."

    local non_dev_files
    non_dev_files=$(find /dev -type f 2>/dev/null | head -20)

    if [ -n "$non_dev_files" ]; then
        local count
        count=$(echo "$non_dev_files" | wc -l)
        detail="/dev 내 일반 파일 ${count}개 발견: $(echo "$non_dev_files" | head -5 | tr '\n' ', '). "
        cur_state="/dev 내 일반 파일 ${count}개"
        status="수동점검"
    else
        detail="/dev 내 비정상 파일 없음. "
        cur_state="/dev 내 비정상 파일 없음"
    fi

    add_result "ISMS-U-26" "파일 및 디렉터리 관리" "/dev에 존재하지 않는 device 파일 점검" "상" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-27: $HOME/.rhosts, hosts.equiv 사용 금지
check_U27() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/hosts.equiv; find /home -name '.rhosts'"
    local cur_state=""
    local remediation="/etc/hosts.equiv 파일과 각 사용자 홈의 .rhosts 파일 삭제 또는 '+' 항목 제거."

    # Check /etc/hosts.equiv
    if [ -f /etc/hosts.equiv ]; then
        local plus_sign
        plus_sign=$(grep "^\+" /etc/hosts.equiv 2>/dev/null)
        if [ -n "$plus_sign" ]; then
            detail+="/etc/hosts.equiv에 '+' 설정 존재. "
            cur_state+="/etc/hosts.equiv: '+' 존재; "
            status="취약"
        else
            detail+="/etc/hosts.equiv 존재, '+' 없음. "
            cur_state+="/etc/hosts.equiv: '+' 없음; "
        fi
    else
        detail+="/etc/hosts.equiv 없음. "
        cur_state+="/etc/hosts.equiv 없음; "
    fi

    # Check user .rhosts files
    local rhosts_found=""
    while IFS=: read -r user _ _ _ _ home _; do
        if [ -f "$home/.rhosts" ]; then
            rhosts_found+="$home/.rhosts "
            local plus_in_rhosts
            plus_in_rhosts=$(grep "^\+" "$home/.rhosts" 2>/dev/null)
            if [ -n "$plus_in_rhosts" ]; then
                status="취약"
            fi
        fi
    done < /etc/passwd

    if [ -n "$rhosts_found" ]; then
        detail+=".rhosts 파일 발견: $rhosts_found. "
        cur_state+=".rhosts: $rhosts_found"
    fi

    add_result "ISMS-U-27" "파일 및 디렉터리 관리" "\$HOME/.rhosts, hosts.equiv 사용 금지" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-28: 접속 IP 및 포트 제한
check_U28() {
    local status="취약"
    local detail=""
    local cmd="cat /etc/hosts.deny; iptables -L INPUT -n; firewall-cmd --state"
    local cur_state=""
    local remediation="/etc/hosts.deny에 ALL:ALL 설정, /etc/hosts.allow에 허용 IP만 등록. 또는 iptables/firewalld로 접근 제어 설정."

    # Check TCP Wrapper
    if [ -f /etc/hosts.deny ]; then
        local deny_all
        deny_all=$(grep -E "^ALL\s*:\s*ALL" /etc/hosts.deny 2>/dev/null)
        if [ -n "$deny_all" ]; then
            detail+="hosts.deny: ALL:ALL 설정됨. "
            cur_state+="hosts.deny: ALL:ALL 설정; "
            status="양호"
        else
            detail+="hosts.deny: ALL:ALL 미설정. "
            cur_state+="hosts.deny: ALL:ALL 미설정; "
        fi
    fi

    # Check iptables/firewalld
    if command -v iptables &>/dev/null; then
        local iptables_rules
        iptables_rules=$(iptables -L INPUT -n 2>/dev/null | grep -c -E "ACCEPT|DROP|REJECT" 2>/dev/null)
        if [ "${iptables_rules:-0}" -gt 2 ]; then
            detail+="iptables 규칙 ${iptables_rules}개 설정. "
            cur_state+="iptables 규칙 ${iptables_rules}개; "
            status="양호"
        fi
    fi

    if command -v firewall-cmd &>/dev/null; then
        if firewall-cmd --state &>/dev/null 2>&1; then
            detail+="firewalld 활성화. "
            cur_state+="firewalld 활성화; "
            status="양호"
        fi
    fi

    if [ "$status" = "취약" ]; then
        detail+="접근제어 설정 미흡. "
        cur_state+="접근제어 미설정"
    fi

    add_result "ISMS-U-28" "파일 및 디렉터리 관리" "접속 IP 및 포트 제한" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-29: hosts.lpd 파일 소유자 및 권한 설정
check_U29() {
    local cmd="ls -l /etc/hosts.lpd"
    local remediation="chown root /etc/hosts.lpd && chmod 600 /etc/hosts.lpd"
    if [ -f /etc/hosts.lpd ]; then
        local result
        result=$(check_file_owner_perm "/etc/hosts.lpd" "root" 600)
        local status="양호"
        if [[ "$result" == VULN* ]]; then status="취약"; fi
        local cur_state
        cur_state=$(ls -l /etc/hosts.lpd 2>/dev/null | awk '{print $1, $3, $4, $9}')
        add_result "ISMS-U-29" "파일 및 디렉터리 관리" "hosts.lpd 파일 소유자 및 권한 설정" "하" "$status" "$result" "기반시설" "$cmd" "$cur_state" "$remediation"
    else
        add_result "ISMS-U-29" "파일 및 디렉터리 관리" "hosts.lpd 파일 소유자 및 권한 설정" "하" "N/A" "hosts.lpd 파일 없음" "기반시설" "$cmd" "hosts.lpd 파일 없음" "$remediation"
    fi
}

# ISMS-U-30: UMASK 설정 관리
check_U30() {
    local status="취약"
    local detail=""
    local cmd="grep -E '^(umask|UMASK)' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs"
    local cur_state=""
    local remediation="/etc/profile 또는 /etc/login.defs에 UMASK 022 이상 설정."

    local umask_val=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs; do
        if [ -f "$f" ]; then
            local val
            val=$(grep -E "^(umask|UMASK)" "$f" 2>/dev/null | tail -1 | awk '{print $NF}')
            if [ -n "$val" ]; then
                umask_val="$val"
                detail+="$f: umask=$val. "
                cur_state+="$f: umask=$val; "
            fi
        fi
    done

    if [ -n "$umask_val" ] && [ "$umask_val" -ge 22 ] 2>/dev/null; then
        status="양호"
    elif [ -n "$umask_val" ]; then
        detail+="UMASK 값 022 미만. "
    else
        detail="UMASK 미설정. "
        cur_state="UMASK 미설정"
    fi

    add_result "ISMS-U-30" "파일 및 디렉터리 관리" "UMASK 설정 관리" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-31: 홈 디렉토리 소유자 및 권한 설정
check_U31() {
    local status="양호"
    local detail=""
    local vuln_homes=""
    local cmd="awk -F: '{print \$1,\$6}' /etc/passwd; ls -ld 각_홈_디렉토리"
    local cur_state=""
    local remediation="홈 디렉토리 소유자를 해당 사용자로 변경 (chown 사용자 홈경로) 및 other 쓰기 권한 제거 (chmod o-w 홈경로)."

    while IFS=: read -r user _ _ _ _ home shell; do
        if echo "$shell" | grep -qE "nologin|false"; then continue; fi
        if [ ! -d "$home" ] || [ "$home" = "/" ]; then continue; fi
        if [ "$user" = "root" ]; then continue; fi

        local owner perm
        owner=$(stat -c '%U' "$home" 2>/dev/null)
        perm=$(stat -c '%a' "$home" 2>/dev/null)
        local other_w=$((perm % 10 & 2))

        if [ "$owner" != "$user" ] || [ "$other_w" -gt 0 ]; then
            vuln_homes+="$home(owner=$owner,perm=$perm) "
        fi
    done < /etc/passwd

    if [ -n "$vuln_homes" ]; then
        detail="취약 홈 디렉토리: ${vuln_homes:0:200}. "
        cur_state="${vuln_homes:0:200}"
        status="취약"
    else
        detail="홈 디렉토리 소유자/권한 적절. "
        cur_state="홈 디렉토리 소유자/권한 적절"
    fi

    add_result "ISMS-U-31" "파일 및 디렉터리 관리" "홈 디렉토리 소유자 및 권한 설정" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-32: 홈 디렉토리로 지정한 디렉토리의 존재 관리
check_U32() {
    local status="양호"
    local detail=""
    local missing_homes=""
    local cmd="awk -F: '{print \$1,\$6}' /etc/passwd"
    local cur_state=""
    local remediation="홈 디렉토리가 없는 계정에 홈 디렉토리 생성 (mkdir 홈경로 && chown 사용자 홈경로) 또는 불필요한 계정 삭제."

    while IFS=: read -r user _ _ _ _ home shell; do
        if echo "$shell" | grep -qE "nologin|false|sync|shutdown|halt"; then continue; fi
        if [ "$home" = "/" ]; then continue; fi
        if [ ! -d "$home" ]; then
            missing_homes+="$user($home) "
        fi
    done < /etc/passwd

    if [ -n "$missing_homes" ]; then
        detail="홈 디렉토리 없는 계정: $missing_homes. "
        cur_state="홈 디렉토리 없는 계정: $missing_homes"
        status="취약"
    else
        detail="모든 활성 계정의 홈 디렉토리 존재. "
        cur_state="모든 활성 계정의 홈 디렉토리 존재"
    fi

    add_result "ISMS-U-32" "파일 및 디렉터리 관리" "홈 디렉토리로 지정한 디렉토리의 존재 관리" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-33: 숨겨진 파일 및 디렉토리 검색 및 제거
check_U33() {
    add_result "ISMS-U-33" "파일 및 디렉터리 관리" "숨겨진 파일 및 디렉토리 검색 및 제거" "하" "수동점검" "숨겨진 파일 점검은 수동 확인 필요 (find / -name '.*' -type f)" "기반시설" "find / -name '.*' -type f" "수동 확인 필요" "불필요한 숨김 파일 및 디렉토리 삭제. find / -name '.*' -type f 명령으로 확인 후 조치."
}

###############################################################################
# 3. 서비스 관리
###############################################################################

# ISMS-U-34: Finger 서비스 비활성화
check_U34() {
    local status="양호"
    local detail=""
    local cmd="ls /etc/xinetd.d/finger; ps -ef | grep fingerd"
    local cur_state=""
    local remediation="finger 서비스 비활성화 또는 패키지 삭제 (apt remove finger 또는 yum remove finger)."

    if [ -f /etc/xinetd.d/finger ]; then
        local disabled
        disabled=$(grep -i "disable" /etc/xinetd.d/finger 2>/dev/null | grep -i "yes")
        if [ -z "$disabled" ]; then
            status="취약"
            detail="finger 서비스 활성화됨. "
            cur_state="finger 서비스 활성화"
        else
            detail="finger 서비스 비활성화(xinetd). "
            cur_state="finger 비활성화(xinetd)"
        fi
    else
        if ps -ef 2>/dev/null | grep -v grep | grep -q fingerd; then
            status="취약"
            detail="fingerd 프로세스 실행 중. "
            cur_state="fingerd 실행 중"
        else
            detail="finger 서비스 미설치/비활성화. "
            cur_state="finger 미설치/비활성화"
        fi
    fi

    add_result "ISMS-U-34" "서비스 관리" "Finger 서비스 비활성화" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-35: 공유 서비스에 대한 익명 접근 제한 설정
check_U35() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/exports; grep 'guest ok' /etc/samba/smb.conf; grep 'anonymous_enable' /etc/vsftpd.conf"
    local cur_state=""
    local remediation="NFS: /etc/exports에서 everyone 공유 제거. Samba: smb.conf에서 guest ok = no 설정. FTP: anonymous_enable=NO 설정."

    # Check NFS
    if [ -f /etc/exports ]; then
        local everyone_share
        everyone_share=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$" | grep "\*")
        if [ -n "$everyone_share" ]; then
            detail+="NFS everyone 공유: $everyone_share. "
            status="취약"
        fi
    fi

    # Check Samba
    if [ -f /etc/samba/smb.conf ]; then
        local guest_ok
        guest_ok=$(grep -i "guest ok" /etc/samba/smb.conf 2>/dev/null | grep -iv "^#\|^;" | grep -i "yes")
        if [ -n "$guest_ok" ]; then
            detail+="Samba guest 접근 허용. "
            status="취약"
        fi
    fi

    # Check FTP anonymous
    for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        if [ -f "$f" ]; then
            local anon
            anon=$(grep -i "^anonymous_enable" "$f" 2>/dev/null | grep -i "yes")
            if [ -n "$anon" ]; then
                detail+="vsFTP 익명 접근 허용. "
                status="취약"
            fi
        fi
    done

    if [ -z "$detail" ]; then
        detail="공유 서비스 익명 접근 미발견. "
        cur_state="공유 서비스 익명 접근 미발견"
    fi

    add_result "ISMS-U-35" "서비스 관리" "공유 서비스에 대한 익명 접근 제한 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-36: r 계열 서비스 비활성화
check_U36() {
    local status="양호"
    local detail=""
    local cmd="ls /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec; ps -ef | grep -E 'rshd|rlogind|rexecd'"
    local cur_state=""
    local remediation="rsh, rlogin, rexec 서비스 비활성화 및 삭제. SSH 사용 권장."

    for svc in rsh rlogin rexec; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            local disabled
            disabled=$(grep -i "disable" "/etc/xinetd.d/$svc" 2>/dev/null | grep -i "yes")
            if [ -z "$disabled" ]; then
                status="취약"
                detail+="$svc 활성화. "
            fi
        fi
    done

    # Check running processes
    if ps -ef 2>/dev/null | grep -v grep | grep -qE "rshd|rlogind|rexecd"; then
        status="취약"
        detail+="r 계열 프로세스 실행 중. "
    fi

    if [ -z "$detail" ]; then
        detail="r 계열 서비스 비활성화. "
        cur_state="r 계열 서비스 비활성화"
    fi

    add_result "ISMS-U-36" "서비스 관리" "r 계열 서비스 비활성화" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-37: crontab 설정파일 권한 설정
check_U37() {
    local status="양호"
    local detail=""
    local cmd="ls -l /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny"
    local cur_state=""
    local remediation="chmod 640 /etc/crontab && chown root /etc/crontab. cron.allow/cron.deny 파일도 소유자 root, 권한 640 이하 설정."

    # Check /etc/crontab
    if [ -f /etc/crontab ]; then
        local result
        result=$(check_file_owner_perm "/etc/crontab" "root" 640)
        if [[ "$result" == VULN* ]]; then
            status="취약"
            detail+="/etc/crontab: $result. "
        else
            detail+="/etc/crontab: $result. "
        fi
    fi

    # Check cron.allow / cron.deny
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        if [ -f "$f" ]; then
            local owner perm
            owner=$(stat -c '%U' "$f" 2>/dev/null)
            perm=$(stat -c '%a' "$f" 2>/dev/null)
            detail+="$f: owner=$owner, perm=$perm. "
            if [ "$owner" != "root" ] || [ "$perm" -gt 640 ] 2>/dev/null; then
                status="취약"
            fi
        fi
    done

    cur_state=$(echo "$detail" | sed 's/\. *$//')
    add_result "ISMS-U-37" "서비스 관리" "crontab 설정파일 권한 설정" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-38: DoS 공격에 취약한 서비스 비활성화
check_U38() {
    local status="양호"
    local detail=""
    local active_svcs=""
    local cmd="ls /etc/xinetd.d/echo /etc/xinetd.d/discard /etc/xinetd.d/daytime /etc/xinetd.d/chargen"
    local cur_state=""
    local remediation="echo, discard, daytime, chargen 서비스를 xinetd에서 disable = yes 설정 또는 삭제."

    for svc in echo discard daytime chargen; do
        if [ -f "/etc/xinetd.d/$svc" ] || [ -f "/etc/xinetd.d/${svc}-dgram" ] || [ -f "/etc/xinetd.d/${svc}-stream" ]; then
            for f in /etc/xinetd.d/${svc}*; do
                if [ -f "$f" ]; then
                    local disabled
                    disabled=$(grep -i "disable" "$f" 2>/dev/null | grep -i "yes")
                    if [ -z "$disabled" ]; then
                        active_svcs+="$svc "
                    fi
                fi
            done
        fi
    done

    if [ -n "$active_svcs" ]; then
        detail="활성화된 취약 서비스: $active_svcs. "
        cur_state="활성화: $active_svcs"
        status="취약"
    else
        detail="DoS 취약 서비스 비활성화. "
        cur_state="DoS 취약 서비스 비활성화"
    fi

    add_result "ISMS-U-38" "서비스 관리" "DoS 공격에 취약한 서비스 비활성화" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-39: 불필요한 NFS 서비스 비활성화
check_U39() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep nfsd; systemctl is-active nfs-server"
    local cur_state=""
    local remediation="NFS 서비스 비활성화: systemctl stop nfs-server && systemctl disable nfs-server"

    if ps -ef 2>/dev/null | grep -v grep | grep -q nfsd; then
        status="취약"
        detail="NFS 데몬(nfsd) 실행 중. "
        cur_state="nfsd 실행 중"
    elif systemctl is-active nfs-server &>/dev/null; then
        status="취약"
        detail="nfs-server 서비스 활성화. "
        cur_state="nfs-server active"
    else
        detail="NFS 서비스 비활성화. "
        cur_state="NFS 비활성화"
    fi

    add_result "ISMS-U-39" "서비스 관리" "불필요한 NFS 서비스 비활성화" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-40: NFS 접근 통제
check_U40() {
    local status="N/A"
    local detail=""

    if ps -ef 2>/dev/null | grep -v grep | grep -q nfsd || systemctl is-active nfs-server &>/dev/null; then
        status="양호"
        if [ -f /etc/exports ]; then
            local everyone
            everyone=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$" | grep "\*")
            if [ -n "$everyone" ]; then
                status="취약"
                detail="NFS everyone 공유 설정: $(echo "$everyone" | head -3 | tr '\n' ', '). "
            else
                detail="NFS 접근 통제 설정됨. "
            fi

            local result
            result=$(check_file_owner_perm "/etc/exports" "root" 644)
            if [[ "$result" == VULN* ]]; then
                status="취약"
                detail+="/etc/exports 권한 취약: $result. "
            fi
        else
            detail="/etc/exports 파일 없음. "
        fi
    else
        detail="NFS 서비스 미사용. "
    fi

    add_result "ISMS-U-40" "서비스 관리" "NFS 접근 통제" "상" "$status" "$detail" "공통" "cat /etc/exports; systemctl is-active nfs-server" "$detail" "/etc/exports에서 everyone(*) 공유 제거, 특정 호스트/IP만 허용 설정."
}

# ISMS-U-41: 불필요한 automountd 제거
check_U41() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep automount; systemctl is-active autofs"
    local cur_state=""
    local remediation="autofs 서비스 비활성화: systemctl stop autofs && systemctl disable autofs"

    if ps -ef 2>/dev/null | grep -v grep | grep -q automount; then
        status="취약"
        detail="automountd 프로세스 실행 중. "
        cur_state="automountd 실행 중"
    elif systemctl is-active autofs &>/dev/null; then
        status="취약"
        detail="autofs 서비스 활성화. "
        cur_state="autofs active"
    else
        detail="automountd 비활성화. "
        cur_state="automountd 비활성화"
    fi

    add_result "ISMS-U-41" "서비스 관리" "불필요한 automountd 제거" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-42: 불필요한 RPC 서비스 비활성화
check_U42() {
    local status="양호"
    local detail=""
    local active_rpc=""

    for svc in rstatd rusersd rwalld rquotad sprayd; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            local disabled
            disabled=$(grep -i "disable" "/etc/xinetd.d/$svc" 2>/dev/null | grep -i "yes")
            if [ -z "$disabled" ]; then
                active_rpc+="$svc "
            fi
        fi
    done

    # Check running RPC services
    if command -v rpcinfo &>/dev/null; then
        local rpc_list
        rpc_list=$(rpcinfo -p 2>/dev/null | grep -E "rstat|ruser|rwall|rquota|spray" | head -5)
        if [ -n "$rpc_list" ]; then
            active_rpc+="(rpcinfo: $(echo "$rpc_list" | awk '{print $5}' | sort -u | tr '\n' ',')) "
        fi
    fi

    if [ -n "$active_rpc" ]; then
        detail="활성화된 RPC 서비스: $active_rpc. "
        status="취약"
    else
        detail="불필요한 RPC 서비스 비활성화. "
    fi

    add_result "ISMS-U-42" "서비스 관리" "불필요한 RPC 서비스 비활성화" "상" "$status" "$detail" "공통" "ls /etc/xinetd.d/rstat* /etc/xinetd.d/ruser* /etc/xinetd.d/rwall* /etc/xinetd.d/rquota* /etc/xinetd.d/spray*; rpcinfo -p" "$detail" "불필요한 RPC 서비스(rstatd, rusersd, rwalld 등) xinetd에서 disable = yes 설정."
}

# ISMS-U-43: NIS, NIS+ 점검
check_U43() {
    local status="양호"
    local detail=""

    local nis_procs
    nis_procs=$(ps -ef 2>/dev/null | grep -v grep | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated")
    if [ -n "$nis_procs" ]; then
        status="취약"
        detail="NIS 관련 프로세스 실행 중: $(echo "$nis_procs" | awk '{print $8}' | tr '\n' ', '). "
    else
        detail="NIS 서비스 비활성화. "
    fi

    add_result "ISMS-U-43" "서비스 관리" "NIS, NIS+ 점검" "상" "$status" "$detail" "공통" "ps -ef | grep -E 'ypserv|ypbind'" "$detail" "NIS 관련 서비스(ypserv, ypbind 등) 중지 및 비활성화."
}

# ISMS-U-44: tftp, talk 서비스 비활성화
check_U44() {
    local status="양호"
    local detail=""

    for svc in tftp talk ntalk; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            local disabled
            disabled=$(grep -i "disable" "/etc/xinetd.d/$svc" 2>/dev/null | grep -i "yes")
            if [ -z "$disabled" ]; then
                status="취약"
                detail+="$svc 활성화. "
            fi
        fi
        if ps -ef 2>/dev/null | grep -v grep | grep -q "${svc}d"; then
            status="취약"
            detail+="${svc}d 프로세스 실행 중. "
        fi
    done

    if [ -z "$detail" ]; then
        detail="tftp, talk 서비스 비활성화. "
    fi

    add_result "ISMS-U-44" "서비스 관리" "tftp, talk 서비스 비활성화" "상" "$status" "$detail" "공통" "ls /etc/xinetd.d/tftp /etc/xinetd.d/talk /etc/xinetd.d/ntalk; ps -ef | grep -E 'tftpd|talkd|ntalkd'" "$detail" "tftp, talk, ntalk 서비스 xinetd에서 disable = yes 설정 또는 삭제."
}

# ISMS-U-45: 메일 서비스 버전 점검
check_U45() {
    local status="N/A"
    local detail=""
    local cur_state=""
    local cmd="sendmail -d0.1 -bt < /dev/null; postconf mail_version; exim -bV"
    local remediation="메일 서비스(Sendmail/Postfix/Exim) 최신 보안 패치 적용. 미사용 시 서비스 비활성화."

    if mail_sendmail_active; then
        local ver
        ver=$(sendmail -d0.1 -bt < /dev/null 2>&1 | grep -m1 -E 'Version|Sendmail' | head -1)
        detail+="Sendmail 실행 중. 버전: ${ver:-확인불가}. "
        cur_state="Sendmail=${ver:-확인불가}"
        status=$(merge_status "$status" "수동점검")
    fi

    if mail_postfix_active; then
        local ver
        ver=$(postconf mail_version 2>/dev/null)
        detail+="Postfix 실행 중. ${ver:-버전 확인불가}. "
        cur_state="${cur_state}; Postfix=${ver:-확인불가}"
        status=$(merge_status "$status" "수동점검")
    fi

    if mail_exim_active; then
        local ver
        ver=$(exim -bV 2>/dev/null | head -1)
        detail+="Exim 실행 중. ${ver:-버전 확인불가}. "
        cur_state="${cur_state}; Exim=${ver:-확인불가}"
        status=$(merge_status "$status" "수동점검")
    fi

    cur_state=$(printf '%s' "$cur_state" | sed 's/^;[[:space:]]*//')

    if [ "$status" = "N/A" ]; then
        detail="메일 서비스 미사용. "
        cur_state="메일 서비스 미사용"
    fi

    add_result "ISMS-U-45" "서비스 관리" "메일 서비스 버전 점검" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-46: 일반 사용자의 메일 서비스 실행 방지
check_U46() {
    local status="N/A"
    local detail=""
    local cur_state=""
    local cmd="grep PrivacyOptions /etc/mail/sendmail.cf; stat -c '%a' /usr/sbin/postsuper; stat -c '%a' /usr/sbin/exiqgrep"
    local remediation="Sendmail: /etc/mail/sendmail.cf에 PrivacyOptions=restrictqrun 설정. Postfix: /usr/sbin/postsuper의 기타 사용자 실행 권한 제거. Exim: /usr/sbin/exiqgrep의 기타 사용자 실행 권한 제거."

    if mail_sendmail_active; then
        local priv_opts
        priv_opts=$(grep "PrivacyOptions" /etc/mail/sendmail.cf 2>/dev/null | grep -v "^#")
        if echo "$priv_opts" | grep -qi "restrictqrun"; then
            detail+="Sendmail PrivacyOptions에 restrictqrun 설정. "
            cur_state="Sendmail=${priv_opts:-미설정}"
            status=$(merge_status "$status" "양호")
        else
            detail+="Sendmail PrivacyOptions에 restrictqrun 미설정. "
            cur_state="Sendmail=${priv_opts:-미설정}"
            status=$(merge_status "$status" "취약")
        fi
    fi

    if mail_postfix_active; then
        local postfix_perm
        local postfix_path
        local postfix_other
        postfix_path=$(command -v postsuper 2>/dev/null || printf '%s' /usr/sbin/postsuper)
        postfix_perm=$(stat -c '%a' "$postfix_path" 2>/dev/null)
        postfix_other=$(last_permission_digit "$postfix_perm")
        if [ -n "$postfix_perm" ] && ! printf '%s' "$postfix_other" | grep -q '[1357]'; then
            detail+="Postfix postsuper 실행 권한 적절($postfix_perm). "
            cur_state="${cur_state}; Postfix=$postfix_path:$postfix_perm"
            status=$(merge_status "$status" "양호")
        else
            detail+="Postfix postsuper 실행 권한 부적절(${postfix_perm:-확인불가}). "
            cur_state="${cur_state}; Postfix=$postfix_path:${postfix_perm:-확인불가}"
            status=$(merge_status "$status" "취약")
        fi
    fi

    if mail_exim_active; then
        local exim_perm
        local exim_path
        local exim_other
        exim_path=$(command -v exiqgrep 2>/dev/null || printf '%s' /usr/sbin/exiqgrep)
        exim_perm=$(stat -c '%a' "$exim_path" 2>/dev/null)
        exim_other=$(last_permission_digit "$exim_perm")
        if [ -n "$exim_perm" ] && ! printf '%s' "$exim_other" | grep -q '[1357]'; then
            detail+="Exim exiqgrep 실행 권한 적절($exim_perm). "
            cur_state="${cur_state}; Exim=$exim_path:$exim_perm"
            status=$(merge_status "$status" "양호")
        else
            detail+="Exim exiqgrep 실행 권한 부적절(${exim_perm:-확인불가}). "
            cur_state="${cur_state}; Exim=$exim_path:${exim_perm:-확인불가}"
            status=$(merge_status "$status" "취약")
        fi
    fi

    cur_state=$(printf '%s' "$cur_state" | sed 's/^;[[:space:]]*//')

    if [ "$status" = "N/A" ]; then
        detail="메일 서비스 미사용. "
        cur_state="메일 서비스 미사용"
    fi

    add_result "ISMS-U-46" "서비스 관리" "일반 사용자의 메일 서비스 실행 방지" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-47: 스팸 메일 릴레이 제한
check_U47() {
    local status="N/A"
    local detail=""
    local cur_state=""
    local cmd="grep -E 'promiscuous_relay|Relaying denied' /etc/mail/sendmail.mc /etc/mail/sendmail.cf; postconf mynetworks; grep -E 'relay_from_hosts|accept hosts' /etc/exim/exim.conf /etc/exim4/exim4.conf"
    local remediation="Sendmail: promiscuous_relay 제거 및 access 정책 적용. Postfix: mynetworks를 내부 허용망으로 제한. Exim: relay_from_hosts 또는 accept hosts를 허용된 네트워크로만 제한."

    if mail_sendmail_active; then
        local relay_denied
        local promiscuous
        local access_file
        relay_denied=$(grep 'Relaying denied' /etc/mail/sendmail.cf 2>/dev/null | grep -v "^#")
        promiscuous=$(grep -i 'promiscuous_relay' /etc/mail/sendmail.mc 2>/dev/null | grep -v "^#")
        access_file=""
        for access_candidate in /etc/mail/access /etc/mail/access.db; do
            if [ -f "$access_candidate" ]; then
                access_file="$access_candidate"
                break
            fi
        done
        if [ -n "$promiscuous" ]; then
            detail+="Sendmail promiscuous_relay 설정 존재. "
            cur_state="Sendmail=promiscuous_relay"
            status=$(merge_status "$status" "취약")
        elif [ -n "$relay_denied" ] || [ -n "$access_file" ]; then
            detail+="Sendmail 릴레이 제한 설정 확인. "
            cur_state="Sendmail=${relay_denied:-$access_file}"
            status=$(merge_status "$status" "양호")
        else
            detail+="Sendmail 릴레이 제한 설정 확인 필요. "
            cur_state="Sendmail=명시 설정 확인불가"
            status=$(merge_status "$status" "수동점검")
        fi
    fi

    if mail_postfix_active; then
        local mynetworks
        mynetworks=$(postconf -h mynetworks 2>/dev/null)
        if [ -z "$mynetworks" ]; then
            detail+="Postfix mynetworks 미설정. "
            cur_state="${cur_state}; Postfix=미설정"
            status=$(merge_status "$status" "취약")
        elif printf '%s' "$mynetworks" | grep -Eq '0\.0\.0\.0/0|/0|all'; then
            detail+="Postfix mynetworks 과다 허용($mynetworks). "
            cur_state="${cur_state}; Postfix=$mynetworks"
            status=$(merge_status "$status" "취약")
        else
            detail+="Postfix mynetworks 제한 설정($mynetworks). "
            cur_state="${cur_state}; Postfix=$mynetworks"
            status=$(merge_status "$status" "양호")
        fi
    fi

    if mail_exim_active; then
        local exim_conf
        local relay_hosts
        local accept_hosts
        exim_conf=$(mail_exim_config)
        relay_hosts=$(grep -E 'relay_from_hosts' "$exim_conf" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -1)
        accept_hosts=$(grep -E 'accept[[:space:]]+hosts' "$exim_conf" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -1)
        if printf '%s %s' "$relay_hosts" "$accept_hosts" | grep -Eq '\*|0\.0\.0\.0/0|/0'; then
            detail+="Exim 릴레이 허용 범위 과다. "
            cur_state="${cur_state}; Exim=${relay_hosts:-$accept_hosts}"
            status=$(merge_status "$status" "취약")
        elif [ -n "$relay_hosts" ] || [ -n "$accept_hosts" ]; then
            detail+="Exim 릴레이 제한 설정 확인. "
            cur_state="${cur_state}; Exim=${relay_hosts:-$accept_hosts}"
            status=$(merge_status "$status" "양호")
        else
            detail+="Exim 릴레이 제한 설정 확인 필요. "
            cur_state="${cur_state}; Exim=명시 설정 확인불가"
            status=$(merge_status "$status" "수동점검")
        fi
    fi

    cur_state=$(printf '%s' "$cur_state" | sed 's/^;[[:space:]]*//')

    if [ "$status" = "N/A" ]; then
        detail="메일 서비스 미사용. "
        cur_state="메일 서비스 미사용"
    fi

    add_result "ISMS-U-47" "서비스 관리" "스팸 메일 릴레이 제한" "상" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-48: expn, vrfy 명령어 제한
check_U48() {
    local status="N/A"
    local detail=""
    local cur_state=""
    local cmd="grep PrivacyOptions /etc/mail/sendmail.cf; postconf disable_vrfy_command; grep -E 'acl_smtp_vrfy|acl_smtp_expn' /etc/exim/exim.conf /etc/exim4/exim4.conf"
    local remediation="Sendmail: PrivacyOptions에 noexpn, novrfy 또는 goaway 설정. Postfix: disable_vrfy_command=yes 설정. Exim: acl_smtp_vrfy/acl_smtp_expn 허용 설정 제거."

    if mail_sendmail_active; then
        local priv_opts
        priv_opts=$(grep "PrivacyOptions" /etc/mail/sendmail.cf 2>/dev/null | grep -v "^#")
        if { echo "$priv_opts" | grep -qi "noexpn" && echo "$priv_opts" | grep -qi "novrfy"; } || \
           echo "$priv_opts" | grep -qi "goaway"; then
            detail+="Sendmail noexpn/novrfy 또는 goaway 설정됨. "
            cur_state="Sendmail=${priv_opts:-미설정}"
            status=$(merge_status "$status" "양호")
        else
            detail+="Sendmail noexpn/novrfy 미설정: ${priv_opts:-미설정}. "
            cur_state="Sendmail=${priv_opts:-미설정}"
            status=$(merge_status "$status" "취약")
        fi
    fi

    if mail_postfix_active; then
        local vrfy
        vrfy=$(postconf disable_vrfy_command 2>/dev/null)
        if echo "$vrfy" | grep -qi "yes"; then
            detail+="Postfix disable_vrfy_command=yes. "
            cur_state="${cur_state}; Postfix=${vrfy:-미설정}"
            status=$(merge_status "$status" "양호")
        else
            detail+="Postfix disable_vrfy_command 미설정(${vrfy:-확인불가}). "
            cur_state="${cur_state}; Postfix=${vrfy:-확인불가}"
            status=$(merge_status "$status" "취약")
        fi
    fi

    if mail_exim_active; then
        local exim_conf
        local exim_vrfy
        local exim_expn
        exim_conf=$(mail_exim_config)
        if [ -n "$exim_conf" ]; then
            exim_vrfy=$(grep -E 'acl_smtp_vrfy[[:space:]]*=' "$exim_conf" 2>/dev/null | grep -v '^[[:space:]]*#')
            exim_expn=$(grep -E 'acl_smtp_expn[[:space:]]*=' "$exim_conf" 2>/dev/null | grep -v '^[[:space:]]*#')
            if printf '%s %s' "$exim_vrfy" "$exim_expn" | grep -qi 'accept'; then
                detail+="Exim expn/vrfy 허용 설정 존재. "
                cur_state="${cur_state}; Exim=${exim_vrfy:-$exim_expn}"
                status=$(merge_status "$status" "취약")
            else
                detail+="Exim expn/vrfy 허용 설정 없음. "
                cur_state="${cur_state}; Exim=허용 설정 없음"
                status=$(merge_status "$status" "양호")
            fi
        else
            detail+="Exim 설정 파일 확인 필요. "
            cur_state="${cur_state}; Exim=설정 파일 확인불가"
            status=$(merge_status "$status" "수동점검")
        fi
    fi

    cur_state=$(printf '%s' "$cur_state" | sed 's/^;[[:space:]]*//')

    if [ "$status" = "N/A" ]; then
        detail="메일 서비스 미사용. "
        cur_state="메일 서비스 미사용"
    fi

    add_result "ISMS-U-48" "서비스 관리" "expn, vrfy 명령어 제한" "중" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-49: DNS 보안 버전 패치
check_U49() {
    local status="N/A"
    local detail=""

    if ps -ef 2>/dev/null | grep -v grep | grep -q named; then
        local ver
        ver=$(named -v 2>/dev/null)
        detail="DNS(BIND) 실행 중. 버전: ${ver:-확인불가}. "
        status="수동점검"
    else
        detail="DNS 서비스 미사용. "
    fi

    add_result "ISMS-U-49" "서비스 관리" "DNS 보안 버전 패치" "상" "$status" "$detail" "공통" "named -v; ps -ef | grep named" "$detail" "DNS(BIND) 최신 보안 패치 적용. 미사용 시 서비스 비활성화."
}

# ISMS-U-50: DNS Zone Transfer 설정
check_U50() {
    local status="N/A"
    local detail=""

    if ps -ef 2>/dev/null | grep -v grep | grep -q named; then
        local allow_transfer=""
        for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options; do
            if [ -f "$f" ]; then
                allow_transfer=$(grep -i "allow-transfer" "$f" 2>/dev/null | grep -v "^#\|^//")
                if [ -n "$allow_transfer" ]; then
                    break
                fi
            fi
        done

        if [ -n "$allow_transfer" ]; then
            if echo "$allow_transfer" | grep -q "any"; then
                status="취약"
                detail="DNS Zone Transfer: any 허용. "
            else
                status="양호"
                detail="DNS Zone Transfer 제한 설정: $allow_transfer. "
            fi
        else
            status="취약"
            detail="DNS allow-transfer 설정 없음. "
        fi
    else
        detail="DNS 서비스 미사용. "
    fi

    add_result "ISMS-U-50" "서비스 관리" "DNS Zone Transfer 설정" "상" "$status" "$detail" "공통" "grep 'allow-transfer' /etc/named.conf /etc/bind/named.conf" "$detail" "named.conf에서 allow-transfer에 허가된 Secondary DNS 서버 IP만 설정. allow-transfer { none; }; 또는 특정 IP 지정."
}

# ISMS-U-51: DNS 서비스의 취약한 동적 업데이트 설정 금지
check_U51() {
    local status="N/A"
    local detail=""

    if ps -ef 2>/dev/null | grep -v grep | grep -q named; then
        local allow_update=""
        for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.local; do
            if [ -f "$f" ]; then
                allow_update=$(grep -i "allow-update" "$f" 2>/dev/null | grep -v "^#\|^//")
                if [ -n "$allow_update" ]; then break; fi
            fi
        done

        if [ -n "$allow_update" ]; then
            if echo "$allow_update" | grep -q "any"; then
                status="취약"
                detail="DNS 동적 업데이트: any 허용. "
            elif echo "$allow_update" | grep -q "none"; then
                status="양호"
                detail="DNS 동적 업데이트: none. "
            else
                status="양호"
                detail="DNS 동적 업데이트 제한 설정: $allow_update. "
            fi
        else
            status="양호"
            detail="DNS allow-update 미설정(기본 비활성). "
        fi
    else
        detail="DNS 서비스 미사용. "
    fi

    add_result "ISMS-U-51" "서비스 관리" "DNS 서비스의 취약한 동적 업데이트 설정 금지" "중" "$status" "$detail" "기반시설" "grep 'allow-update' /etc/named.conf /etc/bind/named.conf" "$detail" "named.conf에서 allow-update { none; }; 설정으로 동적 업데이트 비활성화."
}

# ISMS-U-52: Telnet 서비스 비활성화
check_U52() {
    local status="양호"
    local detail=""

    if systemctl is-active telnet.socket &>/dev/null; then
        status="취약"
        detail="telnet.socket 활성화. "
    elif [ -f /etc/xinetd.d/telnet ]; then
        local disabled
        disabled=$(grep -i "disable" /etc/xinetd.d/telnet 2>/dev/null | grep -i "yes")
        if [ -z "$disabled" ]; then
            status="취약"
            detail="telnet xinetd 활성화. "
        else
            detail="telnet xinetd 비활성화. "
        fi
    else
        if ps -ef 2>/dev/null | grep -v grep | grep -q telnetd; then
            status="취약"
            detail="telnetd 프로세스 실행 중. "
        else
            detail="Telnet 서비스 비활성화. "
        fi
    fi

    add_result "ISMS-U-52" "서비스 관리" "Telnet 서비스 비활성화" "중" "$status" "$detail" "공통" "systemctl is-active telnet.socket; ps -ef | grep telnetd" "$detail" "Telnet 서비스 비활성화: systemctl stop telnet.socket && systemctl disable telnet.socket. SSH 사용 권장."
}

# ISMS-U-53: FTP 서비스 정보 노출 제한
check_U53() {
    local status="N/A"
    local detail=""

    for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        if [ -f "$f" ]; then
            local banner
            banner=$(grep -i "^ftpd_banner" "$f" 2>/dev/null)
            if [ -n "$banner" ]; then
                status="양호"
                detail="FTP 배너 설정됨: $banner. "
            else
                status="취약"
                detail="FTP 배너 미설정(기본 정보 노출). "
            fi
        fi
    done

    if ps -ef 2>/dev/null | grep -v grep | grep -q proftpd; then
        local proftpd_banner
        proftpd_banner=$(grep "ServerIdent" /etc/proftpd/proftpd.conf 2>/dev/null | grep -v "^#")
        detail+="ProFTPD: ${proftpd_banner:-배너 설정 확인 필요}. "
        status="수동점검"
    fi

    if [ "$status" = "N/A" ]; then
        detail="FTP 서비스 미사용. "
    fi

    add_result "ISMS-U-53" "서비스 관리" "FTP 서비스 정보 노출 제한" "하" "$status" "$detail" "기반시설" "grep ftpd_banner /etc/vsftpd.conf; grep ServerIdent /etc/proftpd/proftpd.conf" "$detail" "vsftpd: ftpd_banner=경고메시지 설정. ProFTPD: ServerIdent on '경고메시지' 설정."
}

# ISMS-U-54: 암호화되지 않는 FTP 서비스 비활성화
check_U54() {
    local status="양호"
    local detail=""

    local ftp_running=false
    if ps -ef 2>/dev/null | grep -v grep | grep -qE "vsftpd|proftpd|ftpd"; then
        ftp_running=true
    fi
    if systemctl is-active vsftpd &>/dev/null || systemctl is-active proftpd &>/dev/null; then
        ftp_running=true
    fi

    if [ "$ftp_running" = true ]; then
        # Check if SSL/TLS is configured
        local ssl_enabled=false
        for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
            if [ -f "$f" ]; then
                if grep -qi "^ssl_enable=YES" "$f" 2>/dev/null; then
                    ssl_enabled=true
                fi
            fi
        done
        if [ "$ssl_enabled" = true ]; then
            detail="FTP 서비스 SSL 활성화. "
        else
            status="취약"
            detail="암호화되지 않은 FTP 서비스 활성화. "
        fi
    else
        detail="FTP 서비스 미사용. "
        status="양호"
    fi

    add_result "ISMS-U-54" "서비스 관리" "암호화되지 않는 FTP 서비스 비활성화" "중" "$status" "$detail" "공통" "ps -ef | grep -E 'vsftpd|proftpd|ftpd'; grep ssl_enable /etc/vsftpd.conf" "$detail" "FTP 서비스 비활성화 또는 SFTP/FTPS 사용. vsftpd: ssl_enable=YES 설정."
}

# ISMS-U-55: FTP 계정 Shell 제한
check_U55() {
    local status="N/A"
    local detail=""

    local ftp_shell
    ftp_shell=$(awk -F: '$1 == "ftp" {print $7}' /etc/passwd 2>/dev/null)
    if [ -n "$ftp_shell" ]; then
        if echo "$ftp_shell" | grep -qE "nologin|false"; then
            status="양호"
            detail="ftp 계정 쉘: $ftp_shell. "
        else
            status="취약"
            detail="ftp 계정에 로그인 쉘 부여: $ftp_shell. "
        fi
    else
        detail="ftp 계정 없음. "
        status="양호"
    fi

    add_result "ISMS-U-55" "서비스 관리" "FTP 계정 Shell 제한" "중" "$status" "$detail" "기반시설" "grep '^ftp' /etc/passwd" "$detail" "ftp 계정 쉘을 /sbin/nologin으로 변경: usermod -s /sbin/nologin ftp"
}

# ISMS-U-56: FTP 서비스 접근 제어 설정
check_U56() {
    local status="N/A"
    local detail=""

    local ftp_running=false
    if ps -ef 2>/dev/null | grep -v grep | grep -qE "vsftpd|proftpd|ftpd" || \
       systemctl is-active vsftpd &>/dev/null; then
        ftp_running=true
    fi

    if [ "$ftp_running" = true ]; then
        status="수동점검"
        # Check TCP Wrapper
        if [ -f /etc/hosts.allow ]; then
            local ftp_allow
            ftp_allow=$(grep -i "vsftpd\|ftpd\|proftpd" /etc/hosts.allow 2>/dev/null)
            if [ -n "$ftp_allow" ]; then
                detail="FTP 접근 제어 설정: $ftp_allow. "
                status="양호"
            fi
        fi
        if [ "$status" != "양호" ]; then
            detail="FTP 접근 제어 설정 확인 필요. "
        fi
    else
        detail="FTP 서비스 미사용. "
    fi

    add_result "ISMS-U-56" "서비스 관리" "FTP 서비스 접근 제어 설정" "하" "$status" "$detail" "기반시설" "grep -E 'vsftpd|ftpd' /etc/hosts.allow /etc/hosts.deny" "$detail" "TCP Wrapper(/etc/hosts.allow, /etc/hosts.deny) 또는 방화벽으로 FTP 접근 IP 제한."
}

# ISMS-U-57: Ftpusers 파일 설정
check_U57() {
    local status="N/A"
    local detail=""

    local ftp_running=false
    if ps -ef 2>/dev/null | grep -v grep | grep -qE "vsftpd|proftpd|ftpd" || \
       systemctl is-active vsftpd &>/dev/null; then
        ftp_running=true
    fi

    if [ "$ftp_running" = true ]; then
        # Check ftpusers file for root
        local root_blocked=false
        for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list; do
            if [ -f "$f" ]; then
                if grep -q "^root$" "$f" 2>/dev/null; then
                    root_blocked=true
                    detail+="$f: root 접근 차단. "
                fi
            fi
        done

        if [ "$root_blocked" = true ]; then
            status="양호"
        else
            status="취약"
            detail+="ftpusers에 root 미등록. "
        fi
    else
        detail="FTP 서비스 미사용. "
    fi

    add_result "ISMS-U-57" "서비스 관리" "Ftpusers 파일 설정" "중" "$status" "$detail" "공통" "grep root /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list" "$detail" "ftpusers 파일에 root 계정 등록하여 FTP root 접근 차단."
}

# ISMS-U-58: 불필요한 SNMP 서비스 구동 점검
check_U58() {
    local status="양호"
    local detail=""

    if systemctl is-active snmpd &>/dev/null || ps -ef 2>/dev/null | grep -v grep | grep -q snmpd; then
        status="취약"
        detail="SNMP 서비스 실행 중. "
    else
        detail="SNMP 서비스 미사용. "
    fi

    add_result "ISMS-U-58" "서비스 관리" "불필요한 SNMP 서비스 구동 점검" "중" "$status" "$detail" "기반시설" "systemctl is-active snmpd; ps -ef | grep snmpd" "$detail" "불필요 시 SNMP 서비스 비활성화: systemctl stop snmpd && systemctl disable snmpd"
}

# ISMS-U-59: 안전한 SNMP 버전 사용
check_U59() {
    local status="N/A"
    local detail=""

    if systemctl is-active snmpd &>/dev/null || ps -ef 2>/dev/null | grep -v grep | grep -q snmpd; then
        if [ -f /etc/snmp/snmpd.conf ]; then
            local v3_user
            v3_user=$(grep -E "^(createUser|rouser|rwuser)" /etc/snmp/snmpd.conf 2>/dev/null)
            local v2_comm
            v2_comm=$(grep -E "^(rocommunity|rwcommunity)" /etc/snmp/snmpd.conf 2>/dev/null)

            if [ -n "$v3_user" ]; then
                status="양호"
                detail="SNMP v3 사용자 설정 존재. "
            fi
            if [ -n "$v2_comm" ]; then
                status="취약"
                detail+="SNMP v1/v2c community 설정 존재. "
            fi
        else
            detail="snmpd.conf 파일 없음. "
            status="수동점검"
        fi
    else
        detail="SNMP 서비스 미사용. "
    fi

    add_result "ISMS-U-59" "서비스 관리" "안전한 SNMP 버전 사용" "상" "$status" "$detail" "기반시설" "grep -E '^(createUser|rouser|rwuser|rocommunity|rwcommunity)' /etc/snmp/snmpd.conf" "$detail" "SNMP v3 사용 설정. v1/v2c community 설정 제거하고 SNMPv3 인증/암호화 사용."
}

# ISMS-U-60: SNMP Community String 복잡성 설정
check_U60() {
    local status="N/A"
    local detail=""

    if systemctl is-active snmpd &>/dev/null || ps -ef 2>/dev/null | grep -v grep | grep -q snmpd; then
        if [ -f /etc/snmp/snmpd.conf ]; then
            local communities
            communities=$(grep -E "^(rocommunity|rwcommunity)" /etc/snmp/snmpd.conf 2>/dev/null | awk '{print $2}')
            if [ -n "$communities" ]; then
                local has_default=false
                for comm in $communities; do
                    if [ "$comm" = "public" ] || [ "$comm" = "private" ]; then
                        has_default=true
                        detail+="기본 Community String 사용: $comm. "
                    fi
                    if [ ${#comm} -lt 8 ]; then
                        detail+="짧은 Community String: $comm (${#comm}자). "
                        has_default=true
                    fi
                done
                if [ "$has_default" = true ]; then
                    status="취약"
                else
                    status="양호"
                    detail="Community String 복잡성 충족. "
                fi
            fi
        fi
    else
        detail="SNMP 서비스 미사용. "
    fi

    add_result "ISMS-U-60" "서비스 관리" "SNMP Community String 복잡성 설정" "중" "$status" "$detail" "공통" "grep -E '^(rocommunity|rwcommunity)' /etc/snmp/snmpd.conf" "$detail" "Community String을 public/private에서 추측 어려운 복잡한 문자열(8자 이상)로 변경."
}

# ISMS-U-61: SNMP Access Control 설정
check_U61() {
    local status="N/A"
    local detail=""

    if systemctl is-active snmpd &>/dev/null || ps -ef 2>/dev/null | grep -v grep | grep -q snmpd; then
        if [ -f /etc/snmp/snmpd.conf ]; then
            local acl
            acl=$(grep -E "^(com2sec|access|view)" /etc/snmp/snmpd.conf 2>/dev/null)
            if [ -n "$acl" ]; then
                status="양호"
                detail="SNMP 접근 제어 설정 존재. "
            else
                status="취약"
                detail="SNMP 접근 제어 미설정. "
            fi
        fi
    else
        detail="SNMP 서비스 미사용. "
    fi

    add_result "ISMS-U-61" "서비스 관리" "SNMP Access Control 설정" "상" "$status" "$detail" "기반시설" "grep -E '^(com2sec|access|view)' /etc/snmp/snmpd.conf" "$detail" "/etc/snmp/snmpd.conf에서 com2sec, access, view 설정으로 SNMP 접근 제어."
}

# ISMS-U-62: 로그인 시 경고 메시지 설정
check_U62() {
    local status="취약"
    local detail=""
    local cmd="cat /etc/motd; cat /etc/issue; cat /etc/issue.net; grep Banner /etc/ssh/sshd_config; grep SmtpGreetingMessage /etc/mail/sendmail.cf; grep smtpd_banner /etc/postfix/main.cf; grep smtp_banner /etc/exim/exim.conf /etc/exim4/exim4.conf"
    local cur_state=""
    local remediation="/etc/motd, /etc/issue, /etc/issue.net 파일에 경고 메시지 작성. SSH: /etc/ssh/sshd_config에 Banner /etc/issue.net 설정. Sendmail: SmtpGreetingMessage 설정. Postfix: smtpd_banner 설정. Exim: smtp_banner 설정."
    local smtp_vuln="false"

    # Check /etc/motd, /etc/issue, /etc/issue.net
    for f in /etc/motd /etc/issue /etc/issue.net; do
        if [ -f "$f" ]; then
            local content
            content=$(cat "$f" 2>/dev/null | head -3 | tr '\n' ' ')
            if [ -n "$content" ] && [ ${#content} -gt 5 ]; then
                detail+="$f: 설정됨. "
                cur_state+="$f: 설정됨; "
                status="양호"
            fi
        fi
    done

    # Check SSH Banner
    if [ -f /etc/ssh/sshd_config ]; then
        local banner
        banner=$(grep -E "^Banner" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        if [ -n "$banner" ] && [ "$banner" != "none" ]; then
            detail+="SSH Banner: $banner. "
            cur_state+="SSH Banner=$banner; "
            status="양호"
        fi
    fi

    if mail_sendmail_active; then
        local sendmail_banner
        sendmail_banner=$(grep -E '^[[:space:]]*O?[[:space:]]*SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null | grep -v '^[[:space:]]*#' | head -1)
        if [ -n "$sendmail_banner" ]; then
            detail+="Sendmail SMTP 배너 설정됨. "
            cur_state+="Sendmail Banner=설정됨; "
            status="양호"
        else
            detail+="Sendmail SMTP 배너 미설정. "
            cur_state+="Sendmail Banner=미설정; "
            smtp_vuln="true"
        fi
    fi

    if mail_postfix_active; then
        local postfix_banner
        postfix_banner=$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | grep -v '^[[:space:]]*#' | head -1)
        if [ -n "$postfix_banner" ]; then
            detail+="Postfix SMTP 배너 설정됨. "
            cur_state+="Postfix Banner=설정됨; "
            status="양호"
        else
            detail+="Postfix SMTP 배너 미설정. "
            cur_state+="Postfix Banner=미설정; "
            smtp_vuln="true"
        fi
    fi

    if mail_exim_active; then
        local exim_conf
        local exim_banner
        exim_conf=$(mail_exim_config)
        exim_banner=$(grep -E '^[[:space:]]*smtp_banner[[:space:]]*=' "$exim_conf" 2>/dev/null | grep -v '^[[:space:]]*#' | head -1)
        if [ -n "$exim_banner" ]; then
            detail+="Exim SMTP 배너 설정됨. "
            cur_state+="Exim Banner=설정됨; "
            status="양호"
        else
            detail+="Exim SMTP 배너 미설정. "
            cur_state+="Exim Banner=미설정; "
            smtp_vuln="true"
        fi
    fi

    if [ "$smtp_vuln" = "true" ]; then
        status="취약"
    fi

    if [ "$status" = "취약" ]; then
        if [ -z "$detail" ]; then
            detail="로그인 경고 메시지 미설정. "
            cur_state="경고 메시지 미설정"
        fi
    fi

    add_result "ISMS-U-62" "서비스 관리" "로그인 시 경고 메시지 설정" "하" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-63: sudo 명령어 접근 관리
check_U63() {
    local status="양호"
    local detail=""

    if [ -f /etc/sudoers ]; then
        local result
        result=$(check_file_owner_perm "/etc/sudoers" "root" 640)
        if [[ "$result" == VULN* ]]; then
            status="취약"
        fi
        detail="/etc/sudoers: $result. "
    else
        detail="/etc/sudoers 파일 없음. "
        status="N/A"
    fi

    local cur_state_63
    cur_state_63=$(ls -l /etc/sudoers 2>/dev/null | awk '{print $1, $3, $4, $9}')
    add_result "ISMS-U-63" "서비스 관리" "sudo 명령어 접근 관리" "중" "$status" "$detail" "기반시설" "ls -l /etc/sudoers" "${cur_state_63:-/etc/sudoers 없음}" "chown root /etc/sudoers && chmod 440 /etc/sudoers. visudo로 sudoers 편집."
}

###############################################################################
# 4. 패치 관리
###############################################################################

# ISMS-U-64: 주기적 보안 패치 및 벤더 권고사항 적용
check_U64() {
    local status="수동점검"
    local detail=""

    # OS info
    local os_info=""
    if [ -f /etc/os-release ]; then
        os_info=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d'"' -f2)
    fi
    local kernel
    kernel=$(uname -r 2>/dev/null)

    detail="OS: ${os_info:-확인불가}, Kernel: ${kernel:-확인불가}. 패치 정책 수립 여부 수동 확인 필요. "
    local cur_state="OS: ${os_info:-확인불가}, Kernel: ${kernel:-확인불가}"

    add_result "ISMS-U-64" "패치 관리" "주기적 보안 패치 및 벤더 권고사항 적용" "상" "$status" "$detail" "공통" "cat /etc/os-release; uname -r" "$cur_state" "주기적 보안 패치 정책 수립 및 적용. apt update && apt upgrade 또는 yum update 정기 실행."
}

###############################################################################
# 5. 로그 관리
###############################################################################

# ISMS-U-65: NTP 및 시각 동기화 설정
check_U65() {
    local status="취약"
    local detail=""
    local cmd="systemctl is-active chronyd; systemctl is-active ntpd; systemctl is-active systemd-timesyncd"
    local cur_state=""
    local remediation="NTP 서비스 활성화: systemctl enable --now chronyd 또는 systemctl enable --now systemd-timesyncd"

    if systemctl is-active chronyd &>/dev/null; then
        status="양호"
        local sources
        sources=$(chronyc sources 2>/dev/null | grep -c "^\^" 2>/dev/null)
        detail="chronyd 활성화, NTP 소스 ${sources:-0}개. "
        cur_state="chronyd active, NTP 소스 ${sources:-0}개"
    elif systemctl is-active ntpd &>/dev/null || systemctl is-active ntp &>/dev/null; then
        status="양호"
        detail="NTP 데몬 활성화. "
        cur_state="ntpd active"
    elif systemctl is-active systemd-timesyncd &>/dev/null; then
        status="양호"
        detail="systemd-timesyncd 활성화. "
        cur_state="systemd-timesyncd active"
    else
        detail="NTP/시각 동기화 서비스 미활성화. "
        cur_state="NTP 서비스 미활성화"
    fi

    add_result "ISMS-U-65" "로그 관리" "NTP 및 시각 동기화 설정" "중" "$status" "$detail" "기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-66: 정책에 따른 시스템 로깅 설정
check_U66() {
    local status="취약"
    local detail=""
    local cmd="systemctl is-active rsyslog; grep -E '^(auth|authpriv)' /etc/rsyslog.conf"
    local cur_state=""
    local remediation="rsyslog 서비스 활성화: systemctl enable --now rsyslog. /etc/rsyslog.conf에서 auth, authpriv, kern 등 로깅 정책 설정."

    if systemctl is-active rsyslog &>/dev/null; then
        status="양호"
        detail="rsyslog 서비스 활성화. "
        cur_state="rsyslog active"

        if [ -f /etc/rsyslog.conf ]; then
            local auth_log
            auth_log=$(grep -E "^(auth|authpriv)" /etc/rsyslog.conf 2>/dev/null | head -1)
            if [ -n "$auth_log" ]; then
                detail+="인증 로그 설정: $auth_log. "
                cur_state+="; 인증 로그: $auth_log"
            fi
        fi
    elif systemctl is-active syslog &>/dev/null; then
        status="양호"
        detail="syslog 서비스 활성화. "
        cur_state="syslog active"
    elif systemctl is-active systemd-journald &>/dev/null; then
        status="양호"
        detail="systemd-journald 활성화. "
        cur_state="systemd-journald active"
    else
        detail="시스템 로깅 서비스 미활성화. "
        cur_state="로깅 서비스 미활성화"
    fi

    add_result "ISMS-U-66" "로그 관리" "정책에 따른 시스템 로깅 설정" "중" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

# ISMS-U-67: 로그 디렉터리 소유자 및 권한 설정
check_U67() {
    local status="양호"
    local detail=""
    local vuln_logs=""
    local cmd="ls -l /var/log/"
    local cur_state=""
    local remediation="로그 파일 권한 644 이하로 설정: chmod 644 /var/log/파일명"

    if [ -d /var/log ]; then
        while IFS= read -r f; do
            local owner perm
            owner=$(stat -c '%U' "$f" 2>/dev/null)
            perm=$(stat -c '%a' "$f" 2>/dev/null)
            if [ "$perm" -gt 644 ] 2>/dev/null; then
                vuln_logs+="$(basename "$f")($perm) "
            fi
        done < <(find /var/log -maxdepth 1 -type f 2>/dev/null | head -30)
    fi

    if [ -n "$vuln_logs" ]; then
        detail="644 초과 권한 로그파일: ${vuln_logs:0:200}. "
        cur_state="644 초과: ${vuln_logs:0:200}"
        status="취약"
    else
        detail="/var/log 파일 권한 적절. "
        cur_state="/var/log 파일 권한 적절"
    fi

    add_result "ISMS-U-67" "로그 관리" "로그 디렉터리 소유자 및 권한 설정" "중" "$status" "$detail" "공통" "$cmd" "$cur_state" "$remediation"
}

###############################################################################
# 클라우드 가이드 추가 항목 (Server Linux 전용)
###############################################################################

# CL-LIN-01: 패스워드 최대 사용 기간 설정 (클라우드 가이드 강화: 90일)
check_CL_LIN_01() {
    local status="양호"
    local detail=""
    local cmd="grep '^PASS_MAX_DAYS' /etc/login.defs; chage -l 사용자명"
    local cur_state=""
    local remediation="/etc/login.defs에서 PASS_MAX_DAYS 90 설정. 각 사용자에 chage -M 90 사용자명 적용."

    if [ -f /etc/login.defs ]; then
        local pass_max
        pass_max=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        detail="PASS_MAX_DAYS=${pass_max:-미설정}. "
        cur_state="PASS_MAX_DAYS=${pass_max:-미설정}"
        if [ -z "$pass_max" ] || [ "$pass_max" -gt 90 ] 2>/dev/null || [ "$pass_max" -le 0 ] 2>/dev/null; then
            status="취약"
        fi
    else
        status="취약"
        detail="login.defs 없음. "
        cur_state="login.defs 없음"
    fi

    # Check per-user settings
    local vuln_users=""
    while IFS=: read -r user _ _ _ _ _ shell; do
        if echo "$shell" | grep -qE "nologin|false"; then continue; fi
        local max_days
        max_days=$(chage -l "$user" 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ')
        if [ "$max_days" = "99999" ] || [ "$max_days" = "-1" ]; then
            vuln_users+="$user(${max_days}) "
        fi
    done < /etc/passwd

    if [ -n "$vuln_users" ]; then
        detail+="패스워드 만료 미설정 계정: ${vuln_users:0:150}. "
        cur_state+="; 만료 미설정: ${vuln_users:0:150}"
        status="취약"
    fi

    add_result "CL-LIN-01" "계정 관리" "패스워드 최대 사용 기간 설정" "상" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

###############################################################################
# Execute all checks
###############################################################################

echo "===== Linux CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/68] %s 점검 중...                " "$total" "$1"
}

# 1. 계정 관리
progress "ISMS-U-01"; check_U01
progress "ISMS-U-02"; check_U02
progress "ISMS-U-03"; check_U03
progress "ISMS-U-04"; check_U04
progress "ISMS-U-05"; check_U05
progress "ISMS-U-06"; check_U06
progress "ISMS-U-07"; check_U07
progress "ISMS-U-08"; check_U08
progress "ISMS-U-09"; check_U09
progress "ISMS-U-10"; check_U10
progress "ISMS-U-11"; check_U11
progress "ISMS-U-12"; check_U12
progress "ISMS-U-13"; check_U13

# 2. 파일 및 디렉토리 관리
progress "ISMS-U-14"; check_U14
progress "ISMS-U-15"; check_U15
progress "ISMS-U-16"; check_U16
progress "ISMS-U-17"; check_U17
progress "ISMS-U-18"; check_U18
progress "ISMS-U-19"; check_U19
progress "ISMS-U-20"; check_U20
progress "ISMS-U-21"; check_U21
progress "ISMS-U-22"; check_U22
progress "ISMS-U-23"; check_U23
progress "ISMS-U-24"; check_U24
progress "ISMS-U-25"; check_U25
progress "ISMS-U-26"; check_U26
progress "ISMS-U-27"; check_U27
progress "ISMS-U-28"; check_U28
progress "ISMS-U-29"; check_U29
progress "ISMS-U-30"; check_U30
progress "ISMS-U-31"; check_U31
progress "ISMS-U-32"; check_U32
progress "ISMS-U-33"; check_U33

# 3. 서비스 관리
progress "ISMS-U-34"; check_U34
progress "ISMS-U-35"; check_U35
progress "ISMS-U-36"; check_U36
progress "ISMS-U-37"; check_U37
progress "ISMS-U-38"; check_U38
progress "ISMS-U-39"; check_U39
progress "ISMS-U-40"; check_U40
progress "ISMS-U-41"; check_U41
progress "ISMS-U-42"; check_U42
progress "ISMS-U-43"; check_U43
progress "ISMS-U-44"; check_U44
progress "ISMS-U-45"; check_U45
progress "ISMS-U-46"; check_U46
progress "ISMS-U-47"; check_U47
progress "ISMS-U-48"; check_U48
progress "ISMS-U-49"; check_U49
progress "ISMS-U-50"; check_U50
progress "ISMS-U-51"; check_U51
progress "ISMS-U-52"; check_U52
progress "ISMS-U-53"; check_U53
progress "ISMS-U-54"; check_U54
progress "ISMS-U-55"; check_U55
progress "ISMS-U-56"; check_U56
progress "ISMS-U-57"; check_U57
progress "ISMS-U-58"; check_U58
progress "ISMS-U-59"; check_U59
progress "ISMS-U-60"; check_U60
progress "ISMS-U-61"; check_U61
progress "ISMS-U-62"; check_U62
progress "ISMS-U-63"; check_U63

# 4. 패치 관리
progress "ISMS-U-64"; check_U64

# 5. 로그 관리
progress "ISMS-U-65"; check_U65
progress "ISMS-U-66"; check_U66
progress "ISMS-U-67"; check_U67

# 클라우드 가이드 추가 항목
progress "CL-LIN-01"; check_CL_LIN_01

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
    echo '    "platform": "Linux",'
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

echo "===== Linux CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
