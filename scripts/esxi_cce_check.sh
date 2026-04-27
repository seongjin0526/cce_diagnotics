#!/bin/sh
###############################################################################
# ESXi CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash esxi_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

HOST_TAG=$( (hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown) | tr ' /' '__' )

OUTPUT_FILE="${1:-cce_check_result_esxi_${HOST_TAG}_$(date +%Y%m%d_%H%M%S).json}"

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

    printf '%s\n' "{\"code\":\"$code\",\"category\":\"$category\",\"title\":\"$title\",\"importance\":\"$importance\",\"status\":\"$status\",\"detail\":\"$detail\",\"source\":\"$source\",\"command\":\"$command\",\"current_state\":\"$current_state\",\"remediation\":\"$remediation\"}" >> "$RESULTS_FILE"
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


# --- ESXi helper ---
run_esxcli() {
    esxcli "$@" 2>/dev/null
}


# --- Pre-flight: ESXi 설치 확인 및 경로 탐지 ---
ESXCLI_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) 바이너리 탐지 (ESXi BusyBox 환경)
    if [ -x "/bin/esxcli" ] || [ -x "/sbin/esxcli" ]; then
        ESXCLI_BIN="esxcli"
        APP_FOUND="true"
    fi
    if which vim-cmd >/dev/null 2>&1; then
        APP_FOUND="true"
    fi

    # 2) ESXi 환경 자체 확인
    if [ -f "/etc/vmware/esx.conf" ]; then
        APP_FOUND="true"
    fi
    if [ -d "/etc/vmware" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] ESXi 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CSAP-ESXi-03 / ISMS-HV-07: 계정 잠금 임계값 설정
check_CSAP_ESXi_03() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/pam.d/system-auth-tally"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ 해당 설정 파일에 패스워드 입력 횟수를 제한하는 내용 추가 (예. 5회) # vi /etc/pam.d/system-auth-tally auth sufficient pam_tally2.so silent onerr=fail even_deny_root deny=5 unlock_time=100 (생략) account required pam_tally2.so silent [vClient] ￭ 패스워드 입력 횟수를 5회로 변경 vClient 실행 → 호스트 → 관리 → 시스템 → 고급설정 → security.AccountLockFailures 및 Security.AccountUnlockTime 변경 [주요기반시설 가이드] 로그인 시도 실패 횟수 제한 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 관리 > 설정 > 시스템 > 고급 설정으로 이동 Step 3) Security.AccountLockFailures 설정이 5 이하로 설정되어 있는지 확인 [ 계정 잠금 실패 값 확인 ] Step 4) 5 이하로 설정되어 있지 않은 경우 [옵션 편집]을 클릭하여 아래와 같이 수정 [ 계정 잠금 실패 값 설정 ] Step 5) Security.AccountUnlockTime 설정이 600초(10분) 이상으로 설정되어 있는지 확인 [ 계정 잠금 해제 시간 확인 ] Step 6) 600초(10분) 이상으로 설정되어 있지 않은 경우 [옵션 편집]을 클릭하여 아래와 같이 수정 [ 계정 잠금 해제 시간 설정 ] ※ 시스템이 관련 기능을 지원하지 않을 경우, 내부 정책 확인 11. 가상화 장비 l VMware vCenter Step 1) vSphere Client 접속 후, 다음 메뉴에 접근하여 확인(vSphere Client 버전에 따라, 메뉴 명칭은 달라질 수 있음) (vCenter6.5) \"관리\" > \"Single Sign On\" > \"구성\" > \"Policies\" > \"잠금정책(Lockout Policy)\" > 접속제한 관련 설정(실패한 최대 로그인 시도 횟수, 실패 시간 간격, 잠금 해제 시간)을 확인 (vCenter8) \"관리\" > \"Single Sign On\" > \"구성\" > \"로컬 계정\" > \"잠금정책(Lockout Policy)\" > 접속제한 관련 설정(실패한 최대 로그인 시도 횟수, 실패 시간 간격, 잠금 해제 시간)을 확인"

    local config_file="/etc/pam.d/system-auth-tally"
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

    add_result "CSAP-ESXi-03 / ISMS-HV-07" "계정 관리" "계정 잠금 임계값 설정" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-05 / ISMS-HV-12: ESXi Shell 사용 제한
check_CSAP_ESXi_05() {
    local status="양호"
    local detail=""
    local cmd="/etc/init.d/ESXShell status 입력 후 ESXi Shell 활성화 여부 확인"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ ESXi Shell 사용하지 않을 경우, 사용 제한 설정 # /etc/init.d/ESXShell ESXi Shell 비활성화 [vClient] ￭ ESXi Shell 사용하지 않을 경우, 사용 제한 설정 (ESXi 6.x 기준) vClient 실행 → ESXi 호스트 → 관리 → 서비스 → TSM과 TSM-SSH 항목을 오른쪽 클릭하여 \"중지\" [주요기반시설 가이드] ESXi Shell(TSM, TSM-SSH) 서비스가 비활성화 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 서비스로 이동 Step 3) TSM, TSM-SSH 서비스 활성화 여부 확인 [ TSM TSM-SSH 서비스 활성화 여부 확인 ] Step 4) TSM, TSM-SSH 서비스가 활성화되어 있는 경우, [중지] 클릭하여 서비스 중지 11. 가상화 장비 827"

    local output
    output=$({
        ( /etc/init.d/ESXShell status ESXi Shell )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="ESXi Shell(TSM, TSM-SSH) 서비스가 비활성화된 경우"
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
            detail="ESXi Shell(TSM, TSM-SSH) 서비스가 비활성화된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="ESXi Shell(TSM, TSM-SSH) 서비스가 활성화된 경우"
        else
            status="취약"
            detail="ESXi Shell(TSM, TSM-SSH) 서비스가 활성화된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-05 / ISMS-HV-12" "보안 관리" "ESXi Shell 사용 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-06 / ISMS-HV-13: ESXi Shell 자동 종료
check_CSAP_ESXi_06() {
    local status="양호"
    local detail=""
    local cmd="esxcli system settings advanced list -o \"/UserVars/ESXiShellTimeOut\" 입력 후"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ ESXi Shell 시간 초과 설정 # esxcli system settings advanced set -o /UserVars/ESXiShellTimeOut –i <원하는_대기시간_분 단위> 변경된 설정이 적용되도록 ESXi 호스트를 다시 부팅하거나, 변경된 설정을 즉시 적용하려면 다음 명령어 사용 # esxcli hardware reboot [vClient] ￭ ESXi Shell 시간 초과 설정 (ESXi 6.x 기준) vClient 실행 → 호스트 → 관리 → 시스템 → 고급설정 → UserVars.ESXiShellTimeOut에서 시간 변경(10분) [주요기반시설 가이드] Session Timeout 값(ESXiShellInteractiveTimeOut)이 900 이하 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 관리 > 설정 > 시스템 > 고급 설정으로 이동 Step 3) UserVars.ESXiShellInteractiveTimeOut 설정값 확인 [ ESXiShellInteractiveTimeOut 설정값 확인 ] Step 4) 0 또는 600초(10분) 초과로 설정되어 있을 경우 [옵션 편집]을 클릭하여 아래와 같이 수정 [ 900 이하 설정 적용 ] 11. 가상화 장비 829"

    local output
    output=$({
        ( esxcli system settings advanced list -o /UserVars/ESXiShellTimeOut )
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
        local numeric_value
        numeric_value=$(first_numeric_value "$output")
        if [ -z "$numeric_value" ] || [ "$numeric_value" -eq 0 ] 2>/dev/null; then
            status="취약"
            detail="Session Timeout 값(ESXiShellInteractiveTimeOut)이 0이거나, 600초과로 설정된 경우"
        else
            if [ "$numeric_value" -le 600 ] 2>/dev/null; then
                status="양호"
                detail="Session Timeout 값(ESXiShellInteractiveTimeOut)이 600 이하로 설정된 경우"
            else
                status="취약"
                detail="Session Timeout 값(ESXiShellInteractiveTimeOut)이 0이거나, 600초과로 설정된 경우"
            fi
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-06 / ISMS-HV-13" "보안 관리" "ESXi Shell 자동 종료" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-08 / ISMS-HV-22: 가상스위치 MAC 주소 변경정책 설정
check_CSAP_ESXi_08() {
    local status="양호"
    local detail=""
    local cmd="esxcli network vswitch standard policy security get -v \"vSwitch0\"(가상스위치"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ 가상스위치 MAC 주소 변경정책 설정 # esxcli network vswitch standard policy security set -v vSwitch0(가상스위치 이름) -m false 입력 [vClient] ￭ 가상스위치 MAC 주소 변경정책 설정 (ESXi 6.x 기준) vClient 실행 → 호스트 → 네트워킹 → vSwitch0 → 보안 정책 → MAC 변경 허용 값 \"아니요\" 변경 [주요기반시설 가이드] 가상 스위치 MAC 주소 변경 정책 거부 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 네트워킹 > 가상 스위치 > [가상 스위치 선택] > 설정 편집 > 보안으로 이동 Step 3) MAC 주소 변경 정책 설정 확인 Step 4) 허용으로 설정되어 있을 경우, '거부'로 변경 후 해당 설정 저장 [ MAC 주소 변경 정책 설정 확인 ] 846"

    local output
    output=$({
        ( esxcli network vswitch standard policy security get -v vSwitch0 )
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
            status="양호"
            detail="가상 스위치 MAC 주소 변경 정책이 거부로 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="가상 스위치 MAC 주소 변경 정책이 허용으로 설정된 경우"
        else
            status="취약"
            detail="가상 스위치 MAC 주소 변경 정책이 허용으로 설정된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-08 / ISMS-HV-22" "보안 관리" "가상스위치 MAC 주소 변경정책 설정" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-09 / ISMS-HV-23: 가상스위치 Promiscuous 모드 정책 설정
check_CSAP_ESXi_09() {
    local status="양호"
    local detail=""
    local cmd="esxcli network vswitch standard policy security get -v \"vSwitch0(가상스위치"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ 가상스위치 Promiscuous 모드 정책 변경 # esxcli network vswitch standard policy security set -v \"vSwitch0(가상스위치 이름)\" -p false 입력 [vClient] ￭ 가상스위치 Promiscuous 모드 정책 변경 (ESXi 6.x 기준) vClient 실행 → 호스트 → 네트워킹 → vSwitch0 → 보안 정책 → \"비규칙 모드 허용\" 값을 \"아니요\" 변경 [주요기반시설 가이드] 가상 스위치 무차별(Promiscuous) 모드 정책 거부 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 네트워킹 > 가상 스위치 > [가상 스위치 선택] > 설정 편집 > 보안으로 이동 Step 3) 무차별 모드 정책 설정 확인 Step 4) 허용으로 설정되어 있을 경우, '거부'로 변경 후 해당 설정 저장 11. 가상화 장비 [ 무차별 모드 정책 설정 확인 ]"

    local output
    output=$({
        ( esxcli network vswitch standard policy security get -v vSwitch0 )
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
            status="양호"
            detail="가상 스위치 무차별(Promiscuous) 모드 정책 설정이 거부로 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="가상 스위치 무차별(Promiscuous) 모드 정책 설정이 허용으로 설정된 경우"
        else
            status="취약"
            detail="가상 스위치 무차별(Promiscuous) 모드 정책 설정이 허용으로 설정된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-09 / ISMS-HV-23" "보안 관리" "가상스위치 Promiscuous 모드 정책 설정" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-10 / ISMS-HV-24: 가상스위치 Forged Transmits 모드 정책 설정
check_CSAP_ESXi_10() {
    local status="양호"
    local detail=""
    local cmd="esxcli network vswitch standard policy security get -v \"vSwitch0\"(가상스위치"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ 가상스위치 Forged Transmits 모드 정책 변경 # esxcli network vswitch standard policy security set -v \"vSwitch0(가상스위치 이름)\" -f false 입력 [vClient] ￭ 가상스위치 Forged Transmits 모드 정책 변경 (ESXi 6.x 기준) vClient 실행 → 호스트 → 네트워킹 → vSwitch0 → 보안 정책 → \"위조 전송 허용\" 값을 \"아니요\" 변경 [주요기반시설 가이드] 위조 전송(Forged Transmits) 모드 거부 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 네트워킹 > 가상 스위치 > [가상 스위치 선택] > 설정 편집 > 보안으로 이동 Step 3) 위조 전송 정책 설정 확인 Step 4) 허용으로 설정되어 있을 경우, '거부'로 변경 후 해당 설정 저장 11. 가상화 장비 [위조 전송 정책 설정 확인 ] 850"

    local output
    output=$({
        ( esxcli network vswitch standard policy security get -v vSwitch0 )
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
            status="양호"
            detail="가상 스위치에 위조 전송(Forged Transmits) 모드 설정이 거부로 설정된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="가상 스위치에 위조 전송(Forged Transmits) 모드 설정이 허용으로 설정된 경우"
        else
            status="취약"
            detail="가상 스위치에 위조 전송(Forged Transmits) 모드 설정이 허용으로 설정된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-10 / ISMS-HV-24" "보안 관리" "가상스위치 Forged Transmits 모드 정책 설정" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-13 / ISMS-HV-10: SNMP Community String 복잡성 설정
check_CSAP_ESXi_13() {
    local status="양호"
    local detail=""
    local cmd="esxcli system snmp get | grep Communities 입력 후 Communities 값 확인; esxcli system snmp get; cat /etc/vmware/snmp.xml | grep community | awk -F '\"' '{print \$4}'"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ Community String 값 변경 # esxcli system snmp set -c \"수정할 Community String 값\" 입력 [주요기반시설 가이드] SNMP Community String을 복잡도를 만족하는 값으로 설정 [상세 조치 사례] l VMware ESXi Step 1) SSH를 통해 ESXi 호스트 서버 접속 후, 다음 명령어 실행 \$ esxcli system snmp get Step 2) 다음 명령어를 사용해 Community String 값 설정 변경 \$ esxcli system snmp set --communities <변경 값> l VMware vCenter Step 1) SNMP 사용 확인 if [[ \$(vim-cmd proxysvc/service_list | grep 'TSM') ]]; then echo \"SNMP service is running on vcenter\" else echo \"SNMP service is not running on vcenter\" fi cat /etc/vmware/snmp.xml | grep community | awk -F '\"' '{print \$4}' Step 2) SNMP Community String 설정 확인 # /etc/snmpd.conf 파일에서 Community String 확인 # /usr/lib/vmware/vm-support/bin/nvpsvc -printconfig | grep –E \"SNMPCommunityString|SNMPAccessC ontrol\""

    local output
    output=$({
        ( get_process_snapshot "communities" )
        ( esxcli system snmp get )
        ( get_process_snapshot "community" )
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
            status="양호"
            detail="SNMP Community String이 복잡도를 만족하는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="SNMP Community String이 복잡도를 만족하지 않는 경우"
        else
            status="취약"
            detail="SNMP Community String이 복잡도를 만족하지 않는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-13 / ISMS-HV-10" "보안 관리" "SNMP Community String 복잡성 설정" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-21 / ISMS-HV-11: MOB(Managed Object Browser) 비활성화
check_CSAP_ESXi_21() {
    local status="양호"
    local detail=""
    local cmd="vim-cmd proxysvc/service_list 입력 후 확인"
    local cur_state=""
    local remediation="[클라우드 가이드] [CLI] ￭ MOB 비활성화 # vim-cmd proxysvc/remove_service \"/mob\" \"httpsWithRedirect\" 입력 [주요기반시설 가이드] MOB(Managed Object Browser)서비스 비활성화 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 고급 설정으로 이동 Step 3) Config,HostAgent.plugins.solo.enableMob 설정값 확인 [ MOB 활성화 값 확인 ] 11. 가상화 장비 Step 4) 활성화(true)되어 있을 시, 해당 값을 false로 설정 [ MOB 비활성화 설정 적용 ] l VMware vCenter Step 1) vSphere Client 접속 후, 다음 메뉴에 접근하여 확인(vSphere Client 버전에 따라, 메뉴 명칭은 달라질 수 있음) # (vCenter6.5) \"호스트 및 클러스터\" > [vCenter 서버] > \"구성\" > \"설정\" > \"고급 설정\" > \"config.vpxd.enableDebugBrowse\" 확인 # (vCenter8) \"호스트 및 클러스터\" > [vCenter 서버] > \"구성\" > \"설정\" > \"고급 설정\" > \"config.vpxd.enableDebugBrowse\" 확인 826"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. MOB(Managed Object Browser)가 비활성화된 경우"
    cur_state="수동점검 필요"

    add_result "CSAP-ESXi-21 / ISMS-HV-11" "보안 관리" "MOB(Managed Object Browser) 비활성화" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-01: root 계정 원격 접속 제한
check_CSAP_ESXi_01() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/ssh/sshd_config | grep PermitRootLogin"
    local cur_state=""
    local remediation="￭ root 계정의 ssh 접속 제한 설정 1. vi 편집기를 이용하여 /etc/ssh/sshd_config 파일 열기 # vi /etc/ssh/sshd_config 2. 아래와 같이 설정 변경 PermitRootLogin no"

    local config_file="/etc/ssh/sshd_config"
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

    add_result "CSAP-ESXi-01" "패치 및 로그 관리" "root 계정 원격 접속 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-02: 패스워드 복잡성 설정
check_CSAP_ESXi_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 설정 확인 1. vi 편집기를 이용해 /etc/pam.d/passwd 파일 내 pam_passwdqc.so 수정 문자 클래스 3개 또는 4개인 경우, 8자리 이상 적용 : retry=3 min=disabled,disabled,disabled,8,8 문자 클래스 2개, 10자리 이상 적용 : retry=3 min=disabled,10,disabled,disabled,disabled ￭ 일반적으로 권장하는 패스워드 설정 1. 패스워드의 길이는 최소 8자 이상으로 설정 2. 영문(대문자, 소문자), 숫자, 특수문자를 혼합하여 패스워드 설정 3. 패스워드는 주기적으로 변경하고, 재사용 금지 4. 사전에 있는 단어나 누구나 유추 가능한 간단한 패스워드 사용 금지 ￭ ESXi 사용자 계정 패스워드 변경 1. 다른 사용자 계정 패스워드 변경(Root 권한일 때) # passwd 변경할 ID Enter new password : 변경할 Passwd Re-type new passwd : 변경할 Passwd (위와 동일) 2. 접속 중인 자신의 계정 패스워드 변경 # passwd Enter new password : 변경할 Passwd Re-type new passwd : 변경할 Passwd (위와 동일) ※ 다음과 같은 패스워드는 피해야 한다. 지역명, 부서명, 담당자, 성명, 대표, 업무명, \"root\", \"root123\", \"admin\", \"123admin\" 등"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 패스워드를 영문, 숫자, 특수문자를 혼합"
    cur_state="수동점검 필요"

    add_result "CSAP-ESXi-02" "" "패스워드 복잡성 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-04: 사용자 계정 관리
check_CSAP_ESXi_04() {
    local status="양호"
    local detail=""
    local cmd="/etc/passwd"
    local cur_state=""
    local remediation="[vClient] ￭ 사용자 계정 권한 설정 vClient 실행 → 탐색기 → 호스트 → 관리 → 보안 및 사용자 → 용도 파악 후 불필요한 계정이 있는 경우 제거하고 사용자의 경우 최소한의 권한만 부여"

    local output
    output=$({
        ( /etc/passwd )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="불필요한 계정이 없거나 모니터링 계정에"
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

    add_result "CSAP-ESXi-04" "계정 관리" "사용자 계정 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-07: ESXi Shell 및 SSH 세션 타임아웃 설정
check_CSAP_ESXi_07() {
    local status="양호"
    local detail=""
    local cmd="esxcli system settings advanced list -o \"/UserVars/ESXiShellInteractiveTimeOut\""
    local cur_state=""
    local remediation="[CLI] ￭ 세션 타임아웃 설정 # esxcli system settings advanced set -o \"/UserVars/ESXiShellInteractiveTimeOut\" -i 600 (초 단위) 입력 변경된 설정이 적용되도록 ESXi 호스트를 다시 부팅하거나, 변경된 설정을 즉시 적용하려면 다음 명령어를 사용함 # esxcli hardware reboot [vClient] ￭ ESXi Shell 시간 초과 설정 (ESXi 6.x 기준) vClient 실행 → 호스트 → 관리 → 시스템 → 고급설정 → UserVars.ESXiShellInteractiveTimeOut에서 시간 설정 (초 단위)"

    local output
    output=$({
        ( esxcli system settings advanced list -o /UserVars/ESXiShellInteractiveTimeOut )
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
            status="양호"
            detail="세션 타임아웃 설정이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="세션 타임아웃 설정이 적용되지 않은 경우"
        else
            status="취약"
            detail="세션 타임아웃 설정이 적용되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-07" "보안 관리" "ESXi Shell 및 SSH 세션 타임아웃 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-11: SSH 데몬 빈암호 사용 인증 허용 제한
check_CSAP_ESXi_11() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/ssh/sshd_config | grep PermitEmptyPasswords 입력 후"
    local cur_state=""
    local remediation="￭ ssh 빈 암호 인증 허용 사용 제한 설정 1. vi 편집기를 이용하여 /etc/ssh/sshd_config 파일을 연 후 # vi /etc/ssh/sshd_config 2. 아래와 같이 설정 변경 PermitEmptyPasswords no"

    local config_file="/ssh/sshd_config"
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

    add_result "CSAP-ESXi-11" "보안 관리" "SSH 데몬 빈암호 사용 인증 허용 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-12: SNMP 서비스 확인
check_CSAP_ESXi_12() {
    local status="양호"
    local detail=""
    local cmd="esxcli system snmp get | grep Enable 입력 후 Enable 값 확인"
    local cur_state=""
    local remediation="[CLI] ￭ SNMP 비활성화 설정 # esxcli system snmp set -e no 입력 [vClient] ￭ SNMP 비활성화 설정 vClient 실행 → 호스트 → 관리 → 서비스 → SNMP 중지 (ESXi 6.x 기준)"

    local output
    output=$({
        ( get_process_snapshot "enable" )
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
            status="양호"
            detail="불필요한 SNMP가 비활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 SNMP가 활성화되어 있는 경우"
        else
            status="취약"
            detail="불필요한 SNMP가 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-12" "보안 관리" "SNMP 서비스 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-14: 접속 IP 및 포트 제한
check_CSAP_ESXi_14() {
    local status="양호"
    local detail=""
    local cmd="esxcli network firewall ruleset allowedip list 입력 후 IP 제한 설정 확인"
    local cur_state=""
    local remediation="[CLI] ￭ 서비스별 허용할 IP 설정 1. 해당 서비스에서 모든 IP 차단 # esxcli network firewall ruleset set --ruleset-id sshServer --allowed-all false 입력 2. 허용할 IP 설정 # esxcli network firewall ruleset allowedip add --ruleset-id sshServer --ip-address IP 주소 또는 대역 입력 [vClient]] ￭ 서비스별 허용할 IP 설정 vClient 실행 → 설정 → 보안 프로파일 → Firewall → 속성에서 각 서비스별 IP 제한 설정 ※ ESXi Shell에서 IP 제한 설정 시 설정할 서비스에서 모든 IP에 대해 deny 설정 후 허용할 IP 설정"

    local output
    output=$({
        ( esxcli network firewall ruleset allowedip list IP )
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
            status="양호"
            detail="원격접속 가능한 서비스에 IP 제한 설정이"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="원격접속 가능한 서비스에 IP 제한 설정이"
        else
            status="취약"
            detail="원격접속 가능한 서비스에 IP 제한 설정이"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-14" "보안 관리" "접속 IP 및 포트 제한" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-15: FTP 비활성화
check_CSAP_ESXi_15() {
    local status="양호"
    local detail=""
    local cmd="esxcli network ip connection list에서 21 port의 proftpd 확인"
    local cur_state=""
    local remediation="[CLI] ￭ FTP 구동 중지 # /etc/init.d/proftpd stop"

    local output
    output=$({
        ( esxcli network ip connection list 21 port proftpd )
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
            status="양호"
            detail="FTP 서비스가 비활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="FTP 서비스가 활성화되어 있는 경우"
        else
            status="취약"
            detail="FTP 서비스가 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-15" "보안 관리" "FTP 비활성화" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-16: FTP root 접속 설정
check_CSAP_ESXi_16() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/proftpd.conf에서 RootLogin확인"
    local cur_state=""
    local remediation="￭ FTP root 접속 제한 설정 1. vi 편집기를 이용하여 /etc/proftpd.conf 파일을 연 후 # vi /etc/proftpd.conf 2. 아래와 같이 설정 변경 RootLogin off"

    local output
    output=$({
        ( cat /etc/proftpd.conf RootLogin )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="root로 원격접속이 가능할 경우"
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
            detail="root로 원격접속이 가능할 경우"
        else
            status="양호"
            detail="root로 원격접속이 불가능할 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-16" "보안 관리" "FTP root 접속 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-17: FTP 기본 디렉터리 경로 확인
check_CSAP_ESXi_17() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/proftpd.conf에서 DefaultRoot확인"
    local cur_state=""
    local remediation="￭ FTP root 접속 제한 설정 1. vi 편집기를 이용하여 /etc/proftpd.conf 파일을 연 후 # vi /etc/proftpd.conf 2. 아래와 같이 설정 변경 DefaultRoot /test(지정할 디렉터리 경로)"

    local output
    output=$({
        ( cat /etc/proftpd.conf DefaultRoot )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="취약"
        detail="DefaultRoot 설정이 최상위 Root"
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
            detail="DefaultRoot 설정이 최상위 Root"
        else
            status="양호"
            detail="DefaultRoot 설정이 변경되어있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-17" "보안 관리" "FTP 기본 디렉터리 경로 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-18: NTP 시간 동기화 설정
check_CSAP_ESXi_18() {
    local status="양호"
    local detail=""
    local cmd="esxcli network ip connection list | grep ntpd 입력 후 ntp 목록 확인"
    local cur_state=""
    local remediation="[CLI] ￭ NTP 활성화 vi 편집기를 이용하여 /etc/ntp.conf 파일에서 server time.bora.net(ntp 서버) 설정 # vi /etc/ntp.conf 2. NTP 데몬 시작 # /etc/init.d/ntpd start [vClient] ￭ NTP 활성화 vClient 실행 → 호스트 → 관리 → 서비스 → ntpd 활성화"

    local output
    output=$({
        ( get_process_snapshot "ntpd" )
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
            status="양호"
            detail="NTP 시간 동기화 설정이 적용된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="NTP 시간 동기화 설정이 적용되지 않은 경우"
        else
            status="취약"
            detail="NTP 시간 동기화 설정이 적용되지 않은 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-18" "보안 관리" "NTP 시간 동기화 설정" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-19: SSL 시간 초과 구성 설정 확인
check_CSAP_ESXi_19() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/vmware/rhttpproxy/config.xml"
    local cur_state=""
    local remediation="￭ SSL 시간 초과 설정 방법 (ESXi 6.5 이상) vi 편집기를 이용하여 /etc/vmvare/rhttpproxy/config.xml파일에서 readTimeoutMS, handShakeTimeoutMS 설정 <vmacore> ... <handshakeTimeoutMs>20000</handshakeTimeoutMs> ... </ssl> ... </vmacore> 2. hostd 재시작 # /etc/init.d/hostd restart"

    local output
    output=$({
        ( cat /etc/vmware/rhttpproxy/config.xml )
    } 2>/dev/null | sed '/^$/d' | head -20)
    cur_state="$output"

    if [ -z "$output" ]; then
        status="양호"
        detail="SSL 유휴 연결에 대해 시간 초과 기간을"
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
            detail="SSL 유휴 연결에 대해 시간 초과 기간을"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="SSL 유휴 연결에 대해 시간 초과 기간을"
        else
            status="취약"
            detail="SSL 유휴 연결에 대해 시간 초과 기간을"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-19" "보안 관리" "SSL 시간 초과 구성 설정 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-20: 이미지 프로필 및 VIB 승인 레벨 확인
check_CSAP_ESXi_20() {
    local status="양호"
    local detail=""
    local cmd="esxcli software acceptance get 입력 후 승인 레벨 확인"
    local cur_state=""
    local remediation="[CLI] ￭ 승인 레벨 변경 # esxcli software acceptance set --level PartnerSupported 입력 [vClient] ￭ 승인레벨변경 vClient 실행 → 호스트 → 관리 → 보안 및 사용자 → 수락 수준 설정 → Edit에서 변경"

    local output
    output=$({
        ( esxcli software acceptance get )
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
            status="양호"
            detail="VIB 승인 레벨이 Partner Supported"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="VIB 승인 레벨이 Community"
        else
            status="취약"
            detail="VIB 승인 레벨이 Community"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-20" "보안 관리" "이미지 프로필 및 VIB 승인 레벨 확인" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-22: 불필요한 서비스 제거
check_CSAP_ESXi_22() {
    local status="양호"
    local detail=""
    local cmd="esxcli network ip connection list"
    local cur_state=""
    local remediation="￭ 서비스 사용 여부 확인 후 비활성화 또는 최신 보안 패치 1. 서비스가 필요한 경우 최신 보안 패치 적용 버전 설치 2. 서비스가 필요하지 않은 경우 vClient 실행 → 호스트 → 관리 → 서비스 → 속성에서 필요한 서비스 확인 후 중지"

    local output
    output=$({
        ( esxcli network ip connection list )
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
            status="양호"
            detail="불필요한 서비스가 비활성화되어 있는 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="불필요한 서비스가 활성화되어 있는 경우"
        else
            status="취약"
            detail="불필요한 서비스가 활성화되어 있는 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "CSAP-ESXi-22" "보안 관리" "불필요한 서비스 제거" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-23: 최신 보안패치 및 밴더 권고사항
check_CSAP_ESXi_23() {
    local status="양호"
    local detail=""
    local cmd="esxcli system version get"
    local cur_state=""
    local remediation="￭ 설정 기준 권고 (또는 정책 기준) 1. 보안 취약점이 발표되면 시스템 영향도를 평가하고, 긴급 대응책 및 중장기 대응책을 마련하여 계획과 허가에 의해 대응하는 것이 좋다. 2. 패치를 수행할 시 시스템의 영향도에 따라 패치를 차등 수행하도록 한다. 3. 시스템 운영에 영향을 주지 않는 범위 내에서 주기적으로 패치를 수행할 것을 권고함 ※ 최신 버전을 사용하도록 권고하고 있으나, 시스템 운영상 적용이 어려운 경우 알려진 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$({
        ( esxcli system version get )
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

    add_result "CSAP-ESXi-23" "패치 및 로그 관리" "최신 보안패치 및 밴더 권고사항" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CSAP-ESXi-24: 로그의 정기적 검토 및 보고
check_CSAP_ESXi_24() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 로그 파일에는 해킹의 흔적들이 남겨져 있을 수 있으므로, 다음과 같이 로그 파일의 백업에 대한 검토 필요 1. 반복적인 로그인 실패에 관한 로그 2. 로그인 거부 메시지에 관한 로그 3. ESXi의 로그 파일은 주로 /var/log 디렉터리에 위치"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그 기록의 검토, 분석, 리포트 작성 및 보고"
    cur_state="수동점검 필요"

    add_result "CSAP-ESXi-24" "패치 및 로그 관리" "로그의 정기적 검토 및 보고" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-01: 계정 로그오프/세션 관리
check_ISMS_HV_01() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="600초(10분) 동안 입력이 없을 경우 접속된 클라이언트 세션을 끊도록 설정 [상세 조치 사례] l VMware ESXi, vCenter [웹 콘솔 Session Timeout 설정] Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 고급 설정으로 이동 Step 3) UserVars.HostClientSessionTimeout 설정이 600초(10분)로 설정되어 있는지 확인 [ 웹 콘솔 Session Timeout 설정 확인 ] 11. 가상화 장비 Step 4) 600초(10분) 이하로 설정되어 있지 않은 경우 [옵션 편집]을 클릭하여 아래와 같이 수정 [ 옵션 값 수정 ]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 웹 콘솔 및 사용자 Shell Session Timeout 설정이 600초(10분) 이하로 설정된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-01" "가상화 장비 > 1. 계정 관리" "계정 로그오프/세션 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-02: 가상화 장비 외부접속 차단
check_ISMS_HV_02() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="호스트에서 제공하는 방화벽 애플리케이션을 이용하여 서비스 접속 허용 IP 등록 설정 [상세 조치 사례] l VMware ESXi, vCenter [웹 콘솔 접속 IP 제한 설정] Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 네트워킹 > 방화벽 규칙으로 이동 Step 3) [ESXi] SSH 서버 \"허용된 IP주소\" 확인 Step 4) [vSphere] 웹 클라이언트 \"허용된 IP주소\" 확인 [ 허용된 IP주소 확인 ] Step 5) IP 제한 설정이 적용되어 있지 않은 경우 vSphere Web Client(SSH 서버) > 설정 편집 > 다음 네트워크의 연결만 허용 선택 Step 6) 접속 허용 IP 입력 [ 접속 허용 IP 입력 ]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 허용된 IP에서만 관리 콘솔 및 원격 접속이 가능하도록 제한된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-02" "가상화 장비 > 1. 계정 관리" "가상화 장비 외부접속 차단" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-03: 가상화 장비 루트계정 관리
check_ISMS_HV_03() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="별도의 계정을 생성하여 관리자 권한을 부여하고 루트 계정의 권한은 제거하거나 비활성화 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 작업 > 사용 권한으로 이동 Step 3) root 계정의 관리자 권한이 제거되고 별도의 관리자 권한이 존재하는지 확인 [ 별도의 관리자 권한 확인 ] 11. 가상화 장비 Step 4) root 계정 이외에 관리자 권한이 부여된 계정이 없는 경우 별도의 계정 생성 호스트 > 관리 > 보안 및 사용자 > 사용자 추가 [ 별도의 계정 생성 ] Step 5) 별도로 생성한 계정에 관리자 권한 부여 호스트 > 작업 > 사용 권한 > 사용자 추가 [ 계정 관리자 권한 부여 ] Step 6) root 계정의 관리자 권한 제거 [ root 계정 관리자 권한 제거 ] 798"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 별도의 관리자 계정을 생성하여 가상화 장비가 관리된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-03" "가상화 장비 > 1. 계정 관리" "가상화 장비 루트계정 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-04: 가상화 장비 계정 권한 관리
check_ISMS_HV_04() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 공용 계정 및 퇴사자 계정 제거 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 보안 및 사용자 > 사용자로 이동 [ 등록된 계정 확인 ] 11. 가상화 장비 Step 3) 불필요한 계정이 존재하는 경우 해당 계정 삭제 [ 불필요한 계정 제거 ]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 공용 계정 및 퇴사자 계정이 존재하지 않은 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-04" "가상화 장비 > 1. 계정 관리" "가상화 장비 계정 권한 관리" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-05: 가상화 장비 사용자 인증 강화
check_ISMS_HV_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 권한이 부여된 계정에 대한 권한 제거 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 작업 > 사용 권한으로 이동 Step 3) 등록된 계정별 사용 권한 확인 [ 등록된 계정별 사용 권한 확인 ] 11. 가상화 장비 Step 4) 불필요한 권한이 부여되어 있는 경우 해당 계정 선택 Step 5) 역할에 맞는 권한으로 변경 [ 계정 권한 변경 ]"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 계정별 불필요한 권한이 부여되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-05" "가상화 장비 > 1. 계정 관리" "가상화 장비 사용자 인증 강화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-06: 비밀번호 관리정책 설정
check_ISMS_HV_06() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="로그인 계정 비밀번호를 관리 정책에 맞게 설정 [상세 조치 사례] l VMware ESXi Step 1) WEB 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트> 관리 > 시스템 > 고급 설정으로 이동 Step 3) Security.PasswordQualityControl 설정값 확인 [ Security.PasswordQualityControl 설정값 확인 ] 11. 가상화 장비 Step 4) min = N0, N1, N2, N3, N4 중 N3, N4의 값이 8 미만일 경우 [옵션 편집]을 클릭하여 아래와 같이 수정 [ 옵션 값 수정 ] Step 5) Security.PasswordMaxDays 설정값 확인 [ 최대 암호 수명 값 확인 ] Step 6) 90일 이하로 설정되어 있지 않은 경우 [옵션 편집]을 클릭하여 아래와 같이 수정 [ 최대 암호 수명 값 90 설정 ] ※ (예시) retry = M min = N0, N1, N2, N3, N4 § M : 암호 변경 시, 조건을 불만족하는 암호 입력 시 다시 암호를 되묻는 횟수 § N0 : 문자 종류(대문자, 소문자, 숫자, 특수문자) 중 한 가지만 사용해 구성된 암호에 허용되는 최소 암호 글자 수 § N1 : 문자 종류(대문자, 소문자, 숫자, 특수문자) 중 두 가지를 사용해 구성된 암호에 허용되는 최소 비밀번호 길이 § N2 : 암호 문구 사용 시, 허용되는 최소 비밀번호 길이 § N3 : 문자 종류(대문자, 소문자, 숫자, 특수문자) 중 세 가지를 사용해 구성된 암호에 허용되는 최소 비밀번호 길이 § N4 : 문자 종류(대문자, 소문자, 숫자, 특수문자) 중 네 가지를 사용해 구성된 암호에 허용되는 최소 비밀번호 길이 disabled : 길이에 관계 없이 해당 종류의 암호를 사용하지 않음 암호의 첫 문자로 사용되는 대문자와 마지막 문자로 사용되는 숫자는 문자 종류의 수로 포함되지 않음 l VMware vCenter Step 1) vSphere Client 접속 후, 다음 메뉴에 접근하여 확인(vSphere Client 버전에 따라, 메뉴 명칭은 달라질 수 있음) Step 2) (vCenter6.5) \"관리\" > \"Single Sign On\" > \"구성\" > \"Policies\" > \"암호 정책\" > 비밀번호 정책 확인 Step 3) (vCenter8) \"관리\" > \"Single Sign On\" > \"구성\" > \"로컬 계정\" > \"암호 정책\" > 비밀번호 정책 확인 Step 4) 비밀번호 정책 설정 적용"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그인 계정 비밀번호 관리 정책이 적용된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-06" "가상화 장비 > 1. 계정 관리" "비밀번호 관리정책 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-08: 시스템 사용 주의사항 출력 설정
check_ISMS_HV_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="시스템 사용 주의사항 출력 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 고급 설정으로 이동 Step 3) Annotaions.WelcomeMessage 설정 값 확인 [ 시스템 사용 주의사항 출력 값 확인 ] Step 4) 시스템 사용 주의사항 문구가 설정되어 있지 않은 경우 [옵션 편집]을 클릭하여 문구 입력 11. 가상화 장비 - 다음의 파일들에 메시지 설정 존재 여부 확인 1. /etc/motd 에 시스템 사용 주의사항 설정 2. /etc/issue 파일에 로그인 경고 메시지 설정 3. /etc/ssh/sshd_config 배너 값 설정 l VMware vCenter Step 1) vSphere Client 접속 후, 다음 메뉴에 접근하여 확인(vSphere Client 버전에 따라, 메뉴 명칭은 달라질 수 있음) (vCenter6.5) \"관리\" > \"Single Sign On\" > \"구성\" > \"로그인 배너\" > 로그인 배너 설정 여부를 확인 (vCenter8) \"관리\" > \"Single Sign On\" > \"구성\" > \"로그인 메시지\" > 로그인 배너 설정 여부를 확인 l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 시간 및 날짜로 이동 Step 3) NTP 설정 확인 [ NTP 설정 확인 ] 11. 가상화 장비 Step 4) NTP 서버가 설정되어 있지 않은 경우, [NTP 설정 편집]을 클릭하여 NTP 서버 정보 입력 [ NTP 클라이언트 사용 설정 ] l VMware vCenter Step 1) vCenter Server 관리 페이지(https://<주소>:5480/) 접속 후, 다음 메뉴에 접근하여 확인(vCenter 버전에 따 라, 메뉴 명칭은 달라질 수 있음) # \"시간\" > \"시간 동기화\" > NTP 설정 여부를 확인"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 시스템 사용 주의사항이 출력된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-08" "가상화 장비 > 2. 시스템 서비스 관리" "시스템 사용 주의사항 출력 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-14: 원격 로그 서버 이용
check_ISMS_HV_14() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="원격 로그 서버 또는 스토리지 연동 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 고급 설정으로 이동 Step 3) Syslog.global.logHost 설정값 확인 [ Syslog.global.logHost 설정 값 확인 ] Step 4) [옵션 편집]을 클릭한 후 아래와 같은 양식으로 원격 로그 서버 또는 스토리지 입력 protocol://hostname|ipv4|'['ipv6']'[:port] [ Syslog.global.logHost 설정 ] ※ syslog 설정 예시 예시 설명 tcp://10.0.1.10:3555 TCP 및 Port 3555를 사용하여 Syslog 메시지를 10.0.1.10으로 전송 tcp://[2001:db8:85a3:8d 3:1319:8a2e:370:7348] TCP 및 Port 1514를 사용하여 Syslog 메시지를 IPv6 주소로 전송 udp://10.0.1.10 UDP 및 Port 514를 사용하여 Syslog 메시지를 10.0.1.10으로 전송 ssl://syslog.com SSL(TLS) 및 Port 514를 사용하여 Syslog 메시지를 syslog.com으로 전송 11. 가상화 장비 l VMware vCenter Step 1) Syslog 설정 여부를 확인 Step 2) vCenter Server 관리 페이지(https://<주소>:5480/) 접속 후, 다음 메뉴에 접근하여 확인(vCenter 버전에 따라, 메뉴 명칭은 달라질 수 있음) # \"Syslog\" > Syslog 설정 여부를 확인"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 원격 로그 서버 또는 스토리지가 연동 설정된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-14" "가상화 장비 > 2. 시스템 서비스 관리" "원격 로그 서버 이용" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-15: 시스템 주요 이벤트 로그 설정
check_ISMS_HV_15() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="로그 기록 정책을 내부 정책에 부합하게 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 고급 설정으로 이동 Step 3) Config.HostAgent.log.level 설정값 확인 [ Config.HostAgent.log.level 설정값 확인 ] Step 4) 로그 기록 정책 확인 후, [옵션 편집]을 클릭해 내부 정책에 맞게 설정 [ Config.HostAgent.log.level 설정 적용 ] ※ log.level 설정값 로깅 수준 설명 None 로그 기록하지 않음 Quiet 최소한의 로그 항목을 기록함 Panic 패닉 로그(장애 발생 시 기록되는 메시지) 항목만 기록함 Error 패닉 및 에러 로그 항목만 기록함 Warning 패닉, 에러 및 경고 로그 항목만 기록함 Information 패닉, 에러, 경고 및 정보 로그 항목을 기록함 Verbose 패닉, 에러, 경고, 정보 및 세부 정보를 표시하는 로그 항목을 기록함 Trivia 패닉, 에러, 경고, 정보, 세부 정보 표시 및 기타 정보를 표시하는 로그 항목을 기록함 l VMware vCenter Step 1) 로그 설정 레벨 확인 Step 2) vSphere Client 접속 후, 다음 메뉴에 접근하여 확인(vSphere Client 버전에 따라, 메뉴 명칭은 달라질 수 있음) # (vCenter6.5) \"호스트 및 클러스터\" > [vCenter 서버] > \"구성\" > \"설정\" > \"고급 설정\" > \"config.log.level\" 확인 # (vCenter8) \"호스트 및 클러스터\" > [vCenter 서버] > \"구성\" > \"설정\" > \"고급 설정\" > \"config.log.level\" 확인 11. 가상화 장비 835"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그 기록 정책이 내부 정책에 부합하게 설정된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-15" "가상화 장비 > 2. 시스템 서비스 관리" "시스템 주요 이벤트 로그 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-16: 비휘발성 경로 내 로그 파일 저장
check_ISMS_HV_16() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="로그 파일 경로를 비휘발성 로그 파일 경로로 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 호스트 > 관리 > 시스템 > 고급 설정으로 이동 Step 3) Syslog.global.LogDir 설정값 확인 [ Syslog.global.LogDir 설정값 확인 ] Step 4) 로그 파일 저장 경로 확인 후, [옵션 편집]을 클릭하여 수정 11. 가상화 장비 837"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그 파일 경로가 존재하며, 해당 경로가 비휘발성 경로에 저장된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-16" "가상화 장비 > 2. 시스템 서비스 관리" "비휘발성 경로 내 로그 파일 저장" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-17: 코어덤프 수집 기능 활성화
check_ISMS_HV_17() {
    local status="양호"
    local detail=""
    local cmd="esxcli system coredump network get; esxcli system coredump network check"
    local cur_state=""
    local remediation="코어 덤프 수집 기능 활성화 적용 [상세 조치 사례] l VMware ESXi Step 1) SSH를 통해 ESXi 호스트 서버 접속 후, 다음 명령어 실행 \$ esxcli system coredump network get Step 2) 다음 명령어를 사용해 VMkernel 네트워크 인터페이스와 원격 네트워크 코어 덤프 서버의 IP주소 및 UDP Port 번호 지정 \$ esxcli system coredump network set --interface-name <VMkernel 인터페이스명> --server-ipv4 <IP주소> --server-port <Port 번호> 예시) esxcli system coredump network set --interface-name vmk0 --server-ipv4 10.0.1.10 --server-port Step 3) 다음 명령어를 사용해 네트워크 코어 덤프 구성 활성화 \$ esxcli system coredump network set --enable true Step 4) 코어 덤프 수집 기능 활성화 여부 확인 \$ esxcli system coredump network check 838"

    local output
    output=$({
        ( esxcli system coredump network get )
        ( esxcli system coredump network check )
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
            status="양호"
            detail="코어 덤프 수집 기능이 활성화(true)된 경우"
        elif output_has_positive_marker "$output"; then
            status="취약"
            detail="코어 덤프 수집 기능이 비활성화(false)된 경우"
        else
            status="취약"
            detail="코어 덤프 수집 기능이 비활성화(false)된 경우"
        fi
        fi
    fi
    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"

    add_result "ISMS-HV-17" "가상화 장비 > 3. 가상머신 관리" "코어덤프 수집 기능 활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-18: 가상머신의 장치 변경 제한 설정
check_ISMS_HV_18() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="가상 머신의 장치 설정 변경 방지 활성화 적용 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 가상 시스템 > [가상 머신 선택] > 설정 편집 > VM 옵션 > 고급 > 구성 매개 변수로 이동 Step 3) isolation.device.edit.disable, isolation.device.connectable.disable 설정값 확인 11. 가상화 장비 Step 4) 매개 변수 값을 각각 TRUE로 설정. 또는, 각 매개 변수가 존재하지 않을 시, 해당 매개 변수 추가 및 값을 TRUE로 설정 [ 가상 머신의 장치 설정 변경 방지 설정 적용 ] 840"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 가상 머신의 장치 설정 변경 방지 설정이 활성화(true)된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-18" "가상화 장비 > 3. 가상머신 관리" "가상머신의 장치 변경 제한 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-19: 가상 머신의 불필요한 장치 제거
check_ISMS_HV_19() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 장치 연결 해제 적용 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 https://<VMware ESXi IP> Step 2) 가상 시스템 > [가상 머신 선택] > 설정 편집 > 가상 하드웨어로 이동 Step 3) 장치 연결상태 확인 및 불필요한 외부 장치 비활성화 [ 장치 연결상태 확인 ] 11. 가상화 장비 841"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 장치가 가상 머신에 연결되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-19" "가상화 장비 > 3. 가상머신 관리" "가상 머신의 불필요한 장치 제거" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-20: 가상머신 콘솔 클립보드 복사&붙여넣기 기능 비활성화
check_ISMS_HV_20() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="가상 머신 콘솔 복사 제한 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 가상 시스템 > [가상 머신 선택] > 설정 편집 > VM 옵션 > 고급 > 구성 매개 변수로 이동 Step 3) isolation.tools.copy.disable, isolation.tools.paste.disable 및 isolation.tools.setGUIOptions.enable 설정값 확인 Step 4) isolation.tools.copy.disable와 isolation.tools.paste.disable 각 변수 값을 TRUE로, isolation.tools.setGUIOptions.enable 변수 값을 FALSE로 설정 또는, 각 매개 변수가 존재하지 않을 시, 해당 매개 변수 추가 및 값 설정 11. 가상화 장비 [ 가상 머신 콘솔 복사 기능 활성화 여부 확인 ] 844"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 가상 머신 콘솔 복사 기능이 비활성화 되어 있거나, 복사 제한이 설정된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-20" "가상화 장비 > 3. 가상머신 관리" "가상머신 콘솔 클립보드 복사&붙여넣기 기능 비활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# ISMS-HV-21: 가상머신 콘솔 드래그 앤 드롭 기능 비활성화
check_ISMS_HV_21() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="가상 머신 콘솔 드래그 앤 드롭 제한 설정 [상세 조치 사례] l VMware ESXi Step 1) Web 콘솔 페이지 접속 > https://<VMware ESXi IP> Step 2) 가상 시스템 > [가상 머신 선택] > 설정 편집 > VM 옵션 > 고급 > 구성 매개 변수로 이동 Step 3) isolation.tools.dnd.disable 설정값 확인 Step 4) 매개 변수 값을 TRUE로 설정. 또는, 각 매개 변수가 존재하지 않을 시, 해당 매개 변수 추가 및 값을 TRUE로 설정 [ 가상 머신 콘솔 드래그 앤 드롭 기능 활성화 여부 확인 ] 11. 가상화 장비 845"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 가상 머신 콘솔 드래그 앤 드롭 기능이 비활성화되어 있거나, 제한 설정된 경우"
    cur_state="수동점검 필요"

    add_result "ISMS-HV-21" "가상화 장비 > 3. 가상 머신 관리" "가상머신 콘솔 드래그 앤 드롭 기능 비활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== ESXi CCE 취약점 진단 시작 ====="
echo "호스트: ${HOST_TAG:-unknown}"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/39] %s 점검 중...                " "$total" "$1"
}


progress "CSAP-ESXi-03"; check_CSAP_ESXi_03
progress "CSAP-ESXi-05"; check_CSAP_ESXi_05
progress "CSAP-ESXi-06"; check_CSAP_ESXi_06
progress "CSAP-ESXi-08"; check_CSAP_ESXi_08
progress "CSAP-ESXi-09"; check_CSAP_ESXi_09
progress "CSAP-ESXi-10"; check_CSAP_ESXi_10
progress "CSAP-ESXi-13"; check_CSAP_ESXi_13
progress "CSAP-ESXi-21"; check_CSAP_ESXi_21
progress "CSAP-ESXi-01"; check_CSAP_ESXi_01
progress "CSAP-ESXi-02"; check_CSAP_ESXi_02
progress "CSAP-ESXi-04"; check_CSAP_ESXi_04
progress "CSAP-ESXi-07"; check_CSAP_ESXi_07
progress "CSAP-ESXi-11"; check_CSAP_ESXi_11
progress "CSAP-ESXi-12"; check_CSAP_ESXi_12
progress "CSAP-ESXi-14"; check_CSAP_ESXi_14
progress "CSAP-ESXi-15"; check_CSAP_ESXi_15
progress "CSAP-ESXi-16"; check_CSAP_ESXi_16
progress "CSAP-ESXi-17"; check_CSAP_ESXi_17
progress "CSAP-ESXi-18"; check_CSAP_ESXi_18
progress "CSAP-ESXi-19"; check_CSAP_ESXi_19
progress "CSAP-ESXi-20"; check_CSAP_ESXi_20
progress "CSAP-ESXi-22"; check_CSAP_ESXi_22
progress "CSAP-ESXi-23"; check_CSAP_ESXi_23
progress "CSAP-ESXi-24"; check_CSAP_ESXi_24
progress "ISMS-HV-01"; check_ISMS_HV_01
progress "ISMS-HV-02"; check_ISMS_HV_02
progress "ISMS-HV-03"; check_ISMS_HV_03
progress "ISMS-HV-04"; check_ISMS_HV_04
progress "ISMS-HV-05"; check_ISMS_HV_05
progress "ISMS-HV-06"; check_ISMS_HV_06
progress "ISMS-HV-08"; check_ISMS_HV_08
progress "ISMS-HV-14"; check_ISMS_HV_14
progress "ISMS-HV-15"; check_ISMS_HV_15
progress "ISMS-HV-16"; check_ISMS_HV_16
progress "ISMS-HV-17"; check_ISMS_HV_17
progress "ISMS-HV-18"; check_ISMS_HV_18
progress "ISMS-HV-19"; check_ISMS_HV_19
progress "ISMS-HV-20"; check_ISMS_HV_20
progress "ISMS-HV-21"; check_ISMS_HV_21

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
    echo '    "platform": "ESXi",'
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

echo "===== ESXi CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
