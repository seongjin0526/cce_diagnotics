#!/bin/bash
###############################################################################
# Tomcat CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash tomcat_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_tomcat_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Tomcat helper ---
CATALINA_HOME="${CATALINA_HOME:-}"
if [ -z "$CATALINA_HOME" ]; then
    for d in /usr/share/tomcat* /opt/tomcat* /var/lib/tomcat* /usr/local/tomcat*; do
        if [ -d "$d" ]; then
            CATALINA_HOME="$d"
            break
        fi
    done
fi

get_tomcat_conf() {
    local file="$1"
    echo "${CATALINA_HOME}/conf/${file}"
}


# CLD-Tomcat-01 / WEB-01: default 관리자 계정명
check_CLD_Tomcat_01() {
    local status="양호"
    local detail=""
    local cmd="cat /tomcat-users.xml | grep <user username=; cat /tomcat-users.xml | grep roles=; vi /conf/server.xml"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ default 계정명 변경 \(admin tomcat 등\) 1\) # vi [Tomcat 설치 디렉터리]/tomcat-users.xml 2\) default 계정명 변경 또는 3\) 해당 계정 주석 처리 ￭ 관리자 페이지 비활성화 1\) # [Tomcat 설치 디렉터리]/tomcat-users.xml 또는 2\) 관리자 계정 주석 처리 ※ 관리자 페이지는 default로 비활성화되어 있음\(주석 처리\) [주요기반시설 가이드] 기본 관리자 계정명을 추측하기 어려운 계정명으로 설정 [상세 조치 사례] l Tomcat Step 1\) 기본 계정명 변경 또는 관리자 페이지 비활성화\(기본값: 비활성화\) # vi <Tomcat 설치 디렉터리>/conf/server.xml 예시\) <user username=\"admin\" password=\"XNDJxndn264\!@\" roles=\"manager-gui\"/> Step 2\) Tomcat 재구동 # systemctl restart tomcat ※ \"roles = manager-gui, manager-script, manager-jmx, manager-status\" 설정 시 관리자 계정 및 페이지 활성화 상태 03. 웹 서비스 275"

    local config_file="/tomcat-users.xml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "roles=" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: roles= 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Tomcat-01 / WEB-01" "패치 및 로그 관리" "default 관리자 계정명" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-02 / WEB-02: 취약한 패스워드 사용 제한
check_CLD_Tomcat_02() {
    local status="양호"
    local detail=""
    local cmd="/tomcat-users.xml | grep <user username=; vi /conf/server.xml; systemctl restart tomcat"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 패스워드 변경 1\) 패스워드 복잡도를 만족하도록 설정 # vi [Tomcat 설치 디렉터리]/tomcat-users.xml ※ 패스워드 복잡도 : 영문\(대문자, 소문자\), 숫자, 특수문자 조합 중 3가지 8자리 이상, 2가지 조합 10자리 이상 [주요기반시설 가이드] 복잡도 기준에 맞는 추측하기 어려운 비밀번호 설정 [상세 조치 사례] l Tomcat Step 1\) 복잡도를 만족하는 비밀번호 설정 # vi <Tomcat 설치 디렉터리>/conf/server.xml <user username=\"admin\" password=\"XNDJxndn264\!@\" roles=\"manager-gui\"/> Step 2\) Tomcat 재시작 # systemctl restart tomcat"

    local config_file="/tomcat-users.xml"
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

    add_result "CLD-Tomcat-02 / WEB-02" "계정 관리" "취약한 패스워드 사용 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-03 / WEB-03: 패스워드 파일 권한 관리
check_CLD_Tomcat_03() {
    local status="양호"
    local detail=""
    local cmd="ls -l; chmod 600 //tomcat-users.xml"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 패스워드 파일 권한 변경 1\) # chmod 600 [Tomcat 설치 디렉터리]/tomcat-users.xml ※ 설정 파일 권한 변경 시, 시스템 영향도를 파악하여 충분한 테스트를 진행 한 후에 접근권한 수정 [주요기반시설 가이드] 비밀번호 파일 권한 600 이하로 설정 [상세 조치 사례] l Tomcat Step 1\) tomcat-users.xml 파일 권한 변경 # chmod 600 /<Tomcat 설치 디렉터리>/tomcat-users.xml"

    local vuln_found=false
    if [ -e "//tomcat-users.xml" ]; then
        local result_tomcat_users_xml
        result_tomcat_users_xml=$(check_file_owner_perm "//tomcat-users.xml" "root" "600")
        cur_state+="//tomcat-users.xml: $result_tomcat_users_xml; "
        case "$result_tomcat_users_xml" in
            VULN*) vuln_found=true; detail+="//tomcat-users.xml 소유자/권한 부적절($result_tomcat_users_xml). " ;;
            GOOD*) detail+="//tomcat-users.xml 소유자/권한 적절($result_tomcat_users_xml). " ;;
            NOT_FOUND) detail+="//tomcat-users.xml 파일 없음. " ;;
        esac
    else
        detail+="//tomcat-users.xml 파일 없음. "
        cur_state+="//tomcat-users.xml: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="비밀번호 파일에 권한이 600 이하로 설정된 경우" && cur_state="점검 대상 파일 없음"

    add_result "CLD-Tomcat-03 / WEB-03" "보안 설정" "패스워드 파일 권한 관리" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-06 / WEB-04: 디렉터리 리스팅 설정 제한
check_CLD_Tomcat_06() {
    local status="양호"
    local detail=""
    local cmd="/web.xml; vi //web.xml"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 디렉터리 리스팅 비활성화 1\) # vi [Tomcat 설치 디렉터리]/web.xml [주요기반시설 가이드] 디렉터리 리스팅 기능 차단 설정 [상세 조치 사례] l Tomcat Step 1\) web.xml 파일 내 listings 옵션 비활성화 # vi /<Tomcat 설치 디렉터리>/web.xml <init-param> <param-name>listings</param-name> <param-value>false</param-value> </init-param>"

    local output
    output=$(/web.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Tomcat-06 / WEB-04" "보안 설정" "디렉터리 리스팅 설정 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-07 / WEB-22: 에러 메시지 관리
check_CLD_Tomcat_07() {
    local status="양호"
    local detail=""
    local cmd="cat /web.xml; vi //conf/web.xml; systemctl restart tomcat"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 에러 코드 설정 파일 수정 1\) 필수 에러 코드\(400,401,403,404,500\)에 대한 에러 내용을 알 수 없도록 일원화된 에러 페이지로 관리 ※ 에러가 발생 시, 일원화된 에러 페이지가 표시되도록 하는 방식이 아닌 로그인 페이지로 리다이렉션되는 방식 또한 양호로 처리함 [주요기반시설 가이드] 필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정 [상세 조치 사례] l Tomcat Step 1\) web.xml 파일 내 에러 코드별 에러 페이지 설정 정보 확인 후 별도의 일원화된 에러 페이지 설정 # vi /[Tomcat 설치 디렉터리]/conf/web.xml <error-page> <error-code>404</error-code> <location>/error/404.html</location> \(이하 생략\) </error-page> Step 2\) Tomcat 재구동 # systemctl restart tomcat"

    local svc_status
    svc_status=$(is_service_active "tomcat")
    cur_state="tomcat=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="tomcat 서비스 활성화 상태. "
    else
        detail="tomcat 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "CLD-Tomcat-07 / WEB-22" "보안 설정" "에러 메시지 관리" "하" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-04: 홈 디렉터리 쓰기 권한 관리
check_CLD_Tomcat_04() {
    local status="양호"
    local detail=""
    local cmd="cat /server.xml | grep appBase; ls -al"
    local cur_state=""
    local remediation="￭ 홈 디렉터리 접근 권한 변경 \(예시\) 1\) # chmod 755 [Tomcat 설치 디렉터리]/webapps ※ 설정 파일 권한 변경 시, 시스템 영향도를 파악하여 충분한 테스트를 진행한 후에 접근권한 수정"

    local config_file="/server.xml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "appBase" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: appBase 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Tomcat-04" "보안 설정" "홈 디렉터리 쓰기 권한 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-05: 환경 설정 파일 권한 관리
check_CLD_Tomcat_05() {
    local status="양호"
    local detail=""
    local cmd="ls -al; cat /server.xml | grep appBase"
    local cur_state=""
    local remediation="￭ 파일 권한 변경 1\) 설정 파일 권한 변경 # chmod 600 [해당 파일] 2\) 소스 파일 권한 변경 # chmod 644 [해당 파일]"

    local config_file="/server.xml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "appBase" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: appBase 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Tomcat-05" "보안 설정" "환경 설정 파일 권한 관리" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-08: 로그 파일 관리 및 주기적 백업
check_CLD_Tomcat_08() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="￭ 로그 파일 관리 및 주기적 백업 1\) 백업 정책 수립 2\) 정책에 따라 로그를 기록하고 주기적으로 백업"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 로그 파일을 관리하고 있으며 주기적으로"
    cur_state="수동점검 필요"

    add_result "CLD-Tomcat-08" "패치 및 로그 관리" "로그 파일 관리 및 주기적 백업" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# CLD-Tomcat-09: 최신 보안 패치 적용
check_CLD_Tomcat_09() {
    local status="양호"
    local detail=""
    local cmd="/bin/version.sh; rpm -qa | grep webapps"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 취약점이 없는 보안 패치가 적용된 버전으로 업데이트해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(/bin/version.sh 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Tomcat-09" "패치 및 로그 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# WEB-05: 지정하지 않은 CGI/ISAPI 실행 제한
check_WEB_05() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정 [상세 조치 사례] l Tomcat Step 1\) web.xml 파일 내 CGI 매핑 비활성화 <\!-- <servlet-mapping> <servlet-name>cgi</servlet-name> <url-pattern>/cgi-bin/*</url-pattern> </servlet-mapping> --> Step 2\) Tomcat 재시작"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
    cur_state="수동점검 필요"

    add_result "WEB-05" "웹 서비스 > 2. 서비스 관리" "지정하지 않은 CGI/ISAPI 실행 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-06: 웹 서비스 상위 디렉터리 접근 제한 설정
check_WEB_06() {
    local status="양호"
    local detail=""
    local cmd="vi //conf/server.xml"
    local cur_state=""
    local remediation="상위 디렉터리 접근 기능 제거 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 Context 요소에서 allowLinking 옵션 확인 # vi /<Tomcat 설치 디렉터리>/conf/server.xml <Context allowLinking=\"true\"> <WatchedResource>WEB-INF/web.xml</WatchedResource> <WatchedResource>WEB-INF/tomcat-web.xml</WatchedResource> <WatchedResource>\${catalina.base}/conf/web.xml</WatchedResource> </Context> Step 2\) server.xml 파일 내 Context 요소에서 allowLinking 옵션 제거 #vi /<Tomcat 설치 디렉터리>/conf/server.xml <Context> <WatchedResource>WEB-INF/web.xml</WatchedResource> <WatchedResource>WEB-INF/tomcat-web.xml</WatchedResource> <WatchedResource>\${catalina.base}/conf/web.xml</WatchedResource> </Context>"

    local output
    output=$(vi //conf/server.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "WEB-06" "웹 서비스 > 2. 서비스 관리" "웹 서비스 상위 디렉터리 접근 제한 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-07: 웹 서비스 경로 내 불필요한 파일 제거
check_WEB_07() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 파일 및 디렉터리를 제거하도록 설정 [상세 조치 사례] l Tomcat Step 1\) rm 명령어로 확인된 불필요한 매뉴얼 디렉터리 및 파일 제거 # rm –rf /<Tomcat 설치 디렉터리>/webapps/docs/<불필요 파일> ※ BUILDING.txt, RELEASE-NOTES.txt, jndi-resources-howto.html 등 매뉴얼 파일 포함 03. 웹 서비스 291"

    status="수동점검"
    detail="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
    cur_state="수동점검 필요"

    add_result "WEB-07" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 내 불필요한 파일 제거" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-08: 웹 서비스 파일 업로드 및 다운로드 용량 제한
check_WEB_08() {
    local status="양호"
    local detail=""
    local cmd="vi //conf/web.lxml"
    local cur_state=""
    local remediation="파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 maxPostSize 요소 설정 #vi /<Tomcat 설치 디렉터리>/conf/server.xml <Connector port=\"<사용 포트>\" protocol=\"HTTP/1.1\" connectionTimeout=\"20000\" redirectPort=\"<사용 포트>\" 03. 웹 서비스 maxParameterCount=\"1000\" maxPostSize=\"5242880\" // maxPostSize=5242880=5MB /> Step 2\) web.xml 파일 내 multipart-config 요소 설정 # vi /<Tomcat 설치 디렉터리>/conf/web.lxml <multipart-config> <max-file-size>2097152</max-file-size> <max-request-size>4194304</max-request-size> <file-size-threshold>0</file-size-threshold> </multipart-config>"

    local output
    output=$(vi //conf/web.lxml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "WEB-08" "웹 서비스 > 2. 서비스 관리" "웹 서비스 파일 업로드 및 다운로드 용량 제한" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-09: 웹 서비스 프로세스 권한 제한
check_WEB_09() {
    local status="양호"
    local detail=""
    local cmd="vi /etc/systemd/system/tomcat.service; chown -R tomcat:tomcat //usr/share/tomcat9/; chown -R tomcat:tomcat //tomcat9/temp"
    local cur_state=""
    local remediation="웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정 [상세 조치 사례] l Tomcat Step 1\) tomcat.service 파일 내 Tomcat 데몬 구동 권한을 관리자 계정이 아닌 별도 계정으로 변경 # vi /etc/systemd/system/tomcat.service [Service] User=tomcat Group=tomcat Step 2\) Tomcat 서비스 파일 소유권 변경 # chown -R tomcat:tomcat /[Tomcat 설치 디렉터리]/usr/share/tomcat9/ # chown -R tomcat:tomcat /[Tomcat 설치 디렉터리]/tomcat9/temp # chown -R tomcat:tomcat / [Tomcat 설치 디렉터리]/logs # chown -R tomcat:tomcat /usr/share/tomcat9/webapps # chown -R tomcat:tomcat /usr/share/tomcat9/work Step 3\) 웹서비스 실행 계정 로그인 제한 설정 # usermod -s /sbin/nologin [사용자명] Step 4\) Tomcat 서비스 재구동 # systemctl restart tomcat"

    local vuln_found=false
    if [ -e "/etc/systemd/system/tomcat.service" ]; then
        local result_etc_systemd_system_tomcat_service
        result_etc_systemd_system_tomcat_service=$(check_file_owner_perm "/etc/systemd/system/tomcat.service" "root" "644")
        cur_state+="/etc/systemd/system/tomcat.service: $result_etc_systemd_system_tomcat_service; "
        case "$result_etc_systemd_system_tomcat_service" in
            VULN*) vuln_found=true; detail+="/etc/systemd/system/tomcat.service 소유자/권한 부적절($result_etc_systemd_system_tomcat_service). " ;;
            GOOD*) detail+="/etc/systemd/system/tomcat.service 소유자/권한 적절($result_etc_systemd_system_tomcat_service). " ;;
            NOT_FOUND) detail+="/etc/systemd/system/tomcat.service 파일 없음. " ;;
        esac
    else
        detail+="/etc/systemd/system/tomcat.service 파일 없음. "
        cur_state+="/etc/systemd/system/tomcat.service: 파일 없음; "
    fi
    if [ -e "//usr/share/tomcat9/" ]; then
        local result_usr_share_tomcat9
        result_usr_share_tomcat9=$(check_file_owner_perm "//usr/share/tomcat9/" "root" "644")
        cur_state+="//usr/share/tomcat9/: $result_usr_share_tomcat9; "
        case "$result_usr_share_tomcat9" in
            VULN*) vuln_found=true; detail+="//usr/share/tomcat9/ 소유자/권한 부적절($result_usr_share_tomcat9). " ;;
            GOOD*) detail+="//usr/share/tomcat9/ 소유자/권한 적절($result_usr_share_tomcat9). " ;;
            NOT_FOUND) detail+="//usr/share/tomcat9/ 파일 없음. " ;;
        esac
    else
        detail+="//usr/share/tomcat9/ 파일 없음. "
        cur_state+="//usr/share/tomcat9/: 파일 없음; "
    fi
    if [ -e "//tomcat9/temp" ]; then
        local result_tomcat9_temp
        result_tomcat9_temp=$(check_file_owner_perm "//tomcat9/temp" "root" "644")
        cur_state+="//tomcat9/temp: $result_tomcat9_temp; "
        case "$result_tomcat9_temp" in
            VULN*) vuln_found=true; detail+="//tomcat9/temp 소유자/권한 부적절($result_tomcat9_temp). " ;;
            GOOD*) detail+="//tomcat9/temp 소유자/권한 적절($result_tomcat9_temp). " ;;
            NOT_FOUND) detail+="//tomcat9/temp 파일 없음. " ;;
        esac
    else
        detail+="//tomcat9/temp 파일 없음. "
        cur_state+="//tomcat9/temp: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="웹 프로세스\(웹 서비스\)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진" && cur_state="점검 대상 파일 없음"

    add_result "WEB-09" "웹 서비스 > 2. 서비스 관리" "웹 서비스 프로세스 권한 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-10: 불필요한 프록시 설정 제한
check_WEB_10() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 Connector 요소에서 불필요한 Proxy 설정 제거 <Connector port=\"8080\" protocol=\"HTTP/1.1\" 03. 웹 서비스 redirectPort=\"8443\" proxyName=\"proxy.example.com\" proxyPort=\"80\" />"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 Proxy 설정을 제한한 경우"
    cur_state="수동점검 필요"

    add_result "WEB-10" "웹 서비스 > 2. 서비스 관리" "불필요한 프록시 설정 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-11: 웹 서비스 경로 설정
check_WEB_11() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정 [상세 조치 사례] l Tomcat Step 1\) web.xml 파일 내 docBase를 별도의 경로로 변경 <Host name=\"localhost\" appBase=\"webapps\" unpackWARs=\"true\" autoDeploy=\"true\"> <Context path=\"\" docBase=\"[별도의 경로]\" /> </Host> 304"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-11" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-12: 웹 서비스 링크 사용 금지
check_WEB_12() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="웹 서비스 링크 사용 제한 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 Context 요소 allowLinking 옵션 설정 <Context allowLiking=\"true\"> <WatchedResource>WEB-INF/web.xml</WatchedResource> <WatchedResource>WEB-INF/tomcat-web.xml</WatchedResource> <WatchedResource>\${catalina.base}/conf/web.xml</WatchedResource> </Context>"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-12" "웹 서비스 > 2. 서비스 관리" "웹 서비스 링크 사용 금지" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-13: 웹 서비스 설정 파일 노출 제한
check_WEB_13() {
    local status="양호"
    local detail=""
    local cmd="chmod 600 //conf/server.xml"
    local cur_state=""
    local remediation="DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결 취약점 제거 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 불필요한 DB 연결 리소스 설정 제거 <GlobalNamingResources> <Resource name=\"jdbc/MyDB\" auth=\"Container\" type=\"javax.sql.DataSource\" maxTotal=\"100\" maxIdle=\"30\" maxWaitMillis=\"10000\" username=\"dbuser\" 03. 웹 서비스 password=\"dbpassword\" driverClassName=\"com.mysql.jdbc.Driver\" url=\"jdbc:mysql://localhost:3306/mydb\"/> </GlobalNamingResources> Step 2\) DB 연결 리소스가 존재하는 설정 파일 접근권한을 600으로 설정 # chmod 600 /[Tomcat 설치 디렉터리]/conf/server.xml"

    local vuln_found=false
    if [ -e "//conf/server.xml" ]; then
        local result_conf_server_xml
        result_conf_server_xml=$(check_file_owner_perm "//conf/server.xml" "root" "644")
        cur_state+="//conf/server.xml: $result_conf_server_xml; "
        case "$result_conf_server_xml" in
            VULN*) vuln_found=true; detail+="//conf/server.xml 소유자/권한 부적절($result_conf_server_xml). " ;;
            GOOD*) detail+="//conf/server.xml 소유자/권한 적절($result_conf_server_xml). " ;;
            NOT_FOUND) detail+="//conf/server.xml 파일 없음. " ;;
        esac
    else
        detail+="//conf/server.xml 파일 없음. "
        cur_state+="//conf/server.xml: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우" && cur_state="점검 대상 파일 없음"

    add_result "WEB-13" "웹 서비스 > 2. 서비스 관리" "웹 서비스 설정 파일 노출 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-14: 웹 서비스 경로 내 파일의 접근 통제
check_WEB_14() {
    local status="양호"
    local detail=""
    local cmd="chown -R : web.xml; chmod -R 750 web.xml"
    local cur_state=""
    local remediation="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정 [상세 조치 사례] l Tomcat Step 1\) 루트 디렉터리 불필요한 권한 삭제 또는 적절한 권한 부여 # chown –R [Tomcat 계정]:[Tomcat 그룹] web.xml # chmod -R 750 web.xml 312"

    local vuln_found=false
    if [ -e "/etc/unknown_config_file" ]; then
        local result_etc_unknown_config_file
        result_etc_unknown_config_file=$(check_file_owner_perm "/etc/unknown_config_file" "root" "644")
        cur_state+="/etc/unknown_config_file: $result_etc_unknown_config_file; "
        case "$result_etc_unknown_config_file" in
            VULN*) vuln_found=true; detail+="/etc/unknown_config_file 소유자/권한 부적절($result_etc_unknown_config_file). " ;;
            GOOD*) detail+="/etc/unknown_config_file 소유자/권한 적절($result_etc_unknown_config_file). " ;;
            NOT_FOUND) detail+="/etc/unknown_config_file 파일 없음. " ;;
        esac
    else
        detail+="/etc/unknown_config_file 파일 없음. "
        cur_state+="/etc/unknown_config_file: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우" && cur_state="점검 대상 파일 없음"

    add_result "WEB-14" "웹 서비스 > 2. 서비스 관리" "웹 서비스 경로 내 파일의 접근 통제" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-15: 웹 서비스의 불필요한 스크립트 매핑 제거
check_WEB_15() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정 [상세 조치 사례] l Tomcat Step 1\) 설정 파일의 불필요 스크립트 매핑 제거 <servlet-mapping> <servlet-name>UnuseServlet</servlet-name> <url-pattern>/example/*</url-pattern> </servlet-mapping> ※ context.xml 파일 내 명시된 설정 파일에서도 DB 연결 확인 필요 314"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 스크립트 매핑이 존재하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-15" "웹 서비스 > 2. 서비스 관리" "웹 서비스의 불필요한 스크립트 매핑 제거" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-16: 웹 서비스 헤더 정보 노출 제한
check_WEB_16() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 server 값을 임의 정보로 변경 <Connector port=\"8080\" protocol=\"HTTP/1.1\" connectionTimeout=\"20000\" redirectPort=\"8443\" server=\"{임의 정보로 변경}\" /> Step 1\) server.xml 파일 내 아래 내용 추가 <Host> ... 중략 ... <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showReport=\"true\" showServerInfo =\"false\"/> ... 중략 ... </Host>"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-16" "웹 서비스 > 2. 서비스 관리" "웹 서비스 헤더 정보 노출 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-17: 웹 서비스 가상 디렉로리 삭제
check_WEB_17() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정 [상세 조치 사례] l Tomcat Step 1\) 'Context' 블록 요소의 'path' 속성값 확인 #vi /[Tomcat 설치 디렉터리]/server.xml <Host name=\"localhost\" appBase=\"webapps\" unpackWARs=\"true\" autoDeploy=\"true\"> <Context path=\"/virtual\" docBase=\"/path/to/your/virtual/directory\" reloadable=\"true\"/> </Host> Step 2\) Context 블록 요소 가상 디렉터리 제거"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 가상 디렉터리가 존재하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-17" "웹 서비스 > 2. 서비스 관리" "웹 서비스 가상 디렉로리 삭제" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-19: 웹 서비스 SSI(Server Side Includes) 사용 제한
check_WEB_19() {
    local status="양호"
    local detail=""
    local cmd="systemctl restart tomcat"
    local cur_state=""
    local remediation="웹 서비스 내 불필요한 SSI 사용 제한 설정 [상세 조치 사례] l Tomcat Step 1\) web.xml 파일 내 SSI 서블릿 또는 필터 사용 설정 확인 #cat /[Tomcat 설치 디렉터리]/tomcat-users.xml | grep 'SSIServlet\\|SSIFilter' <servlet-mapping> <servlet-name>SSIServlet</servlet-name> <url-pattern>*.shtml</url-pattern> </servlet-mapping> 또는 <filter-mapping> <filter-name>SSIFilter</filter-name> <url-pattern>*.shtml</url-pattern> </filter-mapping> Step 2\) web.xml 파일 내 SSI 서블릿 및 필터 설정 삭제 또는 주석 처리 Step 3\) web.xml 파일 내에서 SSI와 관련한 불필요 mapping 제거 또는 주석 처리 Step 4\) Tomcat 서비스 재구동 # systemctl restart tomcat"

    local svc_status
    svc_status=$(is_service_active "tomcat")
    cur_state="tomcat=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="tomcat 서비스 활성화 상태. "
        status="취약"
    else
        detail="tomcat 서비스 비활성화 상태. "
    fi

    add_result "WEB-19" "웹 서비스 > 3. 보안 설정" "웹 서비스 SSI\(Server Side Includes\) 사용 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-23: LDAP 알고리즘 적절하게 구성
check_WEB_23() {
    local status="양호"
    local detail=""
    local cmd="grep 'digest=' //conf/server.xml; vi //conf/server.xml; systemctl restart tomcat"
    local cur_state=""
    local remediation="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정 [상세 조치 사례] l Tomcat Step 1\) 비밀번호 다이제스트 알고리즘 확인 \(LDAP 종류별 암호화 알고리즘 지원 여부 확인\) # grep 'digest=' /[Tomcat 설치 디렉터리]/conf/server.xml digest=\"SSHA\" Step 2\) 비밀번호 다이제스트 알고리즘 설정 # vi /[Tomcat 설치 디렉터리]/conf/server.xml digest=\"SHA-256\" Step 3\) Tomcat 재구동 # systemctl restart tomcat ※ SHA-256 이상 암호화 알고리즘 권고 03. 웹 서비스 343"

    local config_file="//conf/server.xml"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "digest=" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: digest= 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "WEB-23" "웹 서비스 > 3. 보안 설정" "LDAP 알고리즘 적절하게 구성" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-24: 별도의 업로드 경로 사용 및 권한 설정
check_WEB_24() {
    local status="양호"
    local detail=""
    local cmd="vi //conf/context.xml; mkdir; mkdir /var/www/html/uploads"
    local cur_state=""
    local remediation="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정 [상세 조치 사례] l Tomcat Step 1\) server.xml 파일 내 Context 요소 allowLinking 옵션 설정 \(기본값 : 업로드 디렉터리 경로 존재하지 않음\) # vi /[Tomcat 설치 디렉터리]/conf/context.xml <servlet> <servlet-name>fileUploadServlet</servlet-name> <servlet-class>com.example.FileUploadServlet</servlet-class> </servlet> Step 2\) 별도의 업로드 경로 생성 # mkdir [웹서비스 디렉터리 외 경로] # mkdir /var/www/html/uploads Step 3\) 업로드 디렉터리 권한 설정 chmod 750 /var/www/html/uploads/ chown tomcat:tomcat /var/www/html/uploads/ Step 4\) 지정한 디렉터리 권한을 웹 서비스에서 사용"

    local output
    output=$(vi //conf/context.xml 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "WEB-24" "웹 서비스 > 3. 보안 설정" "별도의 업로드 경로 사용 및 권한 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-25: 주기적 보안 패치 및 벤더 권고사항 적용
check_WEB_25() {
    local status="양호"
    local detail=""
    local cmd="cd //lib; java -cp catalina.jar org.apache.catalina.util.ServerInfo"
    local cur_state=""
    local remediation="패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정 [상세 조치 사례] l Tomcat Step 1\) 웹 서버 버전과 최신 패치 버전을 비교하여 확인 # cd /[Tomcat 설치 디렉터리]/lib # java -cp catalina.jar org.apache.catalina.util.ServerInfo [ Tomcat 웹 서버 버전 확인 ] Step 2\) Tomcat 사이트를 통해 주기적으로 버전 점검을 하며, 최신 버전 적용 시 충분한 테스트 후 적용 권고 ※ 참고 사이트: https://tomcat.apache.org/"

    local output
    output=$(cd //lib 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "WEB-25" "웹 서비스 > 4. 패치 및 로그 관리" "주기적 보안 패치 및 벤더 권고사항 적용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-26: 로그 디렉터리 및 파일 권한 설정
check_WEB_26() {
    local status="양호"
    local detail=""
    local cmd="ls -al /; chmod o-rwx /"
    local cur_state=""
    local remediation="로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정 [상세 조치 사례] l Tomcat Step 1\) 로그 디렉터리 및 파일 권한 확인 # ls –al /<Tomcat 로그 디렉터리> Step 2\) 로그 디렉터리 및 파일의 불필요 권한 삭제 # chmod o-rwx /<Tomcat 로그 파일> 03. 웹 서비스 351"

    local vuln_found=false
    if [ -e "/etc/unknown_config_file" ]; then
        local result_etc_unknown_config_file
        result_etc_unknown_config_file=$(check_file_owner_perm "/etc/unknown_config_file" "root" "644")
        cur_state+="/etc/unknown_config_file: $result_etc_unknown_config_file; "
        case "$result_etc_unknown_config_file" in
            VULN*) vuln_found=true; detail+="/etc/unknown_config_file 소유자/권한 부적절($result_etc_unknown_config_file). " ;;
            GOOD*) detail+="/etc/unknown_config_file 소유자/권한 적절($result_etc_unknown_config_file). " ;;
            NOT_FOUND) detail+="/etc/unknown_config_file 파일 없음. " ;;
        esac
    else
        detail+="/etc/unknown_config_file 파일 없음. "
        cur_state+="/etc/unknown_config_file: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우" && cur_state="점검 대상 파일 없음"

    add_result "WEB-26" "웹 서비스 > 4. 패치 및 로그 관리" "로그 디렉터리 및 파일 권한 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}


###############################################################################
# Execute all checks
###############################################################################

echo "===== Tomcat CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/27] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Tomcat-01"; check_CLD_Tomcat_01
progress "CLD-Tomcat-02"; check_CLD_Tomcat_02
progress "CLD-Tomcat-03"; check_CLD_Tomcat_03
progress "CLD-Tomcat-06"; check_CLD_Tomcat_06
progress "CLD-Tomcat-07"; check_CLD_Tomcat_07
progress "CLD-Tomcat-04"; check_CLD_Tomcat_04
progress "CLD-Tomcat-05"; check_CLD_Tomcat_05
progress "CLD-Tomcat-08"; check_CLD_Tomcat_08
progress "CLD-Tomcat-09"; check_CLD_Tomcat_09
progress "WEB-05"; check_WEB_05
progress "WEB-06"; check_WEB_06
progress "WEB-07"; check_WEB_07
progress "WEB-08"; check_WEB_08
progress "WEB-09"; check_WEB_09
progress "WEB-10"; check_WEB_10
progress "WEB-11"; check_WEB_11
progress "WEB-12"; check_WEB_12
progress "WEB-13"; check_WEB_13
progress "WEB-14"; check_WEB_14
progress "WEB-15"; check_WEB_15
progress "WEB-16"; check_WEB_16
progress "WEB-17"; check_WEB_17
progress "WEB-19"; check_WEB_19
progress "WEB-23"; check_WEB_23
progress "WEB-24"; check_WEB_24
progress "WEB-25"; check_WEB_25
progress "WEB-26"; check_WEB_26

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
    echo '    "platform": "Tomcat",'
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

echo "===== Tomcat CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
