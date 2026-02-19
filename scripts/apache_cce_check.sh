#!/bin/bash
###############################################################################
# Apache CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash apache_cce_check.sh [output_file.json]
# Output: JSON file with all check results
###############################################################################

set -o pipefail

OUTPUT_FILE="${1:-cce_check_result_apache_$(hostname)_$(date +%Y%m%d_%H%M%S).json}"

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


# --- Apache helper ---
APACHE_CONF=""
for f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache2/conf/httpd.conf; do
    if [ -f "$f" ]; then
        APACHE_CONF="$f"
        break
    fi
done
APACHE_CONF_DIR=$(dirname "${APACHE_CONF:-/etc/httpd/conf/httpd.conf}")

get_apache_conf() {
    echo "$APACHE_CONF"
}


# --- Pre-flight: Apache 설치 확인 및 경로 탐지 ---
APACHE_BIN=""
APACHE_CONF=""
APACHE_CONF_DIR=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    APACHE_BIN=$(command -v httpd 2>/dev/null)
    if [ -z "$APACHE_BIN" ]; then
        APACHE_BIN=$(command -v apache2 2>/dev/null)
    fi
    if [ -z "$APACHE_BIN" ]; then
        APACHE_BIN=$(command -v apachectl 2>/dev/null)
    fi

    # 2) 프로세스에서 탐지
    if [ -z "$APACHE_BIN" ]; then
        local apache_proc
        apache_proc=$(ps -ef 2>/dev/null | grep -E '[h]ttpd|[a]pache2' | head -1)
        if [ -n "$apache_proc" ]; then
            APACHE_BIN=$(echo "$apache_proc" | awk '{print $8}')
            APP_FOUND="true"
        fi
    fi

    # 3) -V 로 설정 경로 추출
    if [ -n "$APACHE_BIN" ]; then
        local server_root
        server_root=$("$APACHE_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)"/\1/p')
        local server_config
        server_config=$("$APACHE_BIN" -V 2>/dev/null | sed -n 's/.*SERVER_CONFIG_FILE="\(.*\)"/\1/p')
        if [ -n "$server_root" ] && [ -n "$server_config" ]; then
            if echo "$server_config" | grep -q '^/'; then
                APACHE_CONF="$server_config"
            else
                APACHE_CONF="$server_root/$server_config"
            fi
        fi
    fi

    # 4) 공통 설정 파일 경로 탐색
    if [ -z "$APACHE_CONF" ]; then
        for f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache2/conf/httpd.conf; do
            if [ -f "$f" ]; then
                APACHE_CONF="$f"
                break
            fi
        done
    fi
    if [ -n "$APACHE_CONF" ]; then
        APACHE_CONF_DIR=$(dirname "$APACHE_CONF")
    fi

    # 5) 패키지 매니저 확인
    if [ -z "$APACHE_BIN" ] && [ -z "$APACHE_CONF" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'apache2\|httpd' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'httpd\|apache' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$APACHE_BIN" ] || [ -n "$APACHE_CONF" ]; then
        APP_FOUND="true"
    fi
}


###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] Apache 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi


# CLD-Apache-01 / WEB-11: 웹 서비스 영역의 분리
check_CLD_Apache_01() {
    local status="양호"
    local detail=""
    local cmd="cat | grep DocumentRoot"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 기본 디렉터리 변경 1\) DocumentRoot를 별도의 경로로 변경 # vi [Apache 환경 설정 파일] [주요기반시설 가이드] 웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정 [상세 조치 사례] l Apache Step 1\) apache2.conf \(또는 /conf/httpd.conf\) 파일 내 DocumentRoot를 별도의 경로로 변경 DocumentRoot [별도의 경로]"

    local output
    output=$(cat | grep DocumentRoot 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        # 결과 없음이 양호한 경우
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Apache-01 / WEB-11" "패치 관리" "웹 서비스 영역의 분리" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Apache-02 / WEB-07: 불필요한 파일 제거
check_CLD_Apache_02() {
    local status="양호"
    local detail=""
    local cmd="find . -name manual; vi /httpd.conf"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 매뉴얼 디렉터리 삭제 1\) # rm –rf [Apache2 설치 디렉터리/manual] 2\) Apache 설정 파일에 매뉴얼에 관한 설정이 존재할 경우 삭제 또는 주석처리 3\) # vi [Apahce 설정 파일] [주요기반시설 가이드] 불필요한 파일 및 디렉터리를 제거하도록 설정 [상세 조치 사례] l Apache Step 1\) rm 명령어로 확인된 불필요한 매뉴얼 디렉터리 및 파일 제거 # rm –rf /<Apache 설치 디렉터리>/htdocs/manual # rm –rf /<Apache 설치 디렉터리>/manual ※ 2.4 버전 이상은 htdocs 디렉터리가 기본 제공되지 않으므로 /var/www/html 사용"

    status="수동점검"
    detail="API 기반 점검 항목. 기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
    cur_state="수동점검 필요"

    add_result "CLD-Apache-02 / WEB-07" "보안 설정" "불필요한 파일 제거" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Apache-03 / WEB-12: 링크 사용 금지
check_CLD_Apache_03() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/apache2/apache2.conf | grep FollowSymLinks; cat | grep Alias"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 심볼릭 링크 사용 제한 1\) 환경 설정 파일 내에 FollowSymLinks Options 중 Indexes 제거 ￭ Alias 사용 제한 1\) Alias 환경 설정 파일 내에 Alias 사용 제한 \(주석처리\) [주요기반시설 가이드] 웹 서비스 링크 사용 제한 설정 [상세 조치 사례] l Apache Step 1\) apache.conf\(또는 /conf/httpd.conf\) 파일 내 Options 지시자 FollowSymLinks 옵션 제거 <Directory /> Options –FollowSymLinks #Options Indexes FollowSymLinks </Directory> 306"

    local config_file="/etc/apache2/apache2.conf"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "Alias" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: Alias 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Apache-03 / WEB-12" "보안 설정" "링크 사용 금지" "중" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Apache-04 / WEB-08: 파일 업로드 및 다운로드 제한
check_CLD_Apache_04() {
    local status="양호"
    local detail=""
    local cmd="cat /etc/apache2/apache2.conf | grep LimitRequestBody"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 파일 업로드 및 다운로드 용량 제한 설정 1\) # vi /etc/apache2/apache2.conf [주요기반시설 가이드] 파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정 [상세 조치 사례] l Apache Step 1\) 설정 파일 내 LimitRequestBody 지시자에서 파일 용량 제한 설정 <Directory /> LimitRequestBody 5000000 </Directory>"

    local config_file="/etc/apache2/apache2.conf"
    # Expand wildcards/find actual config
    local actual_config
    actual_config=$(ls $config_file 2>/dev/null | head -1)
    if [ -z "$actual_config" ]; then
        detail="설정 파일 없음($config_file). "
        cur_state="설정 파일 없음"
        status="N/A"
    else
        local grep_result
        grep_result=$(grep -i "LimitRequestBody" "$actual_config" 2>/dev/null)
        cur_state="$grep_result"
        if [ -n "$grep_result" ]; then
            detail="설정 확인됨: $grep_result. "
        else
            detail="설정 미확인: LimitRequestBody 패턴 미발견. "
            status="취약"
        fi
    fi

    add_result "CLD-Apache-04 / WEB-08" "보안 설정" "파일 업로드 및 다운로드 제한" "하" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Apache-05 / WEB-04: 디렉터리 리스팅 제거
check_CLD_Apache_05() {
    local status="양호"
    local detail=""
    local cmd="vi //httpd.conf; systemctl restart apache2"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ 디렉터리 검색 기능 제거 1\) 환경 설정 파일 Options Indexes FollowSymLinks에서 'Indexes'를 제거하거나, '-indexex' 옵션 설정 2\) Options Indexes FollowSymLinks 주석처리 [주요기반시설 가이드] 디렉터리 리스팅 기능 차단 설정 [상세 조치 사례] l Apache Step 1\) httpd.conf 파일 내 모든 디렉터리의 Options 지시자에서 Indexes 옵션 제거 # vi /<Apache 설치 디렉터리>/httpd.conf\(또는 apache.conf\) <Directory /> Options Indexes 삭제 \(또는 –Indexes 설정\) </Directory> Step 2\) Apache 재시작 # systemctl restart apache2 ※ httpd.conf 뿐 아니라 sites-available 디렉터리 내 모든 사이트에 적용 ※ 파일 위치 및 서비스명은 사용하는 운영체제에 따라 달라질 수 있음 03. 웹 서비스 281"

    status="수동점검"
    detail="API 기반 점검 항목. 디렉터리 리스팅이 설정되지 않은 경우"
    cur_state="수동점검 필요"

    add_result "CLD-Apache-05 / WEB-04" "접근 관리" "디렉터리 리스팅 제거" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Apache-06 / WEB-09: 웹 프로세스 권한 제한
check_CLD_Apache_06() {
    local status="양호"
    local detail=""
    local cmd="ps -ef | grep apache2; vi //envvars; chown -R www-data:www-data /etc/apache2/"
    local cur_state=""
    local remediation="[클라우드 가이드] ￭ apache 데몬 user/group 변경 \(예시\) 1\) # vi [Apache 설정 디렉터리]/envvars 2\) APACHE_RUN_USER, APACHE_RUN_GROUP을 별도의 계정으로 변경 3\) 웹 프로세스 구동 사용자 계정을 변경했을 경우, 로그인이 되지 않도록 계정에 nologin 설정 # vi /etc/passwd [주요기반시설 가이드] 웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정 [상세 조치 사례] l Apache Step 1\) envvars 파일 내 실행 계정을 관리자 계정이 아닌 별도의 계정으로 변경 # vi /[Apache 설치 디렉터리]/envvars export APACHE_RUN_USER=www-data export APACHE_RUN_GROUP=www-data Step 2\) Apache 서비스 파일 소유권 변경 # chown -R www-data:www-data /etc/apache2/ # chown -R www-data:www-data /var/www/ # chown -R www-data:www-data /var/log/apache2/ Step 3\) 웹 서비스 실행 계정 로그인 제한 설정 # usermod -s /sbin/nologin [사용자명] Step 4\) Apache 재구동 # systemctl restart apache2 또는 httpd"

    local vuln_found=false
    if [ -e "//envvars" ]; then
        local result_envvars
        result_envvars=$(check_file_owner_perm "//envvars" "root" "644")
        cur_state+="//envvars: $result_envvars; "
        case "$result_envvars" in
            VULN*) vuln_found=true; detail+="//envvars 소유자/권한 부적절($result_envvars). " ;;
            GOOD*) detail+="//envvars 소유자/권한 적절($result_envvars). " ;;
            NOT_FOUND) detail+="//envvars 파일 없음. " ;;
        esac
    else
        detail+="//envvars 파일 없음. "
        cur_state+="//envvars: 파일 없음; "
    fi
    if [ -e "/etc/apache2/" ]; then
        local result_etc_apache2
        result_etc_apache2=$(check_file_owner_perm "/etc/apache2/" "root" "644")
        cur_state+="/etc/apache2/: $result_etc_apache2; "
        case "$result_etc_apache2" in
            VULN*) vuln_found=true; detail+="/etc/apache2/ 소유자/권한 부적절($result_etc_apache2). " ;;
            GOOD*) detail+="/etc/apache2/ 소유자/권한 적절($result_etc_apache2). " ;;
            NOT_FOUND) detail+="/etc/apache2/ 파일 없음. " ;;
        esac
    else
        detail+="/etc/apache2/ 파일 없음. "
        cur_state+="/etc/apache2/: 파일 없음; "
    fi
    if [ -e "/var/www/" ]; then
        local result_var_www
        result_var_www=$(check_file_owner_perm "/var/www/" "root" "644")
        cur_state+="/var/www/: $result_var_www; "
        case "$result_var_www" in
            VULN*) vuln_found=true; detail+="/var/www/ 소유자/권한 부적절($result_var_www). " ;;
            GOOD*) detail+="/var/www/ 소유자/권한 적절($result_var_www). " ;;
            NOT_FOUND) detail+="/var/www/ 파일 없음. " ;;
        esac
    else
        detail+="/var/www/ 파일 없음. "
        cur_state+="/var/www/: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="웹 프로세스\(웹 서비스\)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진" && cur_state="점검 대상 파일 없음"

    add_result "CLD-Apache-06 / WEB-09" "접근 관리" "웹 프로세스 권한 제한" "상" "$status" "$detail" "통합" "$cmd" "$cur_state" "$remediation"
}

# CLD-Apache-07: 최신 보안 패치 적용
check_CLD_Apache_07() {
    local status="양호"
    local detail=""
    local cmd="apache2 -v"
    local cur_state=""
    local remediation="￭ 보안 패치 적용 1\) 보안 취약점이 존재하지 않는 버전으로 보안패치를 적용해야 함 ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우 최신이 아닌 취약점이 존재하지 않는 버전도 허용하고 있음"

    local output
    output=$(apache2 -v 2>/dev/null)
    cur_state="$output"

    if [ -z "$output" ]; then
        detail="명령 실행 결과 없음. "
        status="수동점검"
    else
        detail="결과: $(echo "$output" | head -5 | tr '\n' ' '). "
        status="수동점검"
    fi

    add_result "CLD-Apache-07" "패치 관리" "최신 보안 패치 적용" "-" "$status" "$detail" "클라우드" "$cmd" "$cur_state" "$remediation"
}

# WEB-05: 지정하지 않은 CGI/ISAPI 실행 제한
check_WEB_05() {
    local status="양호"
    local detail=""
    local cmd="vi //httpd.conf; vi //apache.conf"
    local cur_state=""
    local remediation="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정 [상세 조치 사례] l Apache Step 1\) apache 설정 파일 내 CGI 모듈 비활성화 또는 주석 처리 # vi /<Apache 설치 디렉터리>/httpd.conf\(또는 apache.conf\) #LoadModule cgi_module modules/mod_cgi.so #LoadModule cgid_module modules/mod_cgid.so Step 2\) apache 설정 파일 내 설정된 모든 디렉터리의 Options 지시자에서 ExecCGI 옵션 제거 # vi /<Apache 설치 디렉터리>/apache.conf\(또는 httpd.conf\) <Directory \"/var/www/cgi-bin\"> Options -ExecCGI </Directory> Step 3\) Apache 재시작 284"

    status="수동점검"
    detail="API 기반 점검 항목. CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
    cur_state="수동점검 필요"

    add_result "WEB-05" "웹 서비스 > 2. 서비스 관리" "지정하지 않은 CGI/ISAPI 실행 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-06: 웹 서비스 상위 디렉터리 접근 제한 설정
check_WEB_06() {
    local status="양호"
    local detail=""
    local cmd="vi //httpd.conf; vi //httpd.conf; htpasswd //.htpasswd"
    local cur_state=""
    local remediation="상위 디렉터리 접근 기능 제거 설정 [상세 조치 사례] l Apache Step 1\) AllowOverride 지시자 Authconfig 옵션 설정 확인 # vi /<Apache 설치 디렉터리>/httpd.conf\(또는 apache.conf\) <Directory \"/usr/local/apache2/htdocs\"> AllowOverride None </Directory> Step 2\) AllowOverride 지시자 AuthConfig 옵션 설정 # vi /<Apache 설치 디렉터리>/httpd.conf\(또는 apache.conf\) <Directory \"/usr/local/apache2/htdocs\"> AllowOverride AuthConfig </Directory> 03. 웹 서비스 Step 3\) 사용자 인증을 설정할 디렉터리에 .htaccess 파일 생성 AuthName \"디렉터리 사용자 인증\" AuthType Basic AuthUserFile /usr/local/apache/test/.auth Require valid-user 지시자 설명 AuthName 인증 영역\(웹 브라우저의 인증 창에 표시되는 문구\) AuthType 인증 형태\(Basic 또는, Digest\) AuthUserFile 사용자 정보\(아이디 및 비밀번호\) 저장 파일 위치 AuthGroupFile 그룹 파일의 위치\(옵션\) Require 접근을 허용할 사용자 또는, 그룹 정의 Step 4\) 사용자 인증에 사용할 아이디 및 비밀번호 생성 # htpasswd /<Apache 설치 디렉터리>/.htpasswd [사용자명] New password: <비밀번호 입력> Re-type new password: <비밀번호 재입력> Adding password for user <사용자명> Step 5\) Apache 재구동 # systemctl restart apache2"

    status="수동점검"
    detail="API 기반 점검 항목. 상위 디렉터리 접근 기능을 제거한 경우"
    cur_state="수동점검 필요"

    add_result "WEB-06" "웹 서비스 > 2. 서비스 관리" "웹 서비스 상위 디렉터리 접근 제한 설정" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-10: 불필요한 프록시 설정 제한
check_WEB_10() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정 [상세 조치 사례] l Apache Step 1\) apache2.conf \(또는 /conf/httpd.conf\) 파일 내 불필요한 Proxy 제거 <VirtualHost *:80> ServerName www.example.com ProxyPreserveHost On ProxyRequests Off ProxyPass / http://backend-server.example.com/ ProxyPassReverse / http://backend-server.example.com/ </VirtualHost>"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. 불필요한 Proxy 설정을 제한한 경우"
    cur_state="수동점검 필요"

    add_result "WEB-10" "웹 서비스 > 2. 서비스 관리" "불필요한 프록시 설정 제한" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-14: 웹 서비스 경로 내 파일의 접근 통제
check_WEB_14() {
    local status="양호"
    local detail=""
    local cmd="chown -R ]: apache2.conf; chmod -R 750 apache2.conf"
    local cur_state=""
    local remediation="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정 [상세 조치 사례] l Apache Step 1\) 루트 디렉터리 내 불필요한 권한 삭제 또는 적절한 권한 부여 # chown –R <Apache 계정>]:<Apache 그룹> apache2.conf \(또는 httpd.conf\) # chmod -R 750 apache2.conf \(또는 httpd.conf\)"

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

# WEB-16: 웹 서비스 헤더 정보 노출 제한
check_WEB_16() {
    local status="양호"
    local detail=""
    local cmd="수동점검 필요"
    local cur_state=""
    local remediation="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정 [상세 조치 사례] l Apache Step 1\) httpd.conf \(또는 apache2.conf\) 파일 내 모든 디렉터리에 ServerTokens, ServerSignature 옵션 설정 <Directory/> ServerTokens Prod ServerSignature Off </Directory> ※ ServerTokens 지시자 옵션 ServerTokens 지시자 옵션 키워드 제공하는 정보 예문 Prod 웹 서버 종류 Apache Min 웹 서버 버전 Apache/2.2.3 OS 웹 서버의 버전 + 운영체제 Apache/2.2.3 \(CentOS\) 기본값 Full 웹 서버의 모든 정보 Apache/2.2.3 \(CentOS\) DAV/2 PHP/5.16 03. 웹 서비스 317"

    status="수동점검"
    detail="수동 점검 필요 항목입니다. HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-16" "웹 서비스 > 2. 서비스 관리" "웹 서비스 헤더 정보 노출 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-17: 웹 서비스 가상 디렉로리 삭제
check_WEB_17() {
    local status="양호"
    local detail=""
    local cmd="vi //conf/httpd.conf"
    local cur_state=""
    local remediation="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정 [상세 조치 사례] l Apache Step 1\) Alias 지시자 확인 # vi /[Apache 설치 디렉터리]/conf/httpd.conf\(또는 apache2.conf\) Alias /virtual /var/www/virtual <Directory /var/www/virtual> Options Indexes FollowSymLinks AllowOverride None Require all granted </Directory> Step 2\) 불필요한 가상 디렉터리 삭제 03. 웹 서비스 321"

    status="수동점검"
    detail="API 기반 점검 항목. 불필요한 가상 디렉터리가 존재하지 않는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-17" "웹 서비스 > 2. 서비스 관리" "웹 서비스 가상 디렉로리 삭제" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-18: 웹 서비스 WebDAV 비활성화
check_WEB_18() {
    local status="양호"
    local detail=""
    local cmd="cat //conf/httpd.conf; vi //conf/httpd.conf; systemctl restart apache2"
    local cur_state=""
    local remediation="WebDAV 서비스 비활성화 설정 [상세 조치 사례] l Apache Step 1\) httpd.conf 파일 내 모든 디렉터리에서 WebDAV 설정 확인 # cat /[Apache_Dir]/conf/httpd.conf\(또는 apache2.conf\) Dav On Step 2\) 모든 디렉터리에서 WebDAV 설정 비활성화 또는 주석 처리 # vi /[Apache_Dir]/conf/httpd.conf\(또는 apache2.conf\) <Directory \"/path/to/directory\"> Dav Off </Directory> Step 3\) Apache 재구동 # systemctl restart apache2 03. 웹 서비스 323"

    status="수동점검"
    detail="API 기반 점검 항목. WebDAV 서비스를 비활성화하고 있는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-18" "웹 서비스 > 2. 서비스 관리" "웹 서비스 WebDAV 비활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-19: 웹 서비스 SSI(Server Side Includes) 사용 제한
check_WEB_19() {
    local status="양호"
    local detail=""
    local cmd="vi //conf/httpd.conf; vi //conf/httpd.conf"
    local cur_state=""
    local remediation="웹 서비스 내 불필요한 SSI 사용 제한 설정 [상세 조치 사례] l Apache Step 1\) Options 지시자 Includes 옵션 확인 # vi /[Apache 설치 디렉터리]/conf/httpd.conf\(또는 /conf/apache.conf\) <Directory /> Options Includes </Directory> Step 2\) Options 지시자 Includes 옵션 제거 # vi /[Apache 설치 디렉터리]/conf/httpd.conf\(또는 /conf/apache.conf\) <Directory /> Options </Directory> 326"

    status="수동점검"
    detail="API 기반 점검 항목. 웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-19" "웹 서비스 > 3. 보안 설정" "웹 서비스 SSI\(Server Side Includes\) 사용 제한" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-20: SSL/TLS 활성화
check_WEB_20() {
    local status="양호"
    local detail=""
    local cmd="apache2ctl -M | grep ssl; vi //sites-available/default-ssl.conf; a2ensite default-ssl"
    local cur_state=""
    local remediation="웹 서비스 내 SSL/TLS 활성화 설정 [상세 조치 사례] l Apache Step 1\) SSL 모듈 활성화 확인 # apache2ctl –M | grep ssl ssl_module \(shared\) Step 2\) SSL 가상 호스트 설정에 SSL 인증서 설정 추가 # vi /[Apache 설치 디렉터리]/sites-available/default-ssl.conf <VirtualHost *:443> ServerAdmin webmaster@yourdomain.com ServerName yourdomain.com DocumentRoot /var/www/html SSLEngine on SSLCertificateFile /path/to/your_domain_name.crt SSLCertificateKeyFile /path/to/your_domain_name.key ErrorLog \${APACHE_LOG_DIR}/error.log CustomLog \${APACHE_LOG_DIR}/access.log combined </VirtualHost> Step 3\) SSL 가상 호스트 활성화 # a2ensite default-ssl Step 4\) Apache 재구동 # systemctl restart apache2"

    local svc_status
    svc_status=$(is_service_active "apache2")
    cur_state="apache2=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="apache2 서비스 활성화 상태. "
        status="취약"
    else
        detail="apache2 서비스 비활성화 상태. "
    fi

    add_result "WEB-20" "웹 서비스 > 3. 보안 설정" "SSL/TLS 활성화" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-21: HTTP 리디렉션
check_WEB_21() {
    local status="양호"
    local detail=""
    local cmd="apache2ctl -M | grep ssl; apt install mod_ssl; vi //sites-available/default-ssl.conf"
    local cur_state=""
    local remediation="HTTP Redirection 활성화 설정 [상세 조치 사례] l Apache Step 1\) SSL 모듈 활성화 확인 # apache2ctl -M | grep ssl Step 1\) SSL 인증서 활성화 설정 Step 2\) \(미설치 시\) mod_rewrite 설치 # apt install mod_ssl Step 3\) HTTP Redirection 설정 확인 # vi /[Apache 설치 디렉터리]/sites-available/default-ssl.conf <VirtualHost *:80> ServerName example.com Redirect permanent / https://example.com/ </VirtualHost> 03. 웹 서비스 Step 4\) SSL 가상 호스트 설정 # vi /[Apache 설치 디렉터리]/sites-available/default-ssl.conf <VirtualHost *:80> ServerAdmin webmaster@yourdomain.com ServerName yourdomain.com DocumentRoot /var/www/html RewriteEngine On RewriteCond %{HTTPS} off RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301] ErrorLog \${APACHE_LOG_DIR}/error.log CustomLog \${APACHE_LOG_DIR}/access.log combined </VirtualHost> Step 5\) SSL 가상 호스트 활성화 및 Apache 재구동 # vi sudo a2ensite default-ssl # systemctl restart apache2"

    local svc_status
    svc_status=$(is_service_active "apache2")
    cur_state="apache2=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="apache2 서비스 활성화 상태. "
        status="취약"
    else
        detail="apache2 서비스 비활성화 상태. "
    fi

    add_result "WEB-21" "웹 서비스 > 3. 보안 설정" "HTTP 리디렉션" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-22: 에러 페이지 관리
check_WEB_22() {
    local status="양호"
    local detail=""
    local cmd="vi //sites-available/000-default.conf; systemctl restart apache2"
    local cur_state=""
    local remediation="필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정 [상세 조치 사례] l Apache Step 1\) httpd.conf 파일 내 에러 코드별 에러 페이지 설정 정보 확인 후 별도의 일원화된 에러 페이지 설정 # vi /[Apache 설치 디렉터리]/sites-available/000-default.conf ErrorDocument 400 /error.html ErrorDocument 401 /error.html \(이하 생략\) Step 2\) Apache 재구동 # systemctl restart apache2 03. 웹 서비스 339"

    local svc_status
    svc_status=$(is_service_active "apache2")
    cur_state="apache2=$svc_status"
    if [ "$svc_status" = "active" ]; then
        detail="apache2 서비스 활성화 상태. "
    else
        detail="apache2 서비스 비활성화 상태. "
        status="취약"
    fi

    add_result "WEB-22" "웹 서비스 > 3. 보안 설정" "에러 페이지 관리" "하" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-24: 별도의 업로드 경로 사용 및 권한 설정
check_WEB_24() {
    local status="양호"
    local detail=""
    local cmd="vi //apache2/apache2.conf; mkdir; mkdir /var/www/html/uploads"
    local cur_state=""
    local remediation="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정 [상세 조치 사례] l Apache Step 1\) apache2.conf 파일 내 업로드 경로 및 웹서비스 디렉터리 경로 확인 # vi /[Apache 설치 디렉터리]/apache2/apache2.conf\(또는 apache2.conf\) <Directory /var/www/html/uploads> Options None AllowOverride None Require all denied </Directory> Step 2\) 별도 업로드 경로 생성 # mkdir [웹서비스 디렉터리 외 경로] # mkdir /var/www/html/uploads Step 3\) 파일 실행 권한 확인 # ls -al /[Apache 업로드 디렉터리] Step 4\) 업로드 디렉터리 권한 설정 # chmod 750 /var/www/html/uploads/ # chown www-data:www-data /var/www/html/uploads/ Step 5\) apache2.conf 파일 내 업로드 디렉터리 접근제한 설정 # vi /[Apache 설치 디렉터리]/apache2/apache2.conf <Directory \"/var/www/html/uploads/\"> Require all denied </Directory>"

    local vuln_found=false
    if [ -e "//apache2/apache2.conf" ]; then
        local result_apache2_apache2_conf
        result_apache2_apache2_conf=$(check_file_owner_perm "//apache2/apache2.conf" "root" "644")
        cur_state+="//apache2/apache2.conf: $result_apache2_apache2_conf; "
        case "$result_apache2_apache2_conf" in
            VULN*) vuln_found=true; detail+="//apache2/apache2.conf 소유자/권한 부적절($result_apache2_apache2_conf). " ;;
            GOOD*) detail+="//apache2/apache2.conf 소유자/권한 적절($result_apache2_apache2_conf). " ;;
            NOT_FOUND) detail+="//apache2/apache2.conf 파일 없음. " ;;
        esac
    else
        detail+="//apache2/apache2.conf 파일 없음. "
        cur_state+="//apache2/apache2.conf: 파일 없음; "
    fi
    if [ -e "/var/www/html/uploads" ]; then
        local result_var_www_html_uploads
        result_var_www_html_uploads=$(check_file_owner_perm "/var/www/html/uploads" "root" "644")
        cur_state+="/var/www/html/uploads: $result_var_www_html_uploads; "
        case "$result_var_www_html_uploads" in
            VULN*) vuln_found=true; detail+="/var/www/html/uploads 소유자/권한 부적절($result_var_www_html_uploads). " ;;
            GOOD*) detail+="/var/www/html/uploads 소유자/권한 적절($result_var_www_html_uploads). " ;;
            NOT_FOUND) detail+="/var/www/html/uploads 파일 없음. " ;;
        esac
    else
        detail+="/var/www/html/uploads 파일 없음. "
        cur_state+="/var/www/html/uploads: 파일 없음; "
    fi
    if [ -e "/var/www/html/uploads/" ]; then
        local result_var_www_html_uploads
        result_var_www_html_uploads=$(check_file_owner_perm "/var/www/html/uploads/" "root" "644")
        cur_state+="/var/www/html/uploads/: $result_var_www_html_uploads; "
        case "$result_var_www_html_uploads" in
            VULN*) vuln_found=true; detail+="/var/www/html/uploads/ 소유자/권한 부적절($result_var_www_html_uploads). " ;;
            GOOD*) detail+="/var/www/html/uploads/ 소유자/권한 적절($result_var_www_html_uploads). " ;;
            NOT_FOUND) detail+="/var/www/html/uploads/ 파일 없음. " ;;
        esac
    else
        detail+="/var/www/html/uploads/ 파일 없음. "
        cur_state+="/var/www/html/uploads/: 파일 없음; "
    fi
    if [ "$vuln_found" = "true" ]; then
        status="취약"
    fi
    [ -z "$detail" ] && detail="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우" && cur_state="점검 대상 파일 없음"

    add_result "WEB-24" "웹 서비스 > 3. 보안 설정" "별도의 업로드 경로 사용 및 권한 설정" "중" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-25: 주기적 보안 패치 및 벤더 권고사항 적용
check_WEB_25() {
    local status="양호"
    local detail=""
    local cmd="//httpd -v"
    local cur_state=""
    local remediation="패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정 [상세 조치 사례] l Apache Step 1\) 웹 서버 버전과 최신 패치 버전을 비교하여 확인 # /[Apache 설치 디렉터리]/httpd –v [ Apache 웹 서버 버전 확인 ] Step 2\) Apache 사이트를 통해 주기적으로 버전 점검을 하며, 최신 버전 적용 시 충분한 테스트 후 적용 권고 ※ 참고 사이트: http://httpd.apache.org/download.cgi 348"

    status="수동점검"
    detail="API 기반 점검 항목. 최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
    cur_state="수동점검 필요"

    add_result "WEB-25" "웹 서비스 > 4. 패치 및 로그 관리" "주기적 보안 패치 및 벤더 권고사항 적용" "상" "$status" "$detail" "주요기반시설" "$cmd" "$cur_state" "$remediation"
}

# WEB-26: 로그 디렉터리 및 파일 권한 설정
check_WEB_26() {
    local status="양호"
    local detail=""
    local cmd="ls -al; chmod o-rwx /"
    local cur_state=""
    local remediation="로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정 [상세 조치 사례] l Apache Step 1\) 로그 디렉터리 및 파일 권한 확인 # ls –al <Aapche 로그 디렉터리> Step 2\) 로그 디렉터리 및 파일의 불필요 권한 삭제 # chmod o-rwx /<Apache 로그 파일>"

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

echo "===== Apache CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {
    total=$((total + 1))
    printf "\r[%d/21] %s 점검 중...                " "$total" "$1"
}


progress "CLD-Apache-01"; check_CLD_Apache_01
progress "CLD-Apache-02"; check_CLD_Apache_02
progress "CLD-Apache-03"; check_CLD_Apache_03
progress "CLD-Apache-04"; check_CLD_Apache_04
progress "CLD-Apache-05"; check_CLD_Apache_05
progress "CLD-Apache-06"; check_CLD_Apache_06
progress "CLD-Apache-07"; check_CLD_Apache_07
progress "WEB-05"; check_WEB_05
progress "WEB-06"; check_WEB_06
progress "WEB-10"; check_WEB_10
progress "WEB-14"; check_WEB_14
progress "WEB-16"; check_WEB_16
progress "WEB-17"; check_WEB_17
progress "WEB-18"; check_WEB_18
progress "WEB-19"; check_WEB_19
progress "WEB-20"; check_WEB_20
progress "WEB-21"; check_WEB_21
progress "WEB-22"; check_WEB_22
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
    echo '    "platform": "Apache",'
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

echo "===== Apache CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
