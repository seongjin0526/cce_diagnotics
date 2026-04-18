#!/usr/bin/env python3
"""
CCE 애플리케이션별 진단 스크립트 자동 생성기
진단항목통합.xlsx를 읽어 21개 애플리케이션별 진단 스크립트를 생성한다.
linux_cce_check.sh와 동일한 패턴의 JSON 출력 구조를 따른다.
"""
import os
import re
import shlex
import textwrap
from openpyxl import load_workbook

from code_scheme import to_preferred_code_text
from project_paths import MERGED_ITEMS_XLSX, SCRIPTS_DIR

EXCEL_FILE = MERGED_ITEMS_XLSX
OUTPUT_DIR = SCRIPTS_DIR

OUTPUT_DIR.mkdir(exist_ok=True)

# ── App definitions ──────────────────────────────────────────────────────────
# key = Excel '진단대상' value
# script: output filename
# shell: bash or powershell
# platform_label: used in JSON scan_info
# needs_db_args: adds -h -P -u -p argument parsing
# custom_helpers: extra helper functions injected into the script
# esxi: special ESXi BusyBox mode

APP_DEFS = {
    'KVM': {
        'script': 'kvm_cce_check.sh', 'platform': 'KVM',
        'helpers': ['virsh_helper'],
    },
    'Xenserver': {
        'script': 'xenserver_cce_check.sh', 'platform': 'Xenserver',
        'helpers': ['xe_helper'],
    },
    'ESXi': {
        'script': 'esxi_cce_check.sh', 'platform': 'ESXi',
        'helpers': ['esxcli_helper'], 'esxi': True,
    },
    'MY-SQL': {
        'script': 'mysql_cce_check.sh', 'platform': 'MySQL',
        'helpers': ['mysql_query_helper'], 'needs_db_args': True,
        'db_type': 'mysql',
    },
    'MS-SQL': {
        'script': 'mssql_cce_check.sh', 'platform': 'MSSQL',
        'helpers': ['mssql_query_helper'], 'needs_db_args': True,
        'db_type': 'mssql',
    },
    'Redis': {
        'script': 'redis_cce_check.sh', 'platform': 'Redis',
        'helpers': ['redis_cli_helper'], 'needs_db_args': True,
        'db_type': 'redis',
    },
    'Elasticsearch': {
        'script': 'elasticsearch_cce_check.sh', 'platform': 'Elasticsearch',
        'helpers': ['es_curl_helper'],
    },
    'MongoDB': {
        'script': 'mongodb_cce_check.sh', 'platform': 'MongoDB',
        'helpers': ['mongo_helper'], 'needs_db_args': True,
        'db_type': 'mongodb',
    },
    'PostgreSQL': {
        'script': 'postgresql_cce_check.sh', 'platform': 'PostgreSQL',
        'helpers': ['psql_query_helper'], 'needs_db_args': True,
        'db_type': 'postgresql',
    },
    'Apache': {
        'script': 'apache_cce_check.sh', 'platform': 'Apache',
        'helpers': ['apache_helper'],
    },
    'Nginx': {
        'script': 'nginx_cce_check.sh', 'platform': 'Nginx',
        'helpers': ['nginx_helper'],
    },
    'Tomcat': {
        'script': 'tomcat_cce_check.sh', 'platform': 'Tomcat',
        'helpers': ['tomcat_helper'],
    },
    'Docker': {
        'script': 'docker_cce_check.sh', 'platform': 'Docker',
        'helpers': ['docker_helper'], 'esxi': True,
    },
    'K8s(Master)': {
        'script': 'k8s_master_cce_check.sh', 'platform': 'Kubernetes(Master)',
        'helpers': ['k8s_helper'], 'esxi': True,
    },
    'K8s(Worker)': {
        'script': 'k8s_worker_cce_check.sh', 'platform': 'Kubernetes(Worker)',
        'helpers': ['k8s_helper'], 'esxi': True,
    },
    'PHP': {
        'script': 'php_cce_check.sh', 'platform': 'PHP',
        'helpers': [],
    },
    'NodeJS': {
        'script': 'nodejs_cce_check.sh', 'platform': 'Node.js',
        'helpers': [],
    },
    'Hadoop': {
        'script': 'hadoop_cce_check.sh', 'platform': 'Hadoop',
        'helpers': ['hadoop_helper'],
    },
    'Ceph': {
        'script': 'ceph_cce_check.sh', 'platform': 'Ceph',
        'helpers': ['ceph_helper'],
    },
    'Windows': {
        'script': 'windows_cce_check.ps1', 'platform': 'Windows',
        'helpers': [], 'powershell': True,
    },
}

# ── Excel reader ─────────────────────────────────────────────────────────────

def read_excel_items():
    """Read all items from Excel, grouped by 진단대상."""
    wb = load_workbook(EXCEL_FILE)
    ws = wb['CCE 항목 통합(중복제거)']

    items_by_target = {}
    for r in range(2, ws.max_row + 1):
        target = ws.cell(row=r, column=1).value
        code = ws.cell(row=r, column=4).value
        if not target or not code:
            continue
        # Skip section header rows
        if target.strip().startswith('  ') or '(' in target and '합계' in target:
            continue

        item = {
            'code': to_preferred_code_text(code.strip()),
            'source': (ws.cell(row=r, column=2).value or '').strip(),
            'importance': (ws.cell(row=r, column=3).value or '-').strip(),
            'title': (ws.cell(row=r, column=5).value or '').strip(),
            'category': (ws.cell(row=r, column=6).value or '').strip(),
            'diagnosis': ws.cell(row=r, column=7).value or '',
            'remediation': ws.cell(row=r, column=8).value or '',
        }
        items_by_target.setdefault(target, []).append(item)

    wb.close()
    return items_by_target


# ── Diagnosis text parsing ───────────────────────────────────────────────────

def extract_commands_from_diagnosis(diag_text):
    """Extract executable commands from diagnosis text."""
    commands = []
    for line in diag_text.split('\n'):
        stripped = line.strip()
        # Match lines starting with # or $ followed by a command
        m = re.match(r'^[#$]\s+(.+)', stripped)
        if m:
            cmd = m.group(1).strip()
            # Filter out comments and non-commands
            if cmd and not cmd.startswith('※') and not cmd.startswith('(') and len(cmd) > 3:
                commands.append(cmd)
        # Also match numbered commands like "1) # cat ..."
        m2 = re.match(r'^\d+\)\s*[#$]\s+(.+)', stripped)
        if m2:
            cmd = m2.group(1).strip()
            if cmd and len(cmd) > 3:
                commands.append(cmd)
        inline_cmd = extract_inline_command(stripped)
        if inline_cmd:
            commands.append(inline_cmd)

    deduped = []
    for cmd in commands:
        if cmd and cmd not in deduped:
            deduped.append(cmd)
    return deduped


def extract_good_bad_criteria(diag_text):
    """Extract [양호] and [취약] criteria from diagnosis text."""
    good = ''
    bad = ''
    for line in diag_text.split('\n'):
        stripped = line.strip()
        if stripped.startswith('[양호]'):
            good = stripped[4:].strip()
        elif stripped.startswith('[취약]'):
            bad = stripped[4:].strip()
    return good, bad


def normalize_dash_text(text):
    if not text:
        return ''
    text = text.replace('–', '-').replace('—', '-').replace('−', '-')
    text = re.sub(r'\bls-\s*', 'ls -', text)
    text = re.sub(r'\bstat-\s*', 'stat -', text)
    return text


ABSENCE_SIGNAL_KEYWORDS = (
    '없', '않', '미설정', '미사용', '비활성', '차단', '제거', '금지',
    '숨김', '제한되어 있지', '존재하지', '노출되지', '비어있', 'disabled',
    'inactive', 'not ', 'off',
)
PRESENCE_SIGNAL_KEYWORDS = (
    '설정', '적용', '활성', '사용', '존재', '포함', '허용', '실행',
    '저장', '생성', '구성', '연동', 'enabled', 'active', 'on',
)


def infer_criteria_signal(text):
    normalized = normalize_dash_text(text).lower()
    if not normalized:
        return 'unknown'
    if any(keyword in normalized for keyword in ABSENCE_SIGNAL_KEYWORDS):
        return 'absence'
    if any(keyword in normalized for keyword in PRESENCE_SIGNAL_KEYWORDS):
        return 'presence'
    return 'unknown'


def infer_numeric_threshold(*texts, default=''):
    def collect_numbers(text):
        values = []
        normalized = normalize_dash_text(text)
        for match in re.findall(r'(?<![A-Za-z])(\d{1,4})(?![A-Za-z])', normalized):
            try:
                number = int(match)
            except ValueError:
                continue
            if 1900 <= number <= 2100:
                continue
            values.append(number)
        return values

    prioritized = []
    fallback = []
    for idx, text in enumerate(texts):
        values = collect_numbers(text)
        if idx < 2:
            prioritized.extend(values)
        else:
            fallback.extend(values)
    numbers = prioritized or fallback
    if not numbers:
        return default
    return str(max(numbers))


def infer_numeric_direction(*texts):
    normalized = normalize_dash_text('\n'.join(text for text in texts if text)).lower()
    if not normalized:
        return 'unknown'
    if any(token in normalized for token in ('이하', '이내', '넘지', '초과하지', 'less than or equal', '<=')):
        return 'max'
    if any(token in normalized for token in ('이상', '최소', '이상으로', 'at least', '>=')):
        return 'min'
    if '초과' in normalized or '초과로' in normalized:
        return 'max'
    if '미만' in normalized:
        return 'min'
    return 'unknown'


def infer_special_auto_decision_kind(title, diag, command=''):
    text = normalize_dash_text(f'{title}\n{diag}\n{command}').lower()
    if any(keyword in text for keyword in (
        '최신 보안 패치', 'hot fix', '백업', '보관 주기', '인터뷰',
        '불필요한 계정', '의심스러운 계정', '테스트 계정', '권한이 적절한 사용자',
        '불필요한 파일', '불필요한 proxy', '불필요한 프록시', '정책 수립',
        '로그 파일 관리', '주기적으로 관리', '주기적으로 백업',
    )):
        return 'manual_review'
    if 'permitrootlogin' in text or 'root 계정 원격 접속 제한' in text:
        return 'permit_root_login'
    if 'path 환경변수' in text or ('현재 위치' in text and 'path' in text):
        return 'path_dot'
    if '계정 잠금 임계값' in text or 'lockoutbadcount' in text:
        return 'account_lock'
    if 'tmout' in text or 'session timeout' in text or '세션 종료 시간' in text or '계정 로그오프' in text:
        return 'timeout'
    if 'umask' in text:
        return 'umask'
    if 'uid' in text and '0' in text:
        return 'uid_zero'
    if '도커 그룹' in text:
        return 'docker_group'
    if 'root 권한으로' in text or 'root 계정 또는 root 권한' in text or 'node 프로세스 권한 제한' in text:
        return 'root_process'
    if '헤더 정보 노출' in text:
        return 'header_exposure'
    if 'xp_cmdshell' in text or 'cleartextpassword' in text:
        return 'boolean_zero_good'
    if '암호화 알고리즘' in text or 'authentication_string' in text or 'pg_shadow' in text:
        return 'hash_algo'
    return 'default'


def looks_like_db_query(cmd):
    normalized = normalize_dash_text(cmd).strip()
    lowered = normalized.lower()
    if re.match(r'^(?:mysql|mariadb|mongo|mongosh)\s*>', lowered):
        return True
    if re.match(r'^(?:postgres(?:ql)?|postgres)\s*(?:=#|=>|#|>)', lowered):
        return True
    if lowered.startswith(('=#', '=>')):
        return True
    if lowered.startswith(('select ', 'show ', 'use ', 'exec ', 'sp_configure', '\\du', '\\dp', '\\l')):
        return True
    return False


def is_safe_db_query(query):
    normalized = normalize_dash_text(query).strip().rstrip(';')
    if not normalized:
        return False
    statements = [part.strip().lower() for part in normalized.split(';') if part.strip()]
    if not statements:
        return False
    allowed_prefixes = (
        'select ', 'show ', 'use ', '\\du', '\\dp', '\\l', '\\dn',
        'exec sp_configure', 'exec sp_helpsrvrolemember', 'sp_configure ',
        'db.admincommand', 'db.getsiblingdb', 'db.runcommand',
    )
    return all(statement.startswith(allowed_prefixes) for statement in statements)


def prepare_command_for_app(cmd, app_def):
    normalized = normalize_dash_text(cmd).strip()
    proc_name = infer_process_name([normalized])
    if proc_name:
        return f'get_process_snapshot "{escape_bash_string(proc_name)}"'

    db_type = app_def.get('db_type')
    if not db_type or not looks_like_db_query(normalized):
        return normalized

    query = normalized
    query = re.sub(r'^(?:mysql|mariadb|mongo|mongosh)\s*>\s*', '', query, flags=re.IGNORECASE)
    query = re.sub(r'^(?:postgres(?:ql)?|postgres)?\s*(?:=#|=>|#|>)\s*', '', query, flags=re.IGNORECASE)
    query = query.strip()
    if db_type == 'mysql':
        if re.match(r'^use\s+mysql\s*;?$', query, re.IGNORECASE):
            return ''
        query = re.sub(r'(?i)\bfrom\s+user\b', 'FROM mysql.user', query)
        query = re.sub(r'(?i)\bupdate\s+user\b', 'UPDATE mysql.user', query)
        query = re.sub(r'(?i)\bdelete\s+from\s+user\b', 'DELETE FROM mysql.user', query)
        query = re.sub(r"(?i)show\s+variables\s+like\s+([A-Za-z0-9_%]+)\s*;", r"SHOW VARIABLES LIKE '\1';", query)
        if re.match(r'(?i)^show\s+grants\s+for\s*;?$', query):
            return ''
    if not is_safe_db_query(query):
        return ''

    if db_type == 'mysql':
        return f'run_mysql_query "{escape_bash_string(query)}"'
    if db_type == 'postgresql':
        return f'run_psql_query "{escape_bash_string(query)}"'
    if db_type == 'mssql':
        return f'run_mssql_query "{escape_bash_string(query)}"'
    if db_type == 'mongodb':
        return f'run_mongo_query "{escape_bash_string(query)}"'
    return normalized


def extract_inline_command(stripped):
    command_patterns = (
        r'(net user guest|net user administrator|net user|net accounts|net localgroup administrators|net share)',
        r'(secedit\s+/export\s+/cfg\s+\S+)',
        r'(auditpol\s+/get\s+/subcategory:[^→]+)',
        r'(reg query\s+\S+)',
        r'(wmic\s+[A-Za-z0-9_,= ]+)',
        r'(icacls\s+[^→]+)',
        r'(sc query\s+\S+)',
        r'(ssh\s+-V)',
        r'(sudo\s+-u\s+\w+\s+(?:psql|mysql|mongo|mongosh)\b.*)',
    )
    for pattern in command_patterns:
        match = re.search(pattern, stripped, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    candidate = re.sub(r'^(?:Step\s*\d+\)|\d+[.)])\s*', '', stripped, flags=re.IGNORECASE)
    match = re.match(
        r'^((?:grep|cat|ls|find|stat|ps|curl|auditctl|iptables|ssh\s+-V|umask|virsh|xe|esxcli|docker|kubectl|redis-cli|hadoop|ceph|rados)\b.*)$',
        candidate,
        re.IGNORECASE,
    )
    if match:
        return match.group(1).strip()

    if looks_like_db_query(candidate):
        return candidate
    if looks_like_db_query(stripped):
        return stripped
    return ''


def classify_check_type(diag_text, commands, title=''):
    """Classify the check type based on diagnosis text and commands."""
    diag_lower = normalize_dash_text(diag_text).lower()
    title_lower = normalize_dash_text(title).lower()
    perm_context = any(keyword in f'{title_lower} {diag_lower}' for keyword in ['권한', '소유자', 'access', 'permission'])

    if '인터뷰' in diag_text and not commands:
        return 'manual'

    for cmd in commands:
        cmd_norm = normalize_dash_text(cmd)
        if looks_like_db_query(cmd_norm):
            return 'cli_tool'
        if (
            'chmod' in cmd_norm
            or 'chown' in cmd_norm
            or ('stat ' in cmd_norm and perm_context)
            or (re.search(r'\bls\s+-[A-Za-z]+', cmd_norm) and perm_context)
        ):
            return 'file_perm'
        if 'grep' in cmd_norm and ('conf' in cmd_norm or 'cfg' in cmd_norm or '.ini' in cmd_norm or '.xml' in cmd_norm or '.yaml' in cmd_norm or '.yml' in cmd_norm):
            return 'config_check'
        if 'systemctl' in cmd_norm or 'service ' in cmd_norm:
            return 'service_check'
        if 'curl' in cmd_norm or re.search(r'https?://', cmd_norm.lower()):
            return 'api_check'
        if any(x in cmd_norm for x in ['virsh', 'xe ', 'esxcli', 'docker', 'kubectl',
                                    'mysql', 'psql', 'mongo', 'redis-cli',
                                    'hadoop', 'ceph', 'rados']):
            return 'cli_tool'

    if any(keyword in f'{title_lower} {diag_lower}' for keyword in (
        '설정 파일', '환경 설정', 'nginx.conf', 'httpd.conf', 'apache2.conf',
        'server.xml', 'web.xml', 'tomcat-users.xml', 'php.ini', 'redis.conf',
        'postgresql.conf', 'pg_hba.conf', 'my.cnf', 'elasticsearch.yml', 'mongod.conf',
        '디렉터리 리스팅', 'cgi', 'isapi', '에러 페이지', '에러 메시지',
        '헤더 정보 노출', 'http 리디렉션', 'ssl/tls', 'webdav',
        '링크 사용 금지', '가상 디렉', '업로드', '다운로드', '프록시',
    )) and not perm_context:
        return 'config_check'

    if commands:
        return 'command_check'

    return 'manual'


def infer_process_name(commands):
    for cmd in commands:
        normalized = normalize_dash_text(cmd).lower()
        match = re.search(r'grep(?:\s+-[a-z ]+)?\s+([^\s|;]+)', normalized)
        if match:
            candidate = match.group(1).strip("'\"")
            candidate = re.sub(r'[\[\]]', '', candidate)
            candidate = candidate.lstrip('^').rstrip('$')
            if candidate not in {'grep', 'v', 'i'}:
                return candidate
    return ''


def _shell_command_text(value):
    if not value:
        return ''
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')


def _config_probe_command(config_expr, pattern, *, no_match_marker=None, missing_marker=None):
    pattern_safe = _shell_command_text(pattern)
    no_match_safe = _shell_command_text(no_match_marker or '')
    missing_safe = _shell_command_text(missing_marker or 'FILE_MISSING|설정 파일을 찾지 못했습니다.')
    command = (
        f'cfg={config_expr}; '
        'if [ -f "$cfg" ]; then '
        f'out=$(grep -Ein "{pattern_safe}" "$cfg" 2>/dev/null | head -20); '
    )
    if no_match_marker:
        command += f'if [ -n "$out" ]; then printf \'%s\\n\' "$out"; else echo "{no_match_safe}"; fi; '
    else:
        command += 'printf \'%s\\n\' "$out"; '
    command += f'else echo "{missing_safe}"; fi'
    return command


def _find_probe_command(base_expr, find_args, *, empty_marker=None, missing_marker=None):
    empty_safe = _shell_command_text(empty_marker or 'DEFAULT_GOOD|기본 샘플/불필요 파일이 없습니다.')
    missing_safe = _shell_command_text(missing_marker or 'FILE_MISSING|점검 대상 경로를 찾지 못했습니다.')
    return (
        f'base={base_expr}; '
        'if [ -d "$base" ]; then '
        f'out=$(find "$base" {find_args} 2>/dev/null | head -20); '
        f'if [ -n "$out" ]; then printf \'%s\\n\' "$out"; else echo "{empty_safe}"; fi; '
        f'else echo "{missing_safe}"; fi'
    )


def infer_fallback_commands(item, app_def):
    code = item['code'].split('/')[0].strip()
    platform = app_def.get('platform', '')

    apache_conf = '${APACHE_CONF:-/usr/local/apache2/conf/httpd.conf}'
    nginx_conf = '${NGINX_CONF:-/etc/nginx/nginx.conf}'
    tomcat_server_xml = '${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml'
    tomcat_web_xml = '${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml'
    tomcat_users_xml = '${CATALINA_HOME:-/usr/local/tomcat}/conf/tomcat-users.xml'

    if platform == 'Apache':
        mapping = {
            'CSAP-Apache-01': [_config_probe_command(apache_conf, r'^[[:space:]]*DocumentRoot|^[[:space:]]*Alias[[:space:]]+/', missing_marker='FILE_DEFAULT_BAD|기본 DocumentRoot 경로를 별도 분리 여부를 확인할 수 없습니다.')],
            'CSAP-Apache-05': [_config_probe_command(apache_conf, r'Options[^#\n]*Indexes|^[[:space:]]*IndexOptions')],
            'ISMS-WEB-05': [_config_probe_command(apache_conf, r'LoadModule.*cgi|Options[^#\n]*ExecCGI|ScriptAlias|cgi-bin', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 CGI 관련 설정을 확인하지 못했습니다.')],
            'ISMS-WEB-10': [_config_probe_command(apache_conf, r'ProxyPass|ProxyPassReverse|ProxyRequests|ProxyPreserveHost', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 프록시 지시자가 설정되지 않았습니다.')],
            'ISMS-WEB-16': [_config_probe_command(apache_conf, r'ServerTokens|ServerSignature', missing_marker='FILE_DEFAULT_BAD|기본값은 상세 서버 정보가 노출될 수 있습니다.')],
            'ISMS-WEB-17': [_config_probe_command(apache_conf, r'^[[:space:]]*Alias[[:space:]]+/|<Directory[[:space:]]+/var/www', no_match_marker='SETTING_DEFAULT_GOOD|가상 디렉터리 지시자를 확인하지 못했습니다.')],
            'ISMS-WEB-18': [_config_probe_command(apache_conf, r'^[[:space:]]*Dav[[:space:]]+', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 WebDAV 지시자가 설정되지 않았습니다.')],
            'ISMS-WEB-19': [_config_probe_command(apache_conf, r'Options[^#\n]*Includes|IncludesNOEXEC|mod_include', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 SSI 관련 설정을 확인하지 못했습니다.')],
            'ISMS-WEB-22': [_config_probe_command(apache_conf, r'ErrorDocument', missing_marker='FILE_DEFAULT_BAD|기본 에러 페이지 설정 여부를 확인할 수 없습니다.')],
            'ISMS-WEB-25': ['apache2 -v 2>/dev/null || httpd -v 2>/dev/null || apachectl -v 2>/dev/null'],
        }
        return mapping.get(code, [])

    if platform == 'Nginx':
        mapping = {
            'CSAP-Nginx-01': [_config_probe_command(nginx_conf, r'^[[:space:]]*root[[:space:]]+|^[[:space:]]*alias[[:space:]]+', missing_marker='FILE_DEFAULT_BAD|기본 웹 루트 경로 분리 여부를 확인할 수 없습니다.')],
            'CSAP-Nginx-04': [_config_probe_command(nginx_conf, r'client_max_body_size', missing_marker='FILE_DEFAULT_BAD|기본값은 client_max_body_size 1m 입니다.')],
            'CSAP-Nginx-05': [_config_probe_command(nginx_conf, r'autoindex[[:space:]]+(on|off)', no_match_marker='SETTING_DEFAULT_GOOD|기본값은 autoindex off 입니다.', missing_marker='FILE_DEFAULT_GOOD|기본값은 autoindex off 입니다.')],
            'ISMS-WEB-10': [_config_probe_command(nginx_conf, r'proxy_pass|proxy_set_header|proxy_redirect', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 reverse proxy 지시자가 설정되지 않았습니다.')],
            'ISMS-WEB-16': [_config_probe_command(nginx_conf, r'server_tokens[[:space:]]+(on|off)', no_match_marker='SETTING_DEFAULT_BAD|기본값은 server_tokens on 입니다.', missing_marker='FILE_DEFAULT_BAD|기본값은 server_tokens on 입니다.')],
            'ISMS-WEB-17': [_config_probe_command(nginx_conf, r'^[[:space:]]*alias[[:space:]]+', no_match_marker='SETTING_DEFAULT_GOOD|가상 디렉터리 alias 지시자를 확인하지 못했습니다.')],
            'ISMS-WEB-20': [_config_probe_command(nginx_conf, r'ssl_certificate|listen[[:space:]]+443|ssl_protocols', no_match_marker='SETTING_DEFAULT_BAD|기본값은 SSL/TLS 미활성입니다.', missing_marker='FILE_DEFAULT_BAD|기본값은 SSL/TLS 미활성입니다.')],
            'ISMS-WEB-21': [_config_probe_command(nginx_conf, r'return[[:space:]]+301|rewrite[[:space:]].*https://|error_page[[:space:]]+497', no_match_marker='SETTING_DEFAULT_BAD|기본값은 HTTP 리디렉션 미설정입니다.', missing_marker='FILE_DEFAULT_BAD|기본값은 HTTP 리디렉션 미설정입니다.')],
            'ISMS-WEB-22': [_config_probe_command(nginx_conf, r'error_page[[:space:]]+[0-9]{3}', no_match_marker='SETTING_DEFAULT_BAD|기본 에러 페이지가 일원화되어 있지 않을 수 있습니다.', missing_marker='FILE_DEFAULT_BAD|기본 에러 페이지가 일원화되어 있지 않을 수 있습니다.')],
            'ISMS-WEB-24': [_config_probe_command(nginx_conf, r'client_body_temp_path|location[[:space:]]+/.+upload|alias[[:space:]].+upload|root[[:space:]].+upload')],
        }
        return mapping.get(code, [])

    if platform == 'Tomcat':
        mapping = {
            'CSAP-Tomcat-02': [_config_probe_command(tomcat_users_xml, r'<user[^>]+password=|<role[^>]+manager', missing_marker='FILE_DEFAULT_BAD|기본 관리자 계정 및 비밀번호 정책 적용 여부를 확인할 수 없습니다.')],
            'CSAP-Tomcat-06': [_config_probe_command(tomcat_web_xml, r'<param-name>listings</param-name>|<param-value>false</param-value>', no_match_marker='SETTING_DEFAULT_GOOD|DefaultServlet 기본값은 directory listing 비활성입니다.', missing_marker='FILE_DEFAULT_GOOD|DefaultServlet 기본값은 directory listing 비활성입니다.')],
            'CSAP-Tomcat-08': [_config_probe_command(tomcat_server_xml, r'AccessLogValve|prefix=.*log|directory=.*log', missing_marker='FILE_DEFAULT_BAD|로그 설정 파일을 찾지 못했습니다.')],
            'ISMS-WEB-05': [_config_probe_command(tomcat_web_xml, r'<servlet-name>cgi</servlet-name>|/cgi-bin/\*', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 CGI servlet 매핑이 비활성입니다.', missing_marker='FILE_DEFAULT_GOOD|기본적으로 CGI servlet 매핑이 비활성입니다.')],
            'ISMS-WEB-06': [_config_probe_command(tomcat_server_xml, r'allowLinking', no_match_marker='SETTING_DEFAULT_GOOD|기본값은 allowLinking false 입니다.', missing_marker='FILE_DEFAULT_GOOD|기본값은 allowLinking false 입니다.')],
            'ISMS-WEB-07': [_find_probe_command('${CATALINA_HOME:-/usr/local/tomcat}/webapps', "-maxdepth 2 \\( -name docs -o -name examples -o -name host-manager -o -name manager -o -name ROOT \\)", empty_marker='DEFAULT_GOOD|기본 샘플/예제 웹앱을 찾지 못했습니다.')],
            'ISMS-WEB-08': [
                _config_probe_command(tomcat_server_xml, r'maxPostSize|maxSwallowSize'),
                _config_probe_command(tomcat_web_xml, r'<max-file-size>|<max-request-size>|multipart-config'),
            ],
            'ISMS-WEB-10': [_config_probe_command(tomcat_server_xml, r'proxyName|proxyPort', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 proxyName/proxyPort가 설정되지 않았습니다.')],
            'ISMS-WEB-11': [_config_probe_command(tomcat_server_xml, r'appBase|docBase', missing_marker='FILE_DEFAULT_BAD|기본 appBase/docBase 경로 분리 여부를 확인할 수 없습니다.')],
            'ISMS-WEB-12': [_config_probe_command(tomcat_server_xml, r'allowLinking', no_match_marker='SETTING_DEFAULT_GOOD|기본값은 allowLinking false 입니다.', missing_marker='FILE_DEFAULT_GOOD|기본값은 allowLinking false 입니다.')],
            'ISMS-WEB-15': [_config_probe_command(tomcat_web_xml, r'<servlet-mapping>|<url-pattern>')],
            'ISMS-WEB-16': [_config_probe_command(tomcat_server_xml, r'server=|ErrorReportValve|showServerInfo|xpoweredBy', missing_marker='FILE_DEFAULT_BAD|기본 헤더/오류 페이지 정보 노출 제한 여부를 확인할 수 없습니다.')],
            'ISMS-WEB-17': [_config_probe_command(tomcat_server_xml, r'<Context[^>]+path=', no_match_marker='SETTING_DEFAULT_GOOD|가상 디렉터리 Context path를 확인하지 못했습니다.')],
            'ISMS-WEB-19': [_config_probe_command(tomcat_web_xml, r'SSIServlet|SSIFilter|\.shtml', no_match_marker='SETTING_DEFAULT_GOOD|기본적으로 SSI servlet/filter 매핑이 비활성입니다.', missing_marker='FILE_DEFAULT_GOOD|기본적으로 SSI servlet/filter 매핑이 비활성입니다.')],
        }
        return mapping.get(code, [])

    if platform == 'Node.js':
        if code == 'CSAP-NodeJS-06':
            return [
                _find_probe_command('${NODE_APP_ROOT:-/workspace/docker/test-lab/fixtures/node}', "-maxdepth 2 \\( -name logs -o -name '*.log' \\)", empty_marker='DEFAULT_BAD|로그 파일 또는 로그 디렉터리를 찾지 못했습니다.')
            ]
        return []

    if platform == 'PostgreSQL':
        mapping = {
            'CSAP-PostgreSQL-06': ['run_psql_query "SELECT line_number, type, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;" postgres'],
            'CSAP-PostgreSQL-10': ['run_psql_query "SHOW logging_collector;" postgres', 'run_psql_query "SHOW log_destination;" postgres'],
            'ISMS-D-02': ['run_psql_query "SELECT usename, usesuper, valuntil FROM pg_user ORDER BY usename;" postgres'],
            'ISMS-D-04': ['run_psql_query "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles ORDER BY rolname;" postgres'],
            'ISMS-D-10': ['run_psql_query "SHOW listen_addresses;" postgres', 'run_psql_query "SELECT line_number, type, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;" postgres'],
        }
        return mapping.get(code, [])

    if platform == 'Redis':
        mapping = {
            'CSAP-Redis-01': ['run_redis_cli "CONFIG GET requirepass"', _config_probe_command('${REDIS_CONF:-/etc/redis/redis.conf}', r'^[[:space:]]*requirepass', no_match_marker='SETTING_DEFAULT_BAD|기본값은 인증 비밀번호 미설정입니다.', missing_marker='FILE_DEFAULT_BAD|기본값은 인증 비밀번호 미설정입니다.')],
            'CSAP-Redis-07': ['run_redis_cli "CONFIG GET loglevel"', 'run_redis_cli "CONFIG GET logfile"', _config_probe_command('${REDIS_CONF:-/etc/redis/redis.conf}', r'^[[:space:]]*log(level|file)', no_match_marker='SETTING_DEFAULT_GOOD|기본 loglevel은 notice 입니다.', missing_marker='FILE_DEFAULT_GOOD|기본 loglevel은 notice 입니다.')],
        }
        return mapping.get(code, [])

    if platform == 'MongoDB':
        if code == 'CSAP-MongoDB-06':
            return [
                'run_mongo_query \'db.adminCommand({getCmdLineOpts:1})\' admin',
                _config_probe_command('${MONGOD_CONF:-/etc/mongod.conf}', r'http|rest|bindIp|bindIpAll', no_match_marker='SETTING_DEFAULT_GOOD|MongoDB 7 기본값은 HTTP interface 미사용입니다.', missing_marker='FILE_DEFAULT_GOOD|MongoDB 7 기본값은 HTTP interface 미사용입니다.'),
            ]
        return []

    return []


def escape_bash_string(s):
    """Escape a string for safe use inside bash double-quoted strings."""
    if not s:
        return ''
    # Normalize Unicode smart quotes to ASCII
    s = s.replace('\u201c', '"').replace('\u201d', '"')
    s = s.replace('\u2018', "'").replace('\u2019', "'")
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('$', '\\$')
    s = s.replace('`', '\\`')
    s = s.replace('!', '\\!')
    s = s.replace('\t', ' ')
    # Remove/escape problematic shell chars
    s = s.replace('(', '\\(')
    s = s.replace(')', '\\)')
    # Collapse multiple spaces and newlines
    s = re.sub(r'\n', ' ', s)
    s = re.sub(r'\s{2,}', ' ', s)
    return s.strip()


def escape_ps_string(s):
    """Escape a string for PowerShell."""
    if not s:
        return ''
    s = s.replace('"', '`"')
    s = s.replace('$', '`$')
    s = s.replace('\t', ' ')
    s = re.sub(r'\n', ' ', s)
    s = re.sub(r'\s{2,}', ' ', s)
    return s.strip()


def sanitize_command(cmd):
    """Clean a command extracted from diagnosis text for safe execution in a script."""
    if not cmd:
        return ''
    # Remove dangerous commands entirely
    if re.match(r'^\s*(rm|rmdir|del|format|mkfs|dd)\b', cmd):
        return ''
    cmd = re.sub(r'^[#$]\s+', '', cmd)
    # Replace Korean template placeholders with safe defaults
    cmd = re.sub(r'\[.*?\]', '', cmd)
    # Remove parenthetical Korean annotations like (예시), (생략), (가상스위치 이름)
    cmd = re.sub(r'\([^)]*[\uac00-\ud7a3][^)]*\)', '', cmd)
    # Remove unclosed Korean text at end of command (e.g., "(가상스위치 이름" without closing ")")
    cmd = re.sub(r'\([^)]*[\uac00-\ud7a3].*$', '', cmd)
    # Remove any remaining Korean characters
    cmd = re.sub(r'[\uac00-\ud7a3\u3131-\u3163\u1100-\u11ff]+', '', cmd)
    # Remove inline comments (# followed by content) - but not if # is at very start
    cmd = re.sub(r'\s+#\s+.*$', '', cmd)
    # Remove em-dashes used in Korean docs (–)
    cmd = normalize_dash_text(cmd)
    # Remove embedded double quotes (ASCII and Unicode smart quotes)
    cmd = cmd.replace('"', '')
    cmd = cmd.replace('\u201c', '')  # left double quotation mark "
    cmd = cmd.replace('\u201d', '')  # right double quotation mark "
    cmd = cmd.replace('\u2018', '')  # left single quotation mark '
    cmd = cmd.replace('\u2019', '')  # right single quotation mark '
    # Remove angle bracket template placeholders like <VM_NAME>, < >, etc.
    cmd = re.sub(r'<[^>]*>', '', cmd)
    # Remove stray single quotes
    if cmd.count("'") % 2 != 0:
        cmd = cmd.replace("'", '')
    # Clean up double spaces
    cmd = re.sub(r'\s{2,}', ' ', cmd).strip()
    return cmd


def is_safe_command(cmd):
    """Check if a command is safe to embed in a generated script."""
    if not cmd or len(cmd.strip()) < 3:
        return False
    # Block destructive commands
    if re.match(r'^\s*(rm|rmdir|del|format|mkfs|dd|shutdown|reboot|halt|poweroff|kill|pkill|adduser|useradd|groupadd|usermod|groupmod|passwd|chpasswd)\b', cmd):
        return False
    # Block state-changing or interactive commands
    if re.match(r'^\s*(vi|vim|nano|less|more|systemctl\s+(restart|start|stop|reload|enable|disable|daemon-reload)|service\b.+\b(restart|start|stop|reload)|source|\.)\b', cmd):
        return False
    # Block commands that are just template stubs or redirections
    stripped = cmd.strip()
    if stripped in ('-', '--', '|', '>', '>>', '<'):
        return False
    # Block commands starting with redirection operators
    if re.match(r'^\s*[<>|]', stripped):
        return False
    # Block commands that are just whitespace + symbols
    if not re.search(r'[a-zA-Z]', stripped):
        return False
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return False
    if not tokens:
        return False
    if tokens[0] == 'cat' and len(tokens) == 1:
        return False
    if tokens[0] == 'cat' and len(tokens) > 1 and tokens[1] == '|':
        return False
    if tokens[0] == 'grep':
        non_options = [token for token in tokens[1:] if not token.startswith('-')]
        if '|' not in stripped and len(non_options) < 2:
            return False
    first_token = tokens[0]
    if first_token.startswith('/') and first_token.endswith(('.xml', '.conf', '.cfg', '.ini', '.yaml', '.yml', '.cnf', '.properties', '.txt', '.js', '.jade')):
        return False
    if first_token.endswith(('.xml', '.conf', '.cfg', '.ini', '.yaml', '.yml', '.cnf', '.properties', '.txt', '.js', '.jade')):
        return False
    return True


def make_func_name(code):
    """Convert item code to a valid bash/PS function name."""
    name = code.split('/')[0].strip()
    name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    name = re.sub(r'_+', '_', name).strip('_')
    return f'check_{name}'


# ── Bash check function generation ──────────────────────────────────────────

def generate_bash_check_function(item, app_def):
    """Generate a single check_XX() bash function for an item."""
    code = item['code']
    title = escape_bash_string(item['title'])
    category = escape_bash_string(item['category'])
    importance = item['importance']
    source = escape_bash_string(item['source'])
    remediation_raw = item['remediation']
    remediation = escape_bash_string(remediation_raw)
    diag = item['diagnosis']

    func_name = make_func_name(code)
    extracted_commands = extract_commands_from_diagnosis(diag)
    good_criteria, bad_criteria = extract_good_bad_criteria(diag)

    code_escaped = escape_bash_string(code)

    # Build the check logic
    lines = []
    lines.append(f'# {code}: {item["title"]}')
    lines.append(f'{func_name}() {{')
    lines.append(f'    local status="양호"')
    lines.append(f'    local detail=""')

    # Sanitize extracted commands and adapt app-specific query helpers.
    display_commands = [sanitize_command(c) for c in extracted_commands]
    display_commands = [c for c in display_commands if is_safe_command(c)]
    used_fallback_commands = False
    if not display_commands:
        display_commands = infer_fallback_commands(item, app_def)
        display_commands = [c for c in display_commands if is_safe_command(c)]
        used_fallback_commands = bool(display_commands)
    check_type = classify_check_type(diag, display_commands, item['title'])
    commands = [prepare_command_for_app(c, app_def) for c in display_commands]
    commands = [c for c in commands if is_safe_command(c)]
    if used_fallback_commands:
        if any(cmd.startswith(('run_mysql_query', 'run_psql_query', 'run_mongo_query', 'run_redis_cli', 'run_es_api')) for cmd in commands):
            check_type = 'cli_tool'
        else:
            check_type = 'command_check'

    # Build command string from extracted commands
    if display_commands:
        cmd_str = '; '.join(display_commands[:3])
        cmd_str = escape_bash_string(cmd_str)
    else:
        cmd_str = '수동점검 필요'
    lines.append(f'    local cmd="{cmd_str}"')
    lines.append(f'    local cur_state=""')
    lines.append(f'    local remediation="{remediation}"')
    lines.append('')

    if _generate_special_bash_check(lines, item, diag, commands, good_criteria, bad_criteria, app_def):
        pass
    elif check_type == 'manual':
        if commands and is_safe_command(commands[0]):
            safe_cmd = commands[0]
            lines.append(f'    local output')
            lines.append(f'    output=$( ( {safe_cmd} ) 2>/dev/null || echo "명령 실행 실패")')
            lines.append(f'    cur_state="$output"')
            lines.append('    if printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then')
            lines.append('        local default_text')
            lines.append('        default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^FILE_DEFAULT_GOOD|//p\' | head -1)')
            lines.append('        status="양호"')
            lines.append('        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"')
            lines.append('    elif printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then')
            lines.append('        local default_text')
            lines.append('        default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^FILE_DEFAULT_BAD|//p\' | head -1)')
            lines.append('        status="취약"')
            lines.append('        detail="해당 파일이 없으므로 취약 - ${default_text}"')
            lines.append('    elif printf \'%s\\n\' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then')
            lines.append('        local default_text')
            lines.append('        default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^SETTING_DEFAULT_GOOD|//p\' | head -1)')
            lines.append('        status="양호"')
            lines.append('        detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"')
            lines.append('    elif printf \'%s\\n\' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then')
            lines.append('        local default_text')
            lines.append('        default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^SETTING_DEFAULT_BAD|//p\' | head -1)')
            lines.append('        status="취약"')
            lines.append('        detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"')
            lines.append('    else')
            lines.append(f'        status="수동점검"')
            lines.append(f'        detail="수동 점검 필요 항목입니다. {escape_bash_string(good_criteria)}"')
            lines.append('    fi')
        else:
            lines.append(f'    status="수동점검"')
            lines.append(f'    detail="수동 점검 필요 항목입니다. {escape_bash_string(good_criteria)}"')
            lines.append(f'    cur_state="수동점검 필요"')
    elif check_type == 'file_perm':
        _generate_file_perm_check(lines, item, diag, remediation_raw, commands, good_criteria, app_def)
    elif check_type == 'config_check':
        _generate_config_check(lines, item, diag, commands, good_criteria, bad_criteria, app_def)
    elif check_type == 'service_check':
        _generate_service_check(lines, diag, commands, good_criteria)
    elif check_type == 'api_check':
        _generate_api_check(lines, item, diag, commands, good_criteria, bad_criteria)
    elif check_type == 'cli_tool':
        _generate_cli_check(lines, item, diag, commands, good_criteria, bad_criteria, app_def)
    else:  # command_check
        _generate_command_check(lines, item, diag, commands, good_criteria, bad_criteria)

    lines.append('')
    lines.append(f'    add_result "{code_escaped}" "{category}" "{title}" "{importance}" "$status" "$detail" "{source}" "$cmd" "$cur_state" "$remediation"')
    lines.append(f'}}')
    lines.append('')

    return '\n'.join(lines), func_name


def _generate_special_bash_check(lines, item, diag, commands, good_criteria, bad_criteria, app_def):
    platform = app_def.get('platform', '')
    code = item['code'].split('/')[0].strip()

    if platform == 'MySQL':
        return _generate_mysql_special_check(lines, code)
    if platform == 'MongoDB':
        return _generate_mongodb_observation_check(lines, code, item['title'])
    if platform == 'Redis':
        return _generate_redis_special_check(lines, code)
    if platform == 'Elasticsearch':
        return _generate_elasticsearch_special_check(lines, code)
    return False


def _generate_mysql_special_check(lines, code):
    if code == 'ISMS-D-01':
        lines.append('    cmd="run_mysql_query \\"SELECT user, host, plugin, account_locked, password_expired FROM mysql.user WHERE user = \\\'root\\\';\\""')
        lines.append('    local output')
        lines.append("""    output=$(run_mysql_query "SELECT user, host, plugin, account_locked, password_expired FROM mysql.user WHERE user = 'root';")""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if [ -z "$output" ]; then')
        lines.append('        status="N/A"')
        lines.append('        detail="root 계정 정보를 조회하지 못했습니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | grep -Eiq "root"; then')
        lines.append('        status="수동점검"')
        lines.append('        detail="기본 계정(root) 상태를 수집했습니다. 잠금/비밀번호 정책 변경 여부는 운영 기준 확인이 필요합니다."')
        lines.append('    else')
        lines.append('        status="양호"')
        lines.append('        detail="기본 root 계정을 조회하지 못해 기본 관리자 계정 사용 흔적이 없습니다."')
        lines.append('    fi')
        return True

    if code == 'ISMS-D-02':
        lines.append('    cmd="run_mysql_query \\"SELECT user, host, account_locked FROM mysql.user ORDER BY user, host;\\""')
        lines.append('    local output')
        lines.append("""    output=$(run_mysql_query "SELECT user, host, account_locked FROM mysql.user ORDER BY user, host;")""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if [ -z "$output" ]; then')
        lines.append('        status="N/A"')
        lines.append('        detail="MySQL 계정 목록을 조회하지 못했습니다."')
        lines.append('    else')
        lines.append('        status="수동점검"')
        lines.append('        detail="MySQL 계정 목록과 잠금 상태를 수집했습니다. 불필요 계정 여부는 운영 목적 대조가 필요합니다."')
        lines.append('    fi')
        return True

    if code == 'ISMS-D-04':
        lines.append('    cmd="run_mysql_query \\"SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE privilege_type IN (\\\'SUPER\\\',\\\'SYSTEM_USER\\\',\\\'SYSTEM_VARIABLES_ADMIN\\\',\\\'ROLE_ADMIN\\\',\\\'CREATE USER\\\',\\\'GRANT OPTION\\\') ORDER BY grantee, privilege_type;\\""')
        lines.append('    local output')
        lines.append("""    output=$(run_mysql_query "SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE privilege_type IN ('SUPER','SYSTEM_USER','SYSTEM_VARIABLES_ADMIN','ROLE_ADMIN','CREATE USER','GRANT OPTION') ORDER BY grantee, privilege_type;")""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if [ -z "$output" ]; then')
        lines.append('        status="양호"')
        lines.append('        detail="고위험 관리자 권한이 부여된 계정을 조회하지 못했습니다."')
        lines.append('    else')
        lines.append('        status="수동점검"')
        lines.append('        detail="관리자급 권한 보유 계정을 수집했습니다. 실제 필요 계정인지 운영 정책 확인이 필요합니다."')
        lines.append('    fi')
        return True

    if code == 'ISMS-D-06':
        lines.append('    cmd="run_mysql_query \\"SELECT user, host FROM mysql.user ORDER BY user, host;\\""')
        lines.append('    local output')
        lines.append("""    output=$(run_mysql_query "SELECT user, host FROM mysql.user ORDER BY user, host;")""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if [ -z "$output" ]; then')
        lines.append('        status="N/A"')
        lines.append('        detail="MySQL 계정 정보를 조회하지 못했습니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | awk -F"\\t" \'NF>=2 && $1 != "" {count[$1]++} END {for (k in count) if (count[k] > 1) exit 0; exit 1}\'; then')
        lines.append('        status="양호"')
        lines.append('        detail="동일 사용자명에 대해 host별 개별 계정이 사용 중입니다."')
        lines.append('    else')
        lines.append('        status="수동점검"')
        lines.append('        detail="계정 목록을 수집했습니다. 공용 계정 여부는 실제 사용자 용도 대조가 필요합니다."')
        lines.append('    fi')
        return True

    if code == 'ISMS-D-10':
        lines.append('    cmd="run_mysql_query \\"SELECT user, host FROM mysql.user WHERE host IN (\\\'%\\\',\\\'0.0.0.0\\\',\\\'::\\\') ORDER BY user, host;\\""')
        lines.append('    local output')
        lines.append("""    output=$(run_mysql_query "SELECT user, host FROM mysql.user WHERE host IN ('%','0.0.0.0','::') ORDER BY user, host;")""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if [ -z "$output" ]; then')
        lines.append('        status="양호"')
        lines.append('        detail="모든 원격지(%, 0.0.0.0, ::) 허용 계정을 확인하지 못했습니다."')
        lines.append('    else')
        lines.append('        status="취약"')
        lines.append('        detail="모든 원격지에서 접속 가능한 MySQL 계정이 존재합니다."')
        lines.append('    fi')
        return True

    if code == 'ISMS-D-11':
        lines.append('    cmd="run_mysql_query \\"SELECT grantee, privilege_type FROM information_schema.schema_privileges WHERE table_schema = \\\'mysql\\\' ORDER BY grantee, privilege_type;\\""')
        lines.append('    local output')
        lines.append("""    output=$(run_mysql_query "SELECT grantee, privilege_type FROM information_schema.schema_privileges WHERE table_schema = 'mysql' ORDER BY grantee, privilege_type;")""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if [ -z "$output" ]; then')
        lines.append('        status="양호"')
        lines.append('        detail="mysql 시스템 스키마에 대한 일반 권한을 조회하지 못했습니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | grep -Eiv "^\\\'root\\\'@|mysql\\.sys|mysql\\.session|mysql\\.infoschema" | grep -q .; then')
        lines.append('        status="취약"')
        lines.append('        detail="root 이외 계정에 mysql 시스템 스키마 접근 권한이 부여되어 있습니다."')
        lines.append('    else')
        lines.append('        status="양호"')
        lines.append('        detail="mysql 시스템 스키마 접근 권한이 root 또는 시스템 계정으로 제한됩니다."')
        lines.append('    fi')
        return True

    return False


def _generate_redis_special_check(lines, code):
    if code == 'CSAP-Redis-01':
        lines.append('    cmd="run_redis_cli \\"CONFIG GET requirepass\\"; grep -Ein \\"^[[:space:]]*requirepass\\" ${REDIS_CONF:-/etc/redis/redis.conf}"')
        lines.append('    local output')
        lines.append('    output=$({ ( run_redis_cli "CONFIG GET requirepass" ); ( cfg="${REDIS_CONF:-/etc/redis/redis.conf}"; [ -f "$cfg" ] && grep -Ein "^[[:space:]]*requirepass" "$cfg" 2>/dev/null || echo "FILE_DEFAULT_BAD|기본값은 인증 비밀번호 미설정입니다." ); } 2>/dev/null | sed \'/^$/d\' | head -20)')
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then')
        lines.append('        status="취약"')
        lines.append('        detail="해당 파일이 없으므로 취약 - 기본값은 인증 비밀번호 미설정입니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | grep -Eiq "requirepass[[:space:]]+$|^requirepass$|^[[:space:]]*$"; then')
        lines.append('        status="취약"')
        lines.append('        detail="Redis 인증 비밀번호가 설정되지 않았습니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | grep -Eiq "requirepass"; then')
        lines.append('        status="양호"')
        lines.append('        detail="Redis 인증 비밀번호 설정을 확인했습니다."')
        lines.append('    else')
        lines.append('        status="수동점검"')
        lines.append('        detail="Redis 인증 설정 결과를 수집했습니다. 실제 적용 여부를 확인하십시오."')
        lines.append('    fi')
        return True

    if code == 'CSAP-Redis-07':
        lines.append('    cmd="run_redis_cli \\"CONFIG GET loglevel\\"; run_redis_cli \\"CONFIG GET logfile\\"; grep -Ein \\"^[[:space:]]*log(level|file)\\" ${REDIS_CONF:-/etc/redis/redis.conf}"')
        lines.append('    local output')
        lines.append('    output=$({ ( run_redis_cli "CONFIG GET loglevel" ); ( run_redis_cli "CONFIG GET logfile" ); ( cfg="${REDIS_CONF:-/etc/redis/redis.conf}"; [ -f "$cfg" ] && grep -Ein "^[[:space:]]*log(level|file)" "$cfg" 2>/dev/null || echo "FILE_DEFAULT_GOOD|기본 loglevel은 notice 입니다." ); } 2>/dev/null | sed \'/^$/d\' | head -20)')
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then')
        lines.append('        status="양호"')
        lines.append('        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - 기본 loglevel은 notice 입니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | grep -Eiq "notice|verbose|stdout|/proc/1/fd/1"; then')
        lines.append('        status="양호"')
        lines.append('        detail="Redis 로그 설정을 확인했습니다."')
        lines.append('    else')
        lines.append('        status="수동점검"')
        lines.append('        detail="Redis 로그 설정 결과를 수집했습니다. 보관/백업 정책은 추가 확인이 필요합니다."')
        lines.append('    fi')
        return True

    return False


def _generate_mongodb_observation_check(lines, code, title):
    if code == 'CSAP-MongoDB-01':
        lines.append('    cmd="run_mongo_query \\"db.adminCommand({listDatabases:1})\\" admin; run_mongo_query \\"db.getSiblingDB(...).getCollectionNames()\\" admin"')
        lines.append("    local dbs_output")
        lines.append("    local collections_output")
        lines.append("""    dbs_output=$(run_mongo_query 'db.adminCommand({listDatabases:1}).databases.map(function(x){return x.name;}).join("\\n")' admin)""")
        lines.append("""    collections_output=$(run_mongo_query 'db.adminCommand({listDatabases:1}).databases.filter(function(x){ return ["admin","config","local"].indexOf(x.name) === -1; }).map(function(x){ var cols = db.getSiblingDB(x.name).getCollectionNames(); return x.name + ": " + (cols.length ? cols.join(", ") : "(no collections)"); }).join("\\n")' admin)""")
        lines.append('    cur_state="DBS: ${dbs_output:-조회 실패 또는 결과 없음}"')
        lines.append('    if [ -n "$collections_output" ]; then')
        lines.append('        cur_state="${cur_state} | COLLECTIONS: $collections_output"')
        lines.append('    fi')
        lines.append('    detail="데이터베이스/컬렉션 목록을 수집했습니다. 운영상 불필요 여부는 수동 확인이 필요합니다."')
        lines.append('    status="수동점검"')
        return True

    if code == 'CSAP-MongoDB-02':
        lines.append('    cmd="run_mongo_query \\"db.getSiblingDB(\\\'admin\\\').runCommand({usersInfo:1})\\" admin"')
        lines.append("    local users_output")
        lines.append("""    users_output=$(run_mongo_query 'var users = db.getSiblingDB("admin").runCommand({usersInfo:1}).users || []; users.map(function(u){ return u.user + " => " + (u.roles || []).map(function(r){ return r.role + "@" + r.db; }).join(", "); }).join("\\n")' admin)""")
        lines.append('    cur_state="${users_output:-결과 없음}"')
        lines.append('    detail="MongoDB 계정 목록을 수집했습니다. 불필요 계정 여부는 수동 확인이 필요합니다."')
        lines.append('    status="수동점검"')
        return True

    if code == 'CSAP-MongoDB-03':
        lines.append('    cmd="grep -En \\"authorization|auth\\" ${MONGOD_CONF:-/etc/mongod.conf}"')
        lines.append('    local config_output')
        lines.append('    local active_auth')
        lines.append('    if [ -n "$MONGOD_CONF" ] && [ -f "$MONGOD_CONF" ]; then')
        lines.append('        config_output=$(grep -Ein "authorization|auth" "$MONGOD_CONF" 2>/dev/null | head -20)')
        lines.append('        active_auth=$(grep -Ei "^[[:space:]]*authorization[[:space:]]*:[[:space:]]*enabled|^[[:space:]]*auth[[:space:]]*=[[:space:]]*true" "$MONGOD_CONF" 2>/dev/null | head -5)')
        lines.append('        cur_state="${config_output:-설정 파일에서 관련 항목을 찾지 못함}"')
        lines.append('        if [ -n "$active_auth" ]; then')
        lines.append('            detail="mongod 환경설정 파일에 인증 옵션이 활성화되어 있습니다."')
        lines.append('            status="양호"')
        lines.append('        else')
        lines.append('            detail="mongod 환경설정 파일에서 인증 옵션 활성화를 확인하지 못했습니다."')
        lines.append('            status="취약"')
        lines.append('        fi')
        lines.append('    else')
        lines.append('        cur_state="MongoDB 설정 파일 없음"')
        lines.append('        detail="해당 파일이 없으므로 취약 - MongoDB 기본값은 인증 비활성입니다."')
        lines.append('        status="취약"')
        lines.append('    fi')
        return True

    if code == 'CSAP-MongoDB-04':
        lines.append('    cmd="run_mongo_query \\"db.getSiblingDB(\\\'admin\\\').runCommand({usersInfo:1})\\" admin"')
        lines.append("    local admin_users_output")
        lines.append("""    admin_users_output=$(run_mongo_query 'var users = db.getSiblingDB("admin").runCommand({usersInfo:1}).users || []; users.filter(function(u){ return (u.roles || []).some(function(r){ return ["root","userAdminAnyDatabase","dbAdminAnyDatabase","readWriteAnyDatabase","userAdmin","dbAdmin"].indexOf(r.role) !== -1; }); }).map(function(u){ return u.user + " => " + (u.roles || []).map(function(r){ return r.role + "@" + r.db; }).join(", "); }).join("\\n")' admin)""")
        lines.append('    cur_state="${admin_users_output:-결과 없음}"')
        lines.append('    if [ -n "$admin_users_output" ]; then')
        lines.append('        detail="관리자 권한 계정을 확인했습니다."')
        lines.append('        status="양호"')
        lines.append('    else')
        lines.append('        detail="관리자 권한 계정을 확인하지 못했습니다."')
        lines.append('        status="취약"')
        lines.append('    fi')
        return True

    if code == 'CSAP-MongoDB-06':
        lines.append('    cmd="run_mongo_query \\"db.adminCommand({getCmdLineOpts:1})\\" admin; grep -En \\"http|rest\\" ${MONGOD_CONF:-/etc/mongod.conf}"')
        lines.append('    local output')
        lines.append("""    output=$({ ( run_mongo_query 'db.adminCommand({getCmdLineOpts:1})' admin ); ( cfg="${MONGOD_CONF:-/etc/mongod.conf}"; [ -f "$cfg" ] && grep -Ein "http|rest" "$cfg" 2>/dev/null || echo "FILE_DEFAULT_GOOD|MongoDB 7 기본값은 HTTP interface 미사용입니다." ); } 2>/dev/null | sed '/^$/d' | head -20)""")
        lines.append('    cur_state="${output:-결과 없음}"')
        lines.append('    if printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then')
        lines.append('        status="양호"')
        lines.append('        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - MongoDB 7 기본값은 HTTP interface 미사용입니다."')
        lines.append('    elif printf \'%s\\n\' "$output" | grep -Eiq "rest|http"; then')
        lines.append('        status="취약"')
        lines.append('        detail="MongoDB HTTP interface 관련 설정이 확인되었습니다."')
        lines.append('    else')
        lines.append('        status="양호"')
        lines.append('        detail="MongoDB HTTP interface 관련 설정을 확인하지 못했습니다."')
        lines.append('    fi')
        return True

    if code == 'CSAP-MongoDB-07':
        lines.append('    cmd="grep -En \\"bindIp|bindIpAll\\" ${MONGOD_CONF:-/etc/mongod.conf}"')
        lines.append('    local bind_output')
        lines.append('    if [ -n "$MONGOD_CONF" ] && [ -f "$MONGOD_CONF" ]; then')
        lines.append('        bind_output=$(grep -Ein "bindIp|bindIpAll" "$MONGOD_CONF" 2>/dev/null | head -20)')
        lines.append('        cur_state="${bind_output:-설정 파일에서 관련 항목을 찾지 못함}"')
        lines.append('        if echo "$bind_output" | grep -Eiq "bindIpAll[[:space:]]*:[[:space:]]*true|0\\.0\\.0\\.0"; then')
        lines.append('            detail="MongoDB가 전체 인터페이스에 바인드되어 있습니다."')
        lines.append('            status="취약"')
        lines.append('        elif [ -n "$bind_output" ]; then')
        lines.append('            detail="MongoDB 접근 제한 관련 설정을 수집했습니다."')
        lines.append('            status="양호"')
        lines.append('        else')
        lines.append('            detail="MongoDB 접근 제한 관련 설정을 찾지 못했습니다."')
        lines.append('            status="취약"')
        lines.append('        fi')
        lines.append('    else')
        lines.append('        cur_state="MongoDB 설정 파일 없음"')
        lines.append('        detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - MongoDB 기본 bindIp는 127.0.0.1 입니다."')
        lines.append('        status="양호"')
        lines.append('    fi')
        return True

    if code == 'CSAP-MongoDB-08':
        lines.append('    cmd="grep -En \\"systemLog|path|destination\\" ${MONGOD_CONF:-/etc/mongod.conf}"')
        lines.append('    local log_output')
        lines.append('    if [ -n "$MONGOD_CONF" ] && [ -f "$MONGOD_CONF" ]; then')
        lines.append('        log_output=$(grep -Ein "systemLog|path|destination" "$MONGOD_CONF" 2>/dev/null | head -20)')
        lines.append('        cur_state="${log_output:-설정 파일에서 관련 항목을 찾지 못함}"')
        lines.append('        detail="MongoDB 로그 설정 관련 값을 수집했습니다. 백업 정책 충족 여부는 수동 확인이 필요합니다."')
        lines.append('        status="수동점검"')
        lines.append('    else')
        lines.append('        cur_state="MongoDB 설정 파일 없음"')
        lines.append('        detail="해당 파일이 없으므로 취약 - 기본 로그 설정 및 백업 경로를 확인할 수 없습니다."')
        lines.append('        status="취약"')
        lines.append('    fi')
        return True

    return False


def _generate_elasticsearch_special_check(lines, code):
    if code == 'CSAP-Elasticsearch-04':
        lines.append('    cmd="grep -En \\"network.host|http.host\\" ${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}"')
        lines.append('    local cfg')
        lines.append('    cfg="${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}"')
        lines.append('    if [ -f "$cfg" ]; then')
        lines.append('        local output')
        lines.append('        output=$(grep -Ein "network.host|http.host" "$cfg" 2>/dev/null | head -20)')
        lines.append('        cur_state="${output:-설정 파일에서 관련 항목을 찾지 못함}"')
        lines.append('        if printf \'%s\\n\' "$output" | grep -Eiq "0\\.0\\.0\\.0|::|_site_|_global_"; then')
        lines.append('            status="취약"')
        lines.append('            detail="Elasticsearch가 전체 인터페이스에 바인드되어 있습니다."')
        lines.append('        elif [ -n "$output" ]; then')
        lines.append('            status="양호"')
        lines.append('            detail="Elasticsearch 접근 제한 관련 설정을 수집했습니다."')
        lines.append('        else')
        lines.append('            status="수동점검"')
        lines.append('            detail="network.host/http.host 설정을 찾지 못했습니다. 기본 동작과 운영 환경을 함께 확인해야 합니다."')
        lines.append('        fi')
        lines.append('    else')
        lines.append('        cur_state="Elasticsearch 설정 파일을 찾지 못했습니다."')
        lines.append('        detail="Elasticsearch 설정 파일 경로를 자동으로 확인하지 못했습니다."')
        lines.append('        status="N/A"')
        lines.append('    fi')
        return True

    if code == 'CSAP-Elasticsearch-09':
        lines.append('    cmd="ls -ld ${ES_LOG_DIR:-/usr/share/elasticsearch/logs}; ls ${ES_LOG_DIR:-/usr/share/elasticsearch/logs}/*.log"')
        lines.append('    local log_dir="${ES_LOG_DIR:-/usr/share/elasticsearch/logs}"')
        lines.append('    if [ -d "$log_dir" ]; then')
        lines.append('        local output')
        lines.append('        output=$(ls -1 "$log_dir" 2>/dev/null | head -20)')
        lines.append('        cur_state="${output:-로그 디렉터리 존재}"')
        lines.append('        if printf \'%s\\n\' "$output" | grep -Eiq "\\.log$|gc\\.log"; then')
        lines.append('            status="양호"')
        lines.append('            detail="Elasticsearch 로그 파일이 생성되고 있습니다."')
        lines.append('        else')
        lines.append('            status="수동점검"')
        lines.append('            detail="로그 디렉터리는 존재하지만 Elasticsearch 로그 파일 존재 여부를 추가 확인해야 합니다."')
        lines.append('        fi')
        lines.append('    else')
        lines.append('        cur_state="로그 디렉터리 없음"')
        lines.append('        detail="Elasticsearch 로그 디렉터리를 찾지 못했습니다."')
        lines.append('        status="N/A"')
        lines.append('    fi')
        return True

    return False


def _extract_file_paths(diag, commands):
    """Extract file paths from diagnostic text/commands."""
    paths = []
    normalized_sources = list(commands) + [diag]
    for cmd in normalized_sources:
        cmd = normalize_dash_text(cmd)
        # Look for absolute paths
        for m in re.finditer(r'(/[a-zA-Z0-9_.*./-]+(?:\.\w+)?)', cmd):
            p = m.group(1)
            if len(p) > 4 and not p.startswith('/bin') and not p.startswith('/usr/bin'):
                paths.append(p)
    filtered = []
    low_signal = {
        '/',
        '/etc/app/config',
        '/etc/unknown_config_file',
        '/redis.conf',
        '/elasticsearch.yml',
        '/plugins/search-guard-',
        '/sgconfig',
    }
    for path in paths:
        if path in low_signal:
            continue
        if path.endswith('/redis.conf') and path.count('/') == 1:
            continue
        if path.endswith('/elasticsearch.yml') and path.count('/') == 1:
            continue
        if path not in filtered:
            filtered.append(path)
    return filtered


def _looks_like_placeholder_config_path(path):
    normalized = normalize_dash_text(path).strip()
    config_suffixes = ('.conf', '.cfg', '.ini', '.xml', '.yaml', '.yml', '.cnf', '.properties', '.js', '.cjs', '.mjs', '.ts', '.json', '.log')
    low_signal = {
        '', '/', '/etc/app/config', '/etc/unknown_config_file',
        '/redis.conf', '/elasticsearch.yml', '/postgresql.conf', '/pg_hba.conf',
        '/server.xml', '/web.xml', '/tomcat-users.xml', '/php.ini', '//php.ini',
    }
    if normalized in low_signal:
        return True
    if normalized.startswith('/conf/') or normalized.startswith('/sites-available/'):
        return True
    if normalized.startswith('//') and normalized.count('/') <= 2:
        return True
    if normalized.count('/') == 1 and normalized.endswith(config_suffixes):
        return True
    if '$' not in normalized and '*' not in normalized and not normalized.endswith(config_suffixes):
        return True
    return False


def _infer_config_target(item, diag, commands, app_def):
    platform = app_def.get('platform', '')
    text = normalize_dash_text(f'{item["title"]}\n{diag}\n' + '\n'.join(commands))

    if platform == 'PHP':
        return '${PHP_INI:-/usr/local/etc/php/php.ini}'
    if platform == 'Redis':
        return '${REDIS_CONF:-/etc/redis/redis.conf}'
    if platform == 'MySQL':
        return '${MYSQL_CONF:-/etc/my.cnf}'
    if platform == 'PostgreSQL':
        if any(token in text for token in ('인증 방식', '접근 제한', '접속 제한', 'IP 접근')):
            return '${PG_HBA:-${PG_DATA:-/var/lib/postgresql/data}/pg_hba.conf}'
        return '${PG_CONF:-${PG_DATA:-/var/lib/postgresql/data}/postgresql.conf}'
    if platform == 'MongoDB':
        return '${MONGOD_CONF:-/etc/mongod.conf}'
    if platform == 'Elasticsearch':
        return '${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}'
    if platform == 'Tomcat':
        tomcat_conf_dir = '${CATALINA_HOME:-/usr/local/tomcat}/conf'
        if any(token in text for token in ('관리자 계정', '패스워드 파일', '취약한 패스워드', 'tomcat-users')):
            return f'{tomcat_conf_dir}/tomcat-users.xml'
        if any(token in text for token in ('디렉터리 리스팅', '에러 메시지', '에러 페이지', 'CGI', 'ISAPI', 'SSI', '업로드', '다운로드', '스크립트 매핑')):
            return f'{tomcat_conf_dir}/web.xml'
        return f'{tomcat_conf_dir}/server.xml'
    if platform == 'Apache':
        return '${APACHE_CONF:-/usr/local/apache2/conf/httpd.conf}'
    if platform == 'Nginx':
        return '${NGINX_CONF:-/etc/nginx/nginx.conf}'
    if platform == 'Node.js':
        return '${NODE_MAIN:-app.js}'
    return ''


def _infer_config_grep_pattern(item, diag, commands, app_def):
    platform = app_def.get('platform', '')
    text = normalize_dash_text(f'{item["title"]}\n{diag}').lower()

    if platform == 'PHP':
        if '오류 메시지' in text:
            return '^[[:space:]]*display_errors[[:space:]]*='
        if '헤더 정보' in text:
            return '^[[:space:]]*expose_php[[:space:]]*='
        if 'url 파일 인클루드' in text or '외부 url' in text:
            return 'allow_url_fopen|allow_url_include'
        if '명령어 사용 제한' in text:
            return '^[[:space:]]*disable_functions[[:space:]]*='
        if '실행 경로 제한' in text:
            return '^[[:space:]]*open_basedir[[:space:]]*='

    if platform == 'Redis':
        if '인증 패스워드' in text:
            return '^[[:space:]]*requirepass[[:space:]]+'
        if 'binding' in text or 'bind' in text:
            return '^[[:space:]]*bind[[:space:]]+|^[[:space:]]*protected-mode[[:space:]]+'
        if 'slave 읽기' in text or 'replica' in text:
            return 'replica-read-only|slave-read-only'
        if 'rename-command' in text:
            return 'rename-command[[:space:]]+config'
        if '로그 활성화' in text:
            return 'loglevel|logfile|syslog-enabled'

    if platform == 'MySQL':
        if '로그 활성화' in text:
            return 'general_log|slow_query_log|log_error'
        if '접속 제한' in text:
            return 'bind-address|skip-networking'

    if platform == 'PostgreSQL':
        if 'ip 접근 제한' in text or '접속 제한' in text:
            return '^[[:space:]]*host|^[[:space:]]*hostssl|^[[:space:]]*hostnossl'
        if '인증 방식' in text:
            return 'scram-sha-256|md5|trust|peer|password|ident'
        if '로그 활성화' in text:
            return 'logging_collector|log_destination|log_statement|log_connections|log_disconnections'

    if platform == 'Tomcat':
        if '관리자 계정' in text:
            return '^[[:space:]]*<user|manager-gui|admin-gui|username="(tomcat|admin)"|name="(tomcat|admin)"'
        if '취약한 패스워드' in text:
            return '^[[:space:]]*<user|password='
        if '디렉터리 리스팅' in text:
            return 'listings'
        if '에러 메시지' in text or '에러 페이지' in text:
            return 'error-page'
        if 'cgi' in text or 'isapi' in text:
            return 'cgi'
        if '업로드' in text and '용량' in text:
            return 'maxPostSize|maxSwallowSize'
        if '헤더 정보' in text:
            return 'server=|x-powered-by'
        if '링크 사용 금지' in text:
            return 'allowLinking'
        if '프록시' in text:
            return 'proxyName|proxyPort|scheme'

    if platform == 'Apache':
        if '디렉터리 리스팅' in text:
            return 'Options.*Indexes'
        if 'cgi' in text or 'isapi' in text:
            return 'ScriptAlias|ExecCGI|cgi-script'
        if '헤더 정보' in text:
            return 'ServerTokens|ServerSignature'
        if '프록시' in text:
            return 'ProxyPass|ProxyRequests|ProxyVia'
        if 'webdav' in text:
            return 'Dav[[:space:]]'
        if 'ssl/tls' in text:
            return 'SSLEngine|SSLProtocol|SSLCertificateFile'
        if 'http 리디렉션' in text:
            return 'RewriteRule.*https://|Redirect[[:space:]]+/.*https://'
        if '에러 페이지' in text:
            return 'ErrorDocument'
        if '링크 사용 금지' in text:
            return 'FollowSymLinks|SymLinksIfOwnerMatch'

    if platform == 'Nginx':
        if '디렉터리 리스팅' in text:
            return 'autoindex'
        if '업로드' in text and '용량' in text:
            return 'client_max_body_size'
        if 'cgi' in text or 'isapi' in text:
            return 'fastcgi_pass|uwsgi_pass|scgi_pass'
        if '헤더 정보' in text:
            return 'server_tokens'
        if '프록시' in text:
            return 'proxy_pass|proxy_set_header|proxy_redirect'
        if 'webdav' in text:
            return 'dav_methods'
        if 'ssl/tls' in text:
            return 'ssl_certificate|ssl_protocols|listen[[:space:]].*443'
        if 'http 리디렉션' in text:
            return 'return[[:space:]]+301[[:space:]]+https://|rewrite.*https://'
        if '에러 페이지' in text:
            return 'error_page'
        if '링크 사용 금지' in text:
            return 'disable_symlinks'

    if platform == 'Node.js':
        if '헤더 정보' in text:
            return 'app\\.disable\\([[:space:]]*[\\\"\\\']x-powered-by[\\\"\\\']|helmet\\(|x-powered-by'
        if '오류 메시지' in text:
            return 'errorhandler|stack|render\\([\\\"\\\']error[\\\"\\\']|views/error'
        if '로그 포맷' in text:
            return 'morgan|logger\\('

    return ''


def _extract_perm_info(diag):
    """Extract expected permissions from diagnosis text (e.g., 644, 600, 400)."""
    m = re.search(r'(\d{3})\s*\(', diag)
    if m:
        return m.group(1)
    m = re.search(r'권한이?\s*(\d{3})', diag)
    if m:
        return m.group(1)
    return '644'


def _extract_owner_info(diag):
    """Extract expected owner from diagnosis text."""
    m = re.search(r'소유자가?\s*(root|mysql|postgres|redis|mongod|mongodb|elasticsearch|www-data|apache|nginx|tomcat|ceph|hadoop|nobody|dba)', diag, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    m = re.search(r'chown\s+([a-zA-Z0-9_.-]+)(?::[a-zA-Z0-9_.-]+)?', diag, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return ''


def _infer_permission_targets(item, diag, commands, app_def):
    title = item['title']
    platform = app_def.get('platform', '')
    text = normalize_dash_text(f'{title}\n{diag}\n' + '\n'.join(commands))
    targets = []

    def add(expr):
        if expr and expr not in targets:
            targets.append(expr)

    if platform == 'Redis' and '설정 파일' in text:
        add('${REDIS_CONF:-/etc/redis/redis.conf}')
    if platform == 'Redis' and '데이터 디렉터리' in text:
        add('${REDIS_DATA_DIR:-/data}')

    if platform == 'PostgreSQL':
        if '데이터 디렉터리' in text:
            add('${PG_DATA:-/var/lib/postgresql/data}')
        if '환경설정 파일' in text or '설정 파일' in text:
            add('${PG_CONF:-${PG_DATA:-/var/lib/postgresql/data}/postgresql.conf}')
        if '비밀번호 파일' in text or '인증 방식' in text:
            add('${PG_HBA:-${PG_DATA:-/var/lib/postgresql/data}/pg_hba.conf}')

    if platform == 'MySQL' and ('환경설정 파일' in text or '설정 파일' in text):
        add('${MYSQL_CONF:-/etc/my.cnf}')

    if platform == 'MongoDB':
        if '실행 파일' in text or '주요 실행 및 설정 파일' in text:
            add('$(command -v mongod 2>/dev/null)')
        if '설정 파일' in text or '주요 실행 및 설정 파일' in text:
            add('${MONGOD_CONF:-/etc/mongod.conf}')

    if platform == 'Elasticsearch':
        es_home = '$(dirname "$(dirname "${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}")")'
        if '설정 파일' in text:
            add('${ES_CONF:-/usr/share/elasticsearch/config/elasticsearch.yml}')
        if '설치 디렉터리' in text:
            add(es_home)
        if '플러그인 디렉터리' in text:
            add(f'{es_home}/plugins')
        if 'search-guard' in text:
            add(f'{es_home}/plugins/search-guard-*/tools')

    if platform == 'Apache':
        if '설정 파일' in text:
            add('${APACHE_CONF:-/etc/apache2/apache2.conf}')
        if '로그 디렉터리' in text:
            add('/var/log/apache2')
            add('/usr/local/apache2/logs')

    if platform == 'Nginx':
        if '설정 파일' in text:
            add('${NGINX_CONF:-/etc/nginx/nginx.conf}')
        if '로그 디렉터리' in text:
            add('/var/log/nginx')

    if platform == 'PHP' and ('환경설정 파일' in text or '설정 파일' in text):
        add('${PHP_INI:-/usr/local/etc/php/php.ini}')

    if platform == 'Tomcat':
        tomcat_home = '${CATALINA_HOME:-/usr/local/tomcat}'
        if '패스워드 파일' in text or '관리자 계정' in text:
            add(f'{tomcat_home}/conf/tomcat-users.xml')
        if '홈 디렉터리' in text:
            add(tomcat_home)
        if '환경 설정 파일' in text or '설정 파일' in text:
            add(f'{tomcat_home}/conf/server.xml')
            add(f'{tomcat_home}/conf/web.xml')
        if '로그 디렉터리' in text:
            add(f'{tomcat_home}/logs')

    if platform == 'Node.js' and '로그 디렉터리' in text:
        add('${NODE_APP_ROOT:-/workspace}/logs')
        add('${NODE_APP_ROOT:-/workspace}/log')

    if platform == 'Kubernetes(Master)' and '권한' in text:
        add('/etc/kubernetes/manifests/kube-apiserver.yaml')
        add('/etc/kubernetes/manifests/kube-controller-manager.yaml')
        add('/etc/kubernetes/manifests/kube-scheduler.yaml')
        add('/etc/kubernetes/manifests/etcd.yaml')
        add('/etc/kubernetes/admin.conf')
        add('/etc/kubernetes/scheduler.conf')
        add('/etc/kubernetes/controller-manager.conf')

    if platform == 'Kubernetes(Worker)' and '권한' in text:
        add('/etc/kubernetes/kubelet.conf')
        add('/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf')
        add('/var/lib/kubelet/config.yaml')

    return targets


def _generate_file_perm_check(lines, item, diag, remediation, commands, good_criteria, app_def):
    """Generate file permission check logic."""
    paths = _extract_file_paths(diag, commands)
    inferred_targets = _infer_permission_targets(item, diag, commands, app_def)
    expected_perm = _extract_perm_info(f'{diag}\n{remediation}')
    expected_owner = _extract_owner_info(f'{diag}\n{remediation}')
    posix_append = app_def.get('esxi', False)

    target_specs = []
    for path in paths[:5]:
        if '[' in path or '디렉' in path:
            continue
        target_specs.append(path)
    for path in inferred_targets:
        if path not in target_specs:
            target_specs.append(path)
    if not target_specs:
        target_specs = ['/etc/unknown_config_file']

    lines.append('    local vuln_found=false')
    lines.append('    local checked_any=false')
    lines.append('    local missing_only=true')
    for idx, spec in enumerate(target_specs[:6], start=1):
        lines.append(f'    local target_spec_{idx}')
        lines.append(f'    target_spec_{idx}={spec}')
        lines.append(f'    local resolved_target_{idx}')
        lines.append(f'    resolved_target_{idx}="$target_spec_{idx}"')
        lines.append(f'    if [ -n "$resolved_target_{idx}" ]; then')
        lines.append(f'        for target_path in $resolved_target_{idx}; do')
        lines.append('            [ -z "$target_path" ] && continue')
        lines.append('            checked_any=true')
        lines.append('            if [ -e "$target_path" ]; then')
        lines.append('                missing_only=false')
        lines.append(f'                local result_{idx}')
        lines.append(f'                result_{idx}=$(check_file_owner_perm "$target_path" "{expected_owner}" "{expected_perm}")')
        if posix_append:
            lines.append(f'                cur_state="${{cur_state}}$target_path: $result_{idx}; "')
        else:
            lines.append(f'                cur_state+="$target_path: $result_{idx}; "')
        lines.append(f'                case "$result_{idx}" in')
        if expected_owner:
            if posix_append:
                lines.append(f'                    VULN*) vuln_found=true; detail="${{detail}}$target_path 소유자/권한 부적절($result_{idx}). " ;;')
                lines.append(f'                    GOOD*) detail="${{detail}}$target_path 소유자/권한 적절($result_{idx}). " ;;')
            else:
                lines.append(f'                    VULN*) vuln_found=true; detail+="$target_path 소유자/권한 부적절($result_{idx}). " ;;')
                lines.append(f'                    GOOD*) detail+="$target_path 소유자/권한 적절($result_{idx}). " ;;')
        else:
            if posix_append:
                lines.append(f'                    VULN*) vuln_found=true; detail="${{detail}}$target_path 권한 부적절($result_{idx}). " ;;')
                lines.append(f'                    GOOD*) detail="${{detail}}$target_path 권한 적절($result_{idx}). " ;;')
            else:
                lines.append(f'                    VULN*) vuln_found=true; detail+="$target_path 권한 부적절($result_{idx}). " ;;')
                lines.append(f'                    GOOD*) detail+="$target_path 권한 적절($result_{idx}). " ;;')
        if posix_append:
            lines.append(f'                    NOT_FOUND) detail="${{detail}}$target_path 파일 없음. " ;;')
        else:
            lines.append(f'                    NOT_FOUND) detail+="$target_path 파일 없음. " ;;')
        lines.append('                esac')
        lines.append('            else')
        if posix_append:
            lines.append(f'                detail="${{detail}}$target_path 파일 없음. "')
            lines.append(f'                cur_state="${{cur_state}}$target_path: 파일 없음; "')
        else:
            lines.append(f'                detail+="$target_path 파일 없음. "')
            lines.append(f'                cur_state+="$target_path: 파일 없음; "')
        lines.append('            fi')
        lines.append('        done')
        lines.append('    fi')
    lines.append('    if [ "$vuln_found" = "true" ]; then')
    lines.append('        status="취약"')
    lines.append('    elif [ "$checked_any" = "false" ]; then')
    lines.append('        status="수동점검"')
    lines.append('        detail="점검 대상 파일 경로를 자동으로 해석하지 못했습니다. "')
    lines.append('        cur_state="경로 자동 해석 실패"')
    lines.append('    elif [ "$missing_only" = "true" ]; then')
    lines.append('        status="N/A"')
    lines.append('    fi')
    lines.append(f'    [ -z "$detail" ] && detail="{escape_bash_string(good_criteria)}" && cur_state="점검 대상 파일 없음"')


def _append_bash_output_capture(lines, commands):
    lines.append('    local output')
    lines.append('    output=$({')
    for cmd in commands[:3]:
        lines.append(f'        ( {cmd} )')
    lines.append("    } 2>/dev/null | sed '/^$/d' | head -20)")
    lines.append('    cur_state="$output"')
    lines.append('')


def _append_bash_auto_decision(lines, item, diag, commands, good_criteria, bad_criteria, *, empty_status='auto'):
    title = item['title']
    criteria_text = '\n'.join(filter(None, [good_criteria, bad_criteria, diag, title]))
    signal = infer_criteria_signal(criteria_text)
    threshold = infer_numeric_threshold(good_criteria, bad_criteria, diag, title, default='')
    direction = infer_numeric_direction(good_criteria, bad_criteria, diag, title)
    kind = infer_special_auto_decision_kind(title, diag, ' '.join(commands))
    requires_production = 'production' in normalize_dash_text(f'{title}\n{diag}').lower()

    if kind == 'account_lock':
        if any(token in normalize_dash_text(f'{title}\n{diag}').lower() for token in ('기간', 'duration', 'reset', '원래대로')):
            direction = 'min'
        elif direction == 'unknown':
            direction = 'max'
    elif kind == 'timeout' and direction == 'unknown':
        direction = 'max'
    elif kind == 'umask' and direction == 'unknown':
        direction = 'min'

    good_text = escape_bash_string(good_criteria or f'{title} 기준을 충족합니다.')
    bad_text = escape_bash_string(bad_criteria or f'{title} 기준을 충족하지 않습니다.')
    manual_text = escape_bash_string(good_criteria or bad_criteria or f'{title} 항목은 수동 확인이 필요합니다.')

    lines.append('    if [ -z "$output" ]; then')
    if empty_status == 'na':
        lines.append('        status="N/A"')
        lines.append('        detail="명령 실행 결과 없음 또는 대상 미설치. "')
    elif signal == 'absence':
        lines.append('        status="양호"')
        lines.append(f'        detail="{good_text}"')
    elif signal == 'presence':
        lines.append('        status="취약"')
        lines.append(f'        detail="{bad_text}"')
    else:
        lines.append('        status="수동점검"')
        lines.append(f'        detail="{manual_text}"')
    lines.append('    else')
    lines.append('        if printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_GOOD|"; then')
    lines.append('            local default_text')
    lines.append('            default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^FILE_DEFAULT_GOOD|//p\' | head -1)')
    lines.append('            status="양호"')
    lines.append('            detail="해당 파일이 없으므로 기본값 설정에 의해 양호 - ${default_text}"')
    lines.append('        elif printf \'%s\\n\' "$output" | grep -q "^FILE_DEFAULT_BAD|"; then')
    lines.append('            local default_text')
    lines.append('            default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^FILE_DEFAULT_BAD|//p\' | head -1)')
    lines.append('            status="취약"')
    lines.append('            detail="해당 파일이 없으므로 취약 - ${default_text}"')
    lines.append('        elif printf \'%s\\n\' "$output" | grep -q "^SETTING_DEFAULT_GOOD|"; then')
    lines.append('            local default_text')
    lines.append('            default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^SETTING_DEFAULT_GOOD|//p\' | head -1)')
    lines.append('            status="양호"')
    lines.append('            detail="설정이 명시되지 않아 기본값 설정에 의해 양호 - ${default_text}"')
    lines.append('        elif printf \'%s\\n\' "$output" | grep -q "^SETTING_DEFAULT_BAD|"; then')
    lines.append('            local default_text')
    lines.append('            default_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^SETTING_DEFAULT_BAD|//p\' | head -1)')
    lines.append('            status="취약"')
    lines.append('            detail="설정이 명시되지 않아 기본값 설정에 의해 취약 - ${default_text}"')
    lines.append('        elif printf \'%s\\n\' "$output" | grep -q "^FILE_MISSING|"; then')
    lines.append('            local missing_text')
    lines.append('            missing_text=$(printf \'%s\\n\' "$output" | sed -n \'s/^FILE_MISSING|//p\' | head -1)')
    lines.append('            status="수동점검"')
    lines.append('            detail="설정 파일이 없어 기본값 판정을 확정하지 못했습니다. ${missing_text}"')
    lines.append('        else')

    if kind == 'manual_review':
        lines.append('        status="수동점검"')
        lines.append('        detail="명령 결과는 수집했지만 운영 정책/최신 기준 대조가 필요합니다. "')
    elif kind == 'permit_root_login':
        lines.append('        if printf \'%s\\n\' "$output" | grep -Eiq "permitrootlogin[[:space:]]+yes|^[[:space:]]*yes([[:space:]]|$)"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        elif output_has_negative_marker "$output"; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        else')
        lines.append('            status="수동점검"')
        lines.append(f'            detail="{manual_text}"')
        lines.append('        fi')
    elif kind == 'path_dot':
        lines.append('        if printf \'%s\\n\' "$output" | grep -Eq "(^|[:=])\\.(:|$)"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        else')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        fi')
    elif kind == 'account_lock':
        lines.append('        local numeric_value')
        lines.append('        numeric_value=$(first_numeric_value "$output")')
        lines.append('        if [ -z "$numeric_value" ]; then')
        lines.append('            status="수동점검"')
        lines.append(f'            detail="{manual_text}"')
        lines.append('        else')
        if threshold:
            if direction == 'min':
                lines.append(f'            if [ "$numeric_value" -ge {threshold} ] 2>/dev/null; then')
            else:
                lines.append(f'            if [ "$numeric_value" -le {threshold} ] 2>/dev/null; then')
            lines.append('                status="양호"')
            lines.append(f'                detail="{good_text}"')
            lines.append('            else')
            lines.append('                status="취약"')
            lines.append(f'                detail="{bad_text}"')
            lines.append('            fi')
        else:
            lines.append('            status="수동점검"')
            lines.append(f'            detail="{manual_text}"')
        lines.append('        fi')
    elif kind == 'timeout':
        lines.append('        local numeric_value')
        lines.append('        numeric_value=$(first_numeric_value "$output")')
        lines.append('        if [ -z "$numeric_value" ] || [ "$numeric_value" -eq 0 ] 2>/dev/null; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        else')
        if threshold:
            lines.append(f'            if [ "$numeric_value" -le {threshold} ] 2>/dev/null; then')
            lines.append('                status="양호"')
            lines.append(f'                detail="{good_text}"')
            lines.append('            else')
            lines.append('                status="취약"')
            lines.append(f'                detail="{bad_text}"')
            lines.append('            fi')
        else:
            lines.append('            status="양호"')
            lines.append(f'            detail="{good_text}"')
        lines.append('        fi')
    elif kind == 'umask':
        lines.append('        local numeric_value')
        lines.append('        numeric_value=$(printf \'%s\\n\' "$output" | grep -Eo "[0-7]{3}" | head -1)')
        lines.append('        if [ -z "$numeric_value" ]; then')
        lines.append('            status="수동점검"')
        lines.append(f'            detail="{manual_text}"')
        lines.append('        else')
        if threshold:
            lines.append(f'            if [ $((8#$numeric_value)) -ge $((8#{threshold})) ] 2>/dev/null; then')
            lines.append('                status="양호"')
            lines.append(f'                detail="{good_text}"')
            lines.append('            else')
            lines.append('                status="취약"')
            lines.append(f'                detail="{bad_text}"')
            lines.append('            fi')
        else:
            lines.append('            status="수동점검"')
            lines.append(f'            detail="{manual_text}"')
        lines.append('        fi')
    elif kind == 'uid_zero':
        lines.append('        local uid_zero_count')
        lines.append('        uid_zero_count=$(printf \'%s\\n\' "$output" | grep -Ec "^[^:]+:[^:]*:0:|uid=0")')
        lines.append('        if [ "${uid_zero_count:-0}" -le 1 ] 2>/dev/null; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        else')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        fi')
    elif kind == 'docker_group':
        lines.append('        local docker_members')
        lines.append('        docker_members=$(printf \'%s\\n\' "$output" | awk -F: \'/docker/ {gsub(/[[:space:]]/, "", $NF); print $NF; exit}\')')
        lines.append('        if [ -z "$docker_members" ] || [ "$docker_members" = "root" ]; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        else')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        fi')
    elif kind == 'root_process':
        lines.append('        if printf \'%s\\n\' "$output" | awk \'NR == 1 && $1 == "UID" {next} $1 == "root" {found=1} END {exit found ? 0 : 1}\'; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        elif printf \'%s\\n\' "$output" | grep -Eiq "production|node_env|environment=production|user[[:space:]]*=[[:space:]]*[a-z0-9_-]+"; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        else')
        if requires_production:
            lines.append('            status="수동점검"')
            lines.append('            detail="비root 구동 여부는 확인했지만 production 모드 여부 자동 판정에는 추가 문맥이 필요합니다. "')
        else:
            lines.append('            status="양호"')
            lines.append(f'            detail="{good_text}"')
        lines.append('        fi')
    elif kind == 'header_exposure':
        lines.append('        if printf \'%s\\n\' "$output" | grep -Eiq "app\\.disable\\([[:space:]]*[\\\"\\\']x-powered-by[\\\"\\\']|helmet\\(|server_tokens[[:space:]]+off|servertokens[[:space:]]+prod|serversignature[[:space:]]+off|expose_php[[:space:]]*=[[:space:]]*off"; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        elif printf \'%s\\n\' "$output" | grep -Eiq "x-powered-by|server_tokens[[:space:]]+on|expose_php[[:space:]]*=[[:space:]]*on"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        else')
        lines.append('            status="수동점검"')
        lines.append(f'            detail="{manual_text}"')
        lines.append('        fi')
    elif kind == 'boolean_zero_good':
        lines.append('        if output_has_negative_marker "$output"; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        elif output_has_positive_marker "$output"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        else')
        lines.append('            status="수동점검"')
        lines.append(f'            detail="{manual_text}"')
        lines.append('        fi')
    elif kind == 'hash_algo':
        lines.append('        if printf \'%s\\n\' "$output" | grep -Eiq "md5|mysql_native_password|old_password|sha1"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        elif printf \'%s\\n\' "$output" | grep -Eiq "sha-?256|caching_sha2_password|scram-sha-256|scram_sha_256"; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        else')
        lines.append('            status="수동점검"')
        lines.append(f'            detail="{manual_text}"')
        lines.append('        fi')
    elif signal == 'absence':
        lines.append('        if output_has_negative_marker "$output"; then')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        elif output_has_positive_marker "$output"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        else')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        fi')
    elif signal == 'presence':
        lines.append('        if output_has_negative_marker "$output"; then')
        lines.append('            status="취약"')
        lines.append(f'            detail="{bad_text}"')
        lines.append('        else')
        lines.append('            status="양호"')
        lines.append(f'            detail="{good_text}"')
        lines.append('        fi')
    else:
        lines.append('        status="수동점검"')
        lines.append(f'        detail="{manual_text}"')
    lines.append('        fi')
    lines.append('    fi')
    lines.append('    [ -n "$output" ] && [ -n "$(summarize_output "$output")" ] && detail="${detail} 결과: $(summarize_output "$output")"')


def _generate_config_check(lines, item, diag, commands, good_criteria, bad_criteria, app_def):
    """Generate configuration file check logic."""
    # Try to extract config file and grep pattern from commands
    config_file = ''
    grep_pattern = ''
    for cmd in commands:
        # Extract config file from grep or cat commands
        m = re.search(r'(?:cat|grep)\s+.*?(/[a-zA-Z0-9_./-]+(?:\.conf|\.cfg|\.ini|\.xml|\.yaml|\.yml|\.properties|\.cnf))', cmd)
        if m:
            config_file = m.group(1)
        # Alternate: grep pattern + file
        m2 = re.search(r'grep\s+(?:-[iEP]\s+)?[\'"]?([^\'"]+?)[\'"]?\s+(/[^\s]+)', cmd)
        if m2:
            grep_pattern = m2.group(1)
            config_file = config_file or m2.group(2)
        m3 = re.search(r'cat\s+.*?\|\s*grep\s+(?:-[iEP]\s+)?(.+)', cmd)
        if m3:
            grep_pattern = m3.group(1).strip().strip("'\"")

    if not grep_pattern:
        grep_pattern = _infer_config_grep_pattern(item, diag, commands, app_def)

    inferred_target = _infer_config_target(item, diag, commands, app_def)
    if not config_file:
        paths = _extract_file_paths(diag, commands)
        config_file = paths[0] if paths else ''
    if _looks_like_placeholder_config_path(config_file):
        config_file = inferred_target or config_file
    elif not config_file and inferred_target:
        config_file = inferred_target

    # Clean up template paths and Korean text
    config_file_clean = re.sub(r'\[.*?\]', '*', config_file)
    config_file_clean = re.sub(r'[^\x00-\x7F*]', '', config_file_clean)  # remove non-ASCII
    config_file_clean = config_file_clean.strip()
    if not config_file_clean or config_file_clean == '*':
        config_file_clean = inferred_target or '/etc/app/config'

    config_file_lower = config_file_clean.lower()
    config_env_var = ''
    if 'php.ini' in config_file_lower:
        config_env_var = 'PHP_INI'
    elif 'redis.conf' in config_file_lower:
        config_env_var = 'REDIS_CONF'
    elif 'pg_hba.conf' in config_file_lower:
        config_env_var = 'PG_HBA'
    elif 'postgresql.conf' in config_file_lower:
        config_env_var = 'PG_CONF'
    elif 'mongod.conf' in config_file_lower:
        config_env_var = 'MONGOD_CONF'
    elif 'elasticsearch.yml' in config_file_lower:
        config_env_var = 'ES_CONF'
    elif 'my.cnf' in config_file_lower or '/mysql/' in config_file_lower:
        config_env_var = 'MYSQL_CONF'
    elif any(token in config_file_lower for token in ('nginx.conf', '/nginx/')):
        config_env_var = 'NGINX_CONF'
    elif any(token in config_file_lower for token in ('httpd.conf', 'apache2.conf', '/apache', '/httpd/')):
        config_env_var = 'APACHE_CONF'

    lines.append(f'    local config_file="{config_file_clean}"')
    if config_env_var:
        lines.append(f'    [ -n "${{{config_env_var}:-}}" ] && config_file="${{{config_env_var}}}"')
    lines.append(f'    # Expand wildcards/find actual config')
    lines.append(f'    local actual_config')
    lines.append(f'    actual_config=$(ls $config_file 2>/dev/null | head -1)')
    if inferred_target and inferred_target != config_file_clean:
        inferred_target_safe = inferred_target.replace('"', '\\"')
        lines.append(f'    if [ -z "$actual_config" ]; then')
        lines.append(f'        actual_config=$(ls {inferred_target_safe} 2>/dev/null | head -1)')
        lines.append(f'        [ -n "$actual_config" ] && config_file="{inferred_target_safe}"')
        lines.append(f'    fi')
    lines.append(f'    if [ -z "$actual_config" ]; then')
    lines.append(f'        detail="설정 파일 없음($config_file). "')
    lines.append(f'        cur_state="설정 파일 없음"')
    lines.append(f'        status="N/A"')
    lines.append(f'    else')
    if grep_pattern:
        grep_safe = escape_bash_string(grep_pattern)
        lines.append(f'        local grep_result')
        lines.append(f'        grep_result=$(grep -Ei "{grep_safe}" "$actual_config" 2>/dev/null)')
        lines.append(f'        output="$grep_result"')
        lines.append(f'        cur_state="$grep_result"')
        _append_bash_auto_decision(lines, item, diag, commands, good_criteria, bad_criteria)
    else:
        # Just check file exists and report content
        lines.append(f'        local content')
        lines.append(f'        content=$(head -20 "$actual_config" 2>/dev/null)')
        lines.append(f'        cur_state="설정 파일 존재: $actual_config"')
        lines.append(f'        detail="설정 파일 확인 필요: $actual_config. "')
        lines.append(f'        status="수동점검"')
    lines.append(f'    fi')


def _generate_service_check(lines, diag, commands, good_criteria):
    """Generate service status check logic."""
    service_name = ''
    for cmd in commands:
        if 'systemctl' in cmd:
            units = re.findall(r'([A-Za-z0-9_.@-]+\.(?:service|socket|timer|target))', cmd)
            if units:
                service_name = units[-1]
                break
        m2 = re.search(r'service\s+([\w.-]+)\s+status', cmd)
        if m2:
            service_name = m2.group(1)
            break
    if not service_name:
        m = re.search(r'ps\s+.*?grep\s+(\w+)', ' '.join(commands))
        if m:
            service_name = m.group(1)

    if service_name:
        lines.append(f'    local svc_status')
        lines.append(f'    svc_status=$(is_service_active "{service_name}")')
        lines.append(f'    cur_state="{service_name}=$svc_status"')
        # Determine if service should be active or inactive based on criteria
        if '비활성' in diag or '중지' in diag or '사용하지 않' in diag:
            lines.append(f'    if [ "$svc_status" = "active" ]; then')
            lines.append(f'        detail="{service_name} 서비스 활성화 상태. "')
            lines.append(f'        status="취약"')
            lines.append(f'    else')
            lines.append(f'        detail="{service_name} 서비스 비활성화 상태. "')
            lines.append(f'    fi')
        else:
            lines.append(f'    if [ "$svc_status" = "active" ]; then')
            lines.append(f'        detail="{service_name} 서비스 활성화 상태. "')
            lines.append(f'    else')
            lines.append(f'        detail="{service_name} 서비스 비활성화 상태. "')
            lines.append(f'        status="취약"')
            lines.append(f'    fi')
    else:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="서비스 상태 수동 확인 필요. {escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')


def _generate_api_check(lines, item, diag, commands, good_criteria, bad_criteria):
    """Generate API/curl-based check logic."""
    curl_cmd = ''
    for cmd in commands:
        if 'curl' in cmd:
            curl_cmd = cmd
            break
    if curl_cmd:
        _append_bash_output_capture(lines, [curl_cmd])
        _append_bash_auto_decision(lines, item, diag, [curl_cmd], good_criteria, bad_criteria, empty_status='na')
    else:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="API 기반 점검 항목. {escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')


def _generate_cli_check(lines, item, diag, commands, good_criteria, bad_criteria, app_def):
    """Generate CLI tool-specific check logic (docker, kubectl, virsh, etc)."""
    safe_commands = [c for c in commands if is_safe_command(c)]
    if not safe_commands:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="{escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')
        return

    _append_bash_output_capture(lines, safe_commands)
    _append_bash_auto_decision(lines, item, diag, safe_commands, good_criteria, bad_criteria, empty_status='na')


def _generate_command_check(lines, item, diag, commands, good_criteria, bad_criteria):
    """Generate generic command execution check."""
    safe_commands = [c for c in commands if is_safe_command(c)]
    if not safe_commands:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="{escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')
        return

    _append_bash_output_capture(lines, safe_commands)
    _append_bash_auto_decision(lines, item, diag, safe_commands, good_criteria, bad_criteria)


# ── PowerShell check function generation ─────────────────────────────────────

def generate_ps_check_function(item):
    """Generate a single Check-XX PowerShell function for an item."""
    code = item['code']
    title = escape_ps_string(item['title'])
    category = escape_ps_string(item['category'])
    importance = item['importance']
    source = escape_ps_string(item['source'])
    remediation = escape_ps_string(item['remediation'])
    diag = item['diagnosis']

    func_name = make_func_name(code).replace('check_', 'Check-')
    commands = extract_commands_from_diagnosis(diag)
    good_criteria, bad_criteria = extract_good_bad_criteria(diag)

    code_escaped = escape_ps_string(code)

    lines = []
    lines.append(f'# {code}: {item["title"]}')
    lines.append(f'function {func_name} {{')
    lines.append(f'    $status = "양호"')
    lines.append(f'    $detail = ""')

    # Extract Windows-specific commands from diagnosis
    ps_commands = _extract_windows_commands(diag)

    if ps_commands:
        cmd_str = escape_ps_string('; '.join(ps_commands[:3]))
    else:
        cmd_str = '수동점검 필요'
    lines.append(f'    $cmd = "{cmd_str}"')
    lines.append(f'    $curState = ""')
    lines.append(f'    $remediation = "{remediation}"')
    lines.append('')

    # Generate Windows-specific check logic
    _generate_windows_check_logic(lines, diag, ps_commands, good_criteria, bad_criteria, item)

    lines.append('')
    lines.append(f'    Add-Result -Code "{code_escaped}" -Category "{category}" -Title "{title}" `')
    lines.append(f'        -Importance "{importance}" -Status $status -Detail $detail `')
    lines.append(f'        -Source "{source}" -Command $cmd -CurrentState $curState `')
    lines.append(f'        -Remediation $remediation')
    lines.append(f'}}')
    lines.append('')

    return '\n'.join(lines), func_name


def _extract_windows_commands(diag):
    """Extract Windows CLI commands from diagnosis text."""
    commands = []
    for line in diag.split('\n'):
        stripped = line.strip()
        if stripped.startswith('[') or stripped.startswith('※'):
            continue
        inline_cmd = extract_inline_command(stripped)
        if inline_cmd and any(keyword in inline_cmd.lower() for keyword in (
            'secedit', 'net user', 'net accounts', 'net localgroup administrators',
            'net share', 'wmic', 'auditpol', 'fsutil', 'reg query', 'sc query',
            'netstat', 'winver', 'systeminfo', 'icacls', 'netsh', 'schtasks'
        )):
            commands.append(inline_cmd)

    deduped = []
    for cmd in commands:
        if cmd not in deduped:
            deduped.append(cmd)
    return deduped


def _generate_windows_check_logic(lines, diag, commands, good_criteria, bad_criteria, item):
    """Generate Windows PowerShell check logic."""
    diag_lower = diag.lower()

    # Categorize Windows checks
    if 'secedit' in diag_lower:
        _gen_windows_secedit_check(lines, diag, commands, good_criteria, bad_criteria, item)
    elif any(token in diag_lower for token in ('net user', 'net accounts', 'net localgroup', 'net share')):
        _gen_windows_net_check(lines, diag, commands, good_criteria, bad_criteria, item)
    elif 'auditpol' in diag_lower:
        _gen_windows_audit_check(lines, diag, commands, good_criteria)
    elif 'reg query' in diag_lower or 'hklm' in diag_lower or 'hkey' in diag_lower:
        _gen_windows_registry_check(lines, diag, commands, good_criteria)
    elif 'sc query' in diag_lower or 'get-service' in diag_lower or '서비스' in diag_lower:
        _gen_windows_service_check(lines, diag, commands, good_criteria)
    elif commands:
        # Generic command execution
        lines.append(f'    try {{')
        cmd_safe = escape_ps_string(commands[0])
        lines.append(f'        $output = Invoke-Expression "{cmd_safe}" 2>$null')
        lines.append(f'        $curState = $output | Out-String')
        lines.append(f'        $summary = Get-OutputSummary ($curState)')
        lines.append(f'        if ([string]::IsNullOrWhiteSpace($summary)) {{')
        lines.append(f'            $status = "N/A"')
        lines.append(f'            $detail = "명령 실행 결과 없음 또는 대상 미설치."')
        lines.append(f'        }} elseif (Test-NegativeMarker $summary) {{')
        lines.append(f'            $status = "양호"')
        lines.append(f'            $detail = "{escape_ps_string(good_criteria)}"')
        lines.append(f'        }} elseif (Test-PositiveMarker $summary) {{')
        lines.append(f'            $status = "취약"')
        lines.append(f'            $detail = "{escape_ps_string(bad_criteria)}"')
        lines.append(f'        }} else {{')
        lines.append(f'            $detail = "명령 실행 결과 확인. 추가 수동 검증 필요."')
        lines.append(f'            $status = "수동점검"')
        lines.append(f'        }}')
        lines.append(f'    }} catch {{')
        lines.append(f'        $curState = "명령 실행 실패: $_"')
        lines.append(f'        $detail = "점검 명령 실행 실패."')
        lines.append(f'        $status = "N/A"')
        lines.append(f'    }}')
    else:
        lines.append(f'    $status = "수동점검"')
        lines.append(f'    $detail = "수동 점검 필요 항목입니다. {escape_ps_string(good_criteria)}"')
        lines.append(f'    $curState = "수동점검 필요"')


def _gen_windows_secedit_check(lines, diag, commands, good_criteria, bad_criteria, item):
    """Generate secedit-based security policy check."""
    # Extract the policy key being checked
    policy_key = ''
    m = re.search(r'(PasswordHistorySize|MaximumPasswordAge|MinimumPasswordAge|MinimumPasswordLength|PasswordComplexity|ClearTextPassword|LockoutBadCount|ResetLockoutCount|LockoutDuration|NewAdministratorName|NewGuestName|EnableGuestAccount|ForceLogoffWhenHourExpire|LSAAnonymousNameLookup)', diag)
    if m:
        policy_key = m.group(1)

    if not policy_key:
        # Try other patterns
        m2 = re.search(r'(\w+)\s*(?:=|설정값)', diag)
        if m2:
            policy_key = m2.group(1)

    threshold = infer_numeric_threshold(good_criteria, bad_criteria, diag, item['title'], default='')
    direction = infer_numeric_direction(good_criteria, bad_criteria, diag, item['title'])
    if policy_key in ('LockoutDuration', 'ResetLockoutCount') and direction == 'unknown':
        direction = 'min'
    elif direction == 'unknown':
        direction = 'max'

    lines.append(f'    # Export security policy')
    lines.append(f'    $tempFile = "$env:TEMP\\secedit_export.cfg"')
    lines.append(f'    secedit /export /cfg $tempFile 2>$null | Out-Null')
    lines.append(f'    if (Test-Path $tempFile) {{')
    if policy_key:
        lines.append(f'        $content = Get-Content $tempFile | Select-String "{policy_key}"')
        lines.append(f'        if ($content) {{')
        lines.append(f'            $curState = $content.ToString().Trim()')
        lines.append(f'            $numericValue = Get-FirstNumber $curState')
        if policy_key == 'ClearTextPassword':
            lines.append(f'            if ($numericValue -eq 0) {{')
            lines.append(f'                $status = "양호"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria)}"')
            lines.append(f'            }} else {{')
            lines.append(f'                $status = "취약"')
            lines.append(f'                $detail = "{escape_ps_string(bad_criteria)}"')
            lines.append(f'            }}')
        elif policy_key == 'PasswordComplexity':
            lines.append(f'            if ($numericValue -eq 1) {{')
            lines.append(f'                $status = "양호"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria)}"')
            lines.append(f'            }} else {{')
            lines.append(f'                $status = "취약"')
            lines.append(f'                $detail = "{escape_ps_string(bad_criteria)}"')
            lines.append(f'            }}')
        elif policy_key == 'EnableGuestAccount':
            lines.append(f'            if ($numericValue -eq 0) {{')
            lines.append(f'                $status = "양호"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria)}"')
            lines.append(f'            }} else {{')
            lines.append(f'                $status = "취약"')
            lines.append(f'                $detail = "{escape_ps_string(bad_criteria)}"')
            lines.append(f'            }}')
        elif policy_key == 'NewAdministratorName':
            lines.append(f'            if ($curState -match "=\\s*Administrator\\s*$") {{')
            lines.append(f'                $status = "취약"')
            lines.append(f'                $detail = "{escape_ps_string(bad_criteria)}"')
            lines.append(f'            }} else {{')
            lines.append(f'                $status = "양호"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria)}"')
            lines.append(f'            }}')
        elif threshold:
            lines.append(f'            if ($null -eq $numericValue) {{')
            lines.append(f'                $status = "수동점검"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria or bad_criteria)}"')
            lines.append(f'            }} elseif ($numericValue {"-ge" if direction == "min" else "-le"} {threshold}) {{')
            lines.append(f'                $status = "양호"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria)}"')
            lines.append(f'            }} else {{')
            lines.append(f'                $status = "취약"')
            lines.append(f'                $detail = "{escape_ps_string(bad_criteria)}"')
            lines.append(f'            }}')
        else:
            lines.append(f'            if (Test-NegativeMarker $curState) {{')
            lines.append(f'                $status = "양호"')
            lines.append(f'                $detail = "{escape_ps_string(good_criteria)}"')
            lines.append(f'            }} elseif (Test-PositiveMarker $curState) {{')
            lines.append(f'                $status = "취약"')
            lines.append(f'                $detail = "{escape_ps_string(bad_criteria)}"')
            lines.append(f'            }} else {{')
            lines.append(f'                $detail = "보안정책 확인됨: $curState"')
            lines.append(f'                $status = "수동점검"')
            lines.append(f'            }}')
        lines.append(f'        }} else {{')
        lines.append(f'            $curState = "{policy_key} 설정 미발견"')
        lines.append(f'            $detail = "보안정책 {policy_key} 미설정."')
        lines.append(f'            $status = "취약"')
        lines.append(f'        }}')
    else:
        lines.append(f'        $curState = "secedit 내보내기 완료"')
        lines.append(f'        $detail = "수동 점검 필요. {escape_ps_string(good_criteria)}"')
        lines.append(f'        $status = "수동점검"')
    lines.append(f'        Remove-Item $tempFile -Force 2>$null')
    lines.append(f'    }} else {{')
    lines.append(f'        $curState = "secedit 내보내기 실패"')
    lines.append(f'        $detail = "보안정책 내보내기 실패."')
    lines.append(f'        $status = "N/A"')
    lines.append(f'    }}')


def _gen_windows_net_check(lines, diag, commands, good_criteria, bad_criteria, item):
    """Generate net user-based check."""
    title_text = normalize_dash_text(f'{item["title"]}\n{diag}').lower()
    lines.append(f'    try {{')
    if 'administrator' in title_text:
        lines.append(f'        $output = net user Administrator 2>$null | Out-String')
        lines.append(f'        $curState = $output.Trim()')
        lines.append(f'        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($curState)) {{')
        lines.append(f'            $status = "취약"')
        lines.append(f'            $detail = "{escape_ps_string(bad_criteria)}"')
        lines.append(f'        }} else {{')
        lines.append(f'            $status = "양호"')
        lines.append(f'            $detail = "{escape_ps_string(good_criteria)}"')
        lines.append(f'            if ([string]::IsNullOrWhiteSpace($curState)) {{ $curState = "Administrator 기본 이름 미확인" }}')
        lines.append(f'        }}')
    elif 'guest' in title_text:
        lines.append(f'        $output = net user Guest 2>$null | Out-String')
        lines.append(f'        $curState = $output.Trim()')
        lines.append(f'        if ([string]::IsNullOrWhiteSpace($curState)) {{')
        lines.append(f'            $status = "N/A"')
        lines.append(f'            $detail = "Guest 계정 정보를 조회하지 못했습니다."')
        lines.append(f'        }} elseif ($curState -match "Account active\\s+Yes|활성 계정\\s+예|계정 활성\\s+예") {{')
        lines.append(f'            $status = "취약"')
        lines.append(f'            $detail = "{escape_ps_string(bad_criteria)}"')
        lines.append(f'        }} elseif ($curState -match "Account active\\s+No|활성 계정\\s+아니오|계정 활성\\s+아니오|계정 사용 안함") {{')
        lines.append(f'            $status = "양호"')
        lines.append(f'            $detail = "{escape_ps_string(good_criteria)}"')
        lines.append(f'        }} else {{')
        lines.append(f'            $status = "수동점검"')
        lines.append(f'            $detail = "Guest 계정 상태 해석에 추가 확인이 필요합니다."')
        lines.append(f'        }}')
    elif '잠금 임계값' in title_text:
        threshold = infer_numeric_threshold(good_criteria, bad_criteria, diag, item['title'], default='5')
        lines.append(f'        $output = net accounts 2>$null | Out-String')
        lines.append(f'        $curState = $output.Trim()')
        lines.append(f'        $thresholdLine = ($output -split "`r?`n" | Where-Object {{ $_ -match "Lockout threshold|잠금 임계값" }} | Select-Object -First 1)')
        lines.append(f'        $numericValue = Get-FirstNumber $thresholdLine')
        lines.append(f'        if ($null -eq $numericValue -or $numericValue -eq 0) {{')
        lines.append(f'            $status = "취약"')
        lines.append(f'            $detail = "{escape_ps_string(bad_criteria)}"')
        lines.append(f'        }} elseif ($numericValue -le {threshold}) {{')
        lines.append(f'            $status = "양호"')
        lines.append(f'            $detail = "{escape_ps_string(good_criteria)}"')
        lines.append(f'        }} else {{')
        lines.append(f'            $status = "취약"')
        lines.append(f'            $detail = "{escape_ps_string(bad_criteria)}"')
        lines.append(f'        }}')
    else:
        lines.append(f'        $output = net user 2>$null')
        lines.append(f'        $curState = ($output | Out-String).Trim()')
        lines.append(f'        $detail = "사용자 계정 목록 확인됨. 수동 검증 필요."')
        lines.append(f'        $status = "수동점검"')
    lines.append(f'    }} catch {{')
    lines.append(f'        $curState = "net user 실행 실패"')
    lines.append(f'        $detail = "계정 조회 실패."')
    lines.append(f'        $status = "N/A"')
    lines.append(f'    }}')


def _gen_windows_audit_check(lines, diag, commands, good_criteria):
    """Generate auditpol-based check."""
    # Try to extract specific audit category
    audit_category = ''
    m = re.search(r'auditpol.*?/subcategory:\s*"([^"]+)"', diag)
    if m:
        audit_category = m.group(1)

    lines.append(f'    try {{')
    if audit_category:
        lines.append(f'        $output = auditpol /get /subcategory:"{audit_category}" 2>$null')
    else:
        lines.append(f'        $output = auditpol /get /category:* 2>$null')
    lines.append(f'        $curState = ($output | Out-String).Trim()')
    lines.append(f'        if ($output) {{')
    lines.append(f'            $detail = "감사 정책 확인됨. 수동 검증 필요."')
    lines.append(f'            $status = "수동점검"')
    lines.append(f'        }} else {{')
    lines.append(f'            $detail = "감사 정책 미설정."')
    lines.append(f'            $status = "취약"')
    lines.append(f'        }}')
    lines.append(f'    }} catch {{')
    lines.append(f'        $curState = "auditpol 실행 실패: $_"')
    lines.append(f'        $detail = "감사정책 조회 실패."')
    lines.append(f'        $status = "N/A"')
    lines.append(f'    }}')


def _gen_windows_registry_check(lines, diag, commands, good_criteria):
    """Generate registry check."""
    # Extract registry path
    reg_path = ''
    m = re.search(r'(HKLM\\[^\s\n]+)', diag)
    if m:
        reg_path = m.group(1)

    lines.append(f'    try {{')
    if reg_path:
        reg_safe = escape_ps_string(reg_path)
        lines.append(f'        $regResult = Get-ItemProperty -Path "Registry::{reg_safe}" -ErrorAction Stop 2>$null')
        lines.append(f'        $curState = ($regResult | Format-List | Out-String).Trim()')
        lines.append(f'        $detail = "레지스트리 값 확인됨. 수동 검증 필요."')
        lines.append(f'        $status = "수동점검"')
    else:
        lines.append(f'        $curState = "레지스트리 경로 미지정"')
        lines.append(f'        $detail = "수동 점검 필요. {escape_ps_string(good_criteria)}"')
        lines.append(f'        $status = "수동점검"')
    lines.append(f'    }} catch {{')
    lines.append(f'        $curState = "레지스트리 조회 실패: $_"')
    lines.append(f'        $detail = "레지스트리 키 미존재 또는 접근 불가."')
    lines.append(f'        $status = "수동점검"')
    lines.append(f'    }}')


def _gen_windows_service_check(lines, diag, commands, good_criteria):
    """Generate Windows service check."""
    service_name = ''
    for cmd in commands:
        m = re.search(r'sc\s+query\s+(\w+)', cmd)
        if m:
            service_name = m.group(1)
            break

    if service_name:
        lines.append(f'    try {{')
        lines.append(f'        $svc = Get-Service -Name "{service_name}" -ErrorAction Stop 2>$null')
        lines.append(f'        $curState = "$($svc.Name): $($svc.Status)"')
        # Determine if should be running or stopped
        if '비활성' in diag or '중지' in diag or '사용하지' in diag:
            lines.append(f'        if ($svc.Status -eq "Stopped") {{')
            lines.append(f'            $detail = "{service_name} 서비스 중지 상태 (양호)."')
            lines.append(f'        }} else {{')
            lines.append(f'            $detail = "{service_name} 서비스 실행 중 (취약)."')
            lines.append(f'            $status = "취약"')
            lines.append(f'        }}')
        else:
            lines.append(f'        $detail = "{service_name} 서비스 상태: $($svc.Status). 수동 확인 필요."')
            lines.append(f'        $status = "수동점검"')
        lines.append(f'    }} catch {{')
        lines.append(f'        $curState = "{service_name} 서비스 미설치"')
        lines.append(f'        $detail = "{service_name} 서비스가 존재하지 않음."')
        lines.append(f'        $status = "N/A"')
        lines.append(f'    }}')
    else:
        lines.append(f'    $status = "수동점검"')
        lines.append(f'    $detail = "서비스 상태 수동 확인 필요. {escape_ps_string(good_criteria)}"')
        lines.append(f'    $curState = "수동점검 필요"')


# ── Script template builders ─────────────────────────────────────────────────

def build_bash_script(app_key, app_def, items):
    """Build a complete bash script for an application."""
    is_esxi = app_def.get('esxi', False)
    platform = app_def['platform']
    needs_db = app_def.get('needs_db_args', False)
    db_type = app_def.get('db_type', '')
    script_name = app_def['script']
    total_items = len(items)

    parts = []

    # ── Shebang and header
    shebang = '#!/bin/sh' if is_esxi else '#!/bin/bash'
    parts.append(f'''{shebang}
###############################################################################
# {platform} CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: sudo bash {script_name}{" -h <host> -P <port> -u <user> -p <password>" if needs_db else ""} [output_file.json]
# Output: JSON file with all check results
###############################################################################
''')

    if not is_esxi:
        parts.append('set -o pipefail\n')

    # ── Argument parsing
    if needs_db:
        parts.append(_build_db_arg_parser(db_type, script_name, is_esxi))
    else:
        if is_esxi:
            parts.append(f'OUTPUT_FILE="${{1:-cce_check_result_{platform.lower()}_$(hostname)_$(date +%Y%m%d_%H%M%S).json}}"\n')
        else:
            parts.append(f'OUTPUT_FILE="${{1:-cce_check_result_{platform.lower()}_$(hostname)_$(date +%Y%m%d_%H%M%S).json}}"\n')

    # ── Temp dir
    if is_esxi:
        parts.append('TEMP_DIR="/tmp/cce_check_$$"\nmkdir -p "$TEMP_DIR"\ntrap "rm -rf $TEMP_DIR" EXIT\n')
    else:
        parts.append('TEMP_DIR=$(mktemp -d)\ntrap "rm -rf $TEMP_DIR" EXIT\n')

    # ── JSON helper (add_result)
    if is_esxi:
        parts.append(_build_esxi_helpers())
    else:
        parts.append(_build_bash_helpers())

    # ── Custom helpers per app
    for helper in app_def.get('helpers', []):
        parts.append(_get_custom_helper(helper, app_def))

    # ── Pre-flight detection function
    parts.append(_get_detect_function(app_key, app_def))

    # ── Pre-flight call
    parts.append(f'''###############################################################################
# Pre-flight: 애플리케이션 설치 확인 및 경로 탐지
###############################################################################
detect_app

if [ "$APP_FOUND" = "false" ]; then
    echo "[경고] {platform} 이(가) 설치되어 있지 않거나 탐지되지 않았습니다."
    echo "일부 점검 항목이 N/A로 처리될 수 있습니다."
    echo ""
fi

''')

    # ── Check functions
    func_names = []
    for item in items:
        func_code, func_name = generate_bash_check_function(item, app_def)
        parts.append(func_code)
        func_names.append((item['code'], func_name))

    # ── Execution section
    parts.append(f'''
###############################################################################
# Execute all checks
###############################################################################

echo "===== {platform} CCE 취약점 진단 시작 ====="
echo "호스트: $(hostname)"
echo "날짜: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

total=0
progress() {{
    total=$((total + 1))
    printf "\\r[%d/{total_items}] %s 점검 중...                " "$total" "$1"
}}

''')

    # Call each check
    for code, func_name in func_names:
        code_safe = code.split('/')[0].strip()
        parts.append(f'progress "{code_safe}"; {func_name}')
    parts.append('\necho ""\necho ""\n')

    # ── JSON output
    parts.append(_build_json_output(platform, total_items, is_esxi))

    return '\n'.join(parts)


def _build_db_arg_parser(db_type, script_name, is_esxi):
    """Build argument parser for DB scripts."""
    defaults = {
        'mysql': ('localhost', '3306', 'root', ''),
        'mssql': ('localhost', '1433', 'sa', ''),
        'redis': ('localhost', '6379', '', ''),
        'mongodb': ('localhost', '27017', '', ''),
        'postgresql': ('localhost', '5432', 'postgres', ''),
    }
    host, port, user, pw = defaults.get(db_type, ('localhost', '0', '', ''))

    return f'''# Database connection parameters
DB_HOST="{host}"
DB_PORT="{port}"
DB_USER="{user}"
DB_PASS=""

usage() {{
    echo "Usage: sudo bash {script_name} [-h host] [-P port] [-u user] [-p password] [output_file.json]"
    exit 1
}}

while getopts "h:P:u:p:" opt; do
    case $opt in
        h) DB_HOST="$OPTARG" ;;
        P) DB_PORT="$OPTARG" ;;
        u) DB_USER="$OPTARG" ;;
        p) DB_PASS="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

OUTPUT_FILE="${{1:-cce_check_result_{db_type}_$(hostname)_$(date +%Y%m%d_%H%M%S).json}}"

'''


def _build_bash_helpers():
    """Build common bash helper functions (matching linux_cce_check.sh)."""
    return '''# --- JSON helper functions ---
results=()

normalize_trace_value() {
    printf '%s' "$1" | tr '\\t\\r\\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//'
}

summarize_output() {
    printf '%s' "$1" | head -n 5 | tr '\\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'
}

output_has_negative_marker() {
    printf '%s\\n' "$1" | grep -Eiq '(^|[^[:alnum:]_-])(0|false|off|disabled|inactive|none|no|n|deny|denied|prohibit-password|without-password|never)([^[:alnum:]_-]|$)|계정 사용 안함|사용 안함|비활성'
}

output_has_positive_marker() {
    printf '%s\\n' "$1" | grep -Eiq '(^|[^[:alnum:]_-])(1|true|on|enabled|enable|active|yes|y|allow|allowed)([^[:alnum:]_-]|$)|활성'
}

first_numeric_value() {
    printf '%s\\n' "$1" | grep -Eo '[0-9]+' | head -1
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
    printf '\\n[TRACE] code=%s status=%s title=%s\\n' "$code" "$status" "$title"
    printf '[TRACE] command=%s\\n' "${command_text:--}"
    printf '[TRACE] current_state=%s\\n' "${current_state_text:--}"
    printf '[TRACE] detail=%s\\n' "${detail_text:--}"
}

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
    local raw_detail="$detail"
    local raw_command="$command"
    local raw_current_state="$current_state"

    # Escape strings for JSON
    detail=$(echo "$detail" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
    command=$(echo "$command" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')

    results+=("{\\"code\\":\\"$code\\",\\"category\\":\\"$category\\",\\"title\\":\\"$title\\",\\"importance\\":\\"$importance\\",\\"status\\":\\"$status\\",\\"detail\\":\\"$detail\\",\\"source\\":\\"$source\\",\\"command\\":\\"$command\\",\\"current_state\\":\\"$current_state\\",\\"remediation\\":\\"$remediation\\"}")
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
    if [ -z "$expected_owner" ] || [ "$owner" = "$expected_owner" ]; then
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

get_process_snapshot() {
    local pattern="$1"
    local snapshot=""

    if command -v ps >/dev/null 2>&1; then
        snapshot=$(ps -ef 2>/dev/null | grep -v grep | grep -E "$pattern" || true)
        if [ -n "$snapshot" ]; then
            printf '%s\n' "$snapshot"
            return 0
        fi
    fi

    if command -v pgrep >/dev/null 2>&1; then
        snapshot=$(pgrep -af "$pattern" 2>/dev/null || true)
        if [ -n "$snapshot" ]; then
            printf '%s\n' "$snapshot"
            return 0
        fi
    fi

    local pid_dir
    for pid_dir in /proc/[0-9]*; do
        [ -r "$pid_dir/cmdline" ] || continue
        local cmdline
        cmdline=$(tr '\\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
        [ -z "$cmdline" ] && continue
        if printf '%s\n' "$cmdline" | grep -Eiq "$pattern"; then
            local uid="unknown"
            if [ -r "$pid_dir/status" ]; then
                uid=$(awk '/^Uid:/ {print $2; exit}' "$pid_dir/status" 2>/dev/null || printf 'unknown')
                if command -v id >/dev/null 2>&1; then
                    uid=$(id -nu "$uid" 2>/dev/null || printf '%s' "$uid")
                fi
            fi
            printf '%s %s\n' "$uid" "$cmdline"
        fi
    done
}

is_service_active() {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" &>/dev/null; then
        echo "active"
    elif command -v service >/dev/null 2>&1 && service "$svc" status >/dev/null 2>&1; then
        echo "active"
    elif command -v pgrep >/dev/null 2>&1 && pgrep -f "$svc" >/dev/null 2>&1; then
        echo "active"
    elif [ -n "$(get_process_snapshot "$svc")" ]; then
        echo "active"
    else
        echo "inactive"
    fi
}

'''


def _build_esxi_helpers():
    """Build ESXi-compatible (BusyBox ash) helper functions."""
    return '''# --- JSON helper functions (ESXi BusyBox compatible) ---
RESULTS_FILE="$TEMP_DIR/results.txt"
: > "$RESULTS_FILE"

normalize_trace_value() {
    printf '%s' "$1" | tr '\\t\\r\\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//'
}

summarize_output() {
    printf '%s' "$1" | head -n 5 | tr '\\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'
}

output_has_negative_marker() {
    printf '%s\\n' "$1" | grep -Eiq '(^|[^[:alnum:]_-])(0|false|off|disabled|inactive|none|no|n|deny|denied|prohibit-password|without-password|never)([^[:alnum:]_-]|$)|계정 사용 안함|사용 안함|비활성'
}

output_has_positive_marker() {
    printf '%s\\n' "$1" | grep -Eiq '(^|[^[:alnum:]_-])(1|true|on|enabled|enable|active|yes|y|allow|allowed)([^[:alnum:]_-]|$)|활성'
}

first_numeric_value() {
    printf '%s\\n' "$1" | grep -Eo '[0-9]+' | head -1
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
    printf '\\n[TRACE] code=%s status=%s title=%s\\n' "$code" "$status" "$title"
    printf '[TRACE] command=%s\\n' "${command_text:--}"
    printf '[TRACE] current_state=%s\\n' "${current_state_text:--}"
    printf '[TRACE] detail=%s\\n' "${detail_text:--}"
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
    detail=$(echo "$detail" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
    command=$(echo "$command" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')

    echo "{\\"code\\":\\"$code\\",\\"category\\":\\"$category\\",\\"title\\":\\"$title\\",\\"importance\\":\\"$importance\\",\\"status\\":\\"$status\\",\\"detail\\":\\"$detail\\",\\"source\\":\\"$source\\",\\"command\\":\\"$command\\",\\"current_state\\":\\"$current_state\\",\\"remediation\\":\\"$remediation\\"}" >> "$RESULTS_FILE"
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

'''


def _get_custom_helper(helper_name, app_def):
    """Return custom helper function code."""
    db_type = app_def.get('db_type', '')

    helpers = {
        'virsh_helper': '''# --- KVM helper ---
run_virsh() {
    virsh "$@" 2>/dev/null
}

''',
        'xe_helper': '''# --- Xenserver helper ---
run_xe() {
    xe "$@" 2>/dev/null
}

''',
        'esxcli_helper': '''# --- ESXi helper ---
run_esxcli() {
    esxcli "$@" 2>/dev/null
}

''',
        'mysql_query_helper': '''# --- MySQL helper ---
run_mysql_query() {
    local query="$1"
    if [ -n "$DB_PASS" ]; then
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" -N -e "$query" 2>/dev/null
    else
        if [ -z "$DB_HOST" ] || [ "$DB_HOST" = "localhost" ] || [ "$DB_HOST" = "127.0.0.1" ] || [ "$DB_HOST" = "::1" ]; then
            mysql -u "$DB_USER" -N -e "$query" 2>/dev/null \
                || mysql --protocol=tcp -h 127.0.0.1 -P "${DB_PORT:-3306}" -u "$DB_USER" -N -e "$query" 2>/dev/null \
                || mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -N -e "$query" 2>/dev/null
        else
            mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -N -e "$query" 2>/dev/null
        fi
    fi
}

''',
        'mssql_query_helper': '''# --- MSSQL helper ---
run_mssql_query() {
    local query="$1"
    if command -v sqlcmd &>/dev/null; then
        sqlcmd -S "$DB_HOST,$DB_PORT" -U "$DB_USER" -P "$DB_PASS" -Q "$query" -h -1 2>/dev/null
    elif command -v mssql-cli &>/dev/null; then
        mssql-cli -S "$DB_HOST" -U "$DB_USER" -P "$DB_PASS" -Q "$query" 2>/dev/null
    else
        echo "ERROR: sqlcmd or mssql-cli not found"
    fi
}

''',
        'redis_cli_helper': '''# --- Redis helper ---
run_redis_cli() {
    local cmd="$1"
    if [ -n "$DB_PASS" ]; then
        redis-cli -h "$DB_HOST" -p "$DB_PORT" -a "$DB_PASS" --no-auth-warning $cmd 2>/dev/null
    else
        redis-cli -h "$DB_HOST" -p "$DB_PORT" $cmd 2>/dev/null
    fi
}

''',
        'es_curl_helper': '''# --- Elasticsearch helper ---
ES_URL="${ES_URL:-http://localhost:9200}"

run_es_api() {
    local endpoint="$1"
    curl -s -m 10 "${ES_URL}${endpoint}" 2>/dev/null
}

''',
        'mongo_helper': '''# --- MongoDB helper ---
run_mongo_query() {
    local query="$1"
    local db="${2:-admin}"
    local output=""
    local rc=0
    local mongo_bin=""
    if [ -n "$DB_PASS" ] && [ -n "$DB_USER" ]; then
        output=$(mongosh --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ]; then
            mongo_bin=$(command -v mongo 2>/dev/null || true)
        fi
        if [ "$rc" -ne 0 ] && [ -n "$mongo_bin" ]; then
            output=$(mongo --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>&1)
            rc=$?
        fi
    else
        output=$(mongosh --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ]; then
            mongo_bin=$(command -v mongo 2>/dev/null || true)
        fi
        if [ "$rc" -ne 0 ] && [ -n "$mongo_bin" ]; then
            output=$(mongo --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>&1)
            rc=$?
        fi
    fi
    printf '%s' "$output"
}

''',
        'psql_query_helper': '''# --- PostgreSQL helper ---
run_psql_query() {
    local query="$1"
    local db="${2:-postgres}"
    if [ -n "$DB_PASS" ]; then
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db" -t -c "$query" 2>/dev/null
    else
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db" -t -c "$query" 2>/dev/null
    fi
}

''',
        'apache_helper': '''# --- Apache helper ---
APACHE_CONF="${APACHE_CONF:-}"
if [ -z "$APACHE_CONF" ]; then
    for f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache2/conf/httpd.conf; do
        if [ -f "$f" ]; then
            APACHE_CONF="$f"
            break
        fi
    done
fi
APACHE_CONF_DIR="${APACHE_CONF_DIR:-$(dirname "${APACHE_CONF:-/etc/httpd/conf/httpd.conf}")}"

get_apache_conf() {
    echo "$APACHE_CONF"
}

''',
        'nginx_helper': '''# --- Nginx helper ---
NGINX_CONF="${NGINX_CONF:-}"
if [ -z "$NGINX_CONF" ]; then
    for f in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf; do
        if [ -f "$f" ]; then
            NGINX_CONF="$f"
            break
        fi
    done
fi

get_nginx_conf() {
    echo "$NGINX_CONF"
}

''',
        'tomcat_helper': '''# --- Tomcat helper ---
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

''',
        'docker_helper': '''# --- Docker helper ---
run_docker_cmd() {
    docker "$@" 2>/dev/null
}

''',
        'k8s_helper': '''# --- Kubernetes helper ---
run_kubectl() {
    kubectl "$@" 2>/dev/null
}

''',
        'hadoop_helper': '''# --- Hadoop helper ---
HADOOP_CONF_DIR="${HADOOP_CONF_DIR:-/etc/hadoop/conf}"
if [ ! -d "$HADOOP_CONF_DIR" ]; then
    for d in /opt/hadoop*/etc/hadoop /usr/lib/hadoop/etc/hadoop; do
        if [ -d "$d" ]; then
            HADOOP_CONF_DIR="$d"
            break
        fi
    done
fi

''',
        'ceph_helper': '''# --- Ceph helper ---
CEPH_CONF="${CEPH_CONF:-/etc/ceph/ceph.conf}"

run_ceph_cmd() {
    ceph "$@" 2>/dev/null
}

''',
    }
    return helpers.get(helper_name, f'# Helper {helper_name} not defined\n\n')


def _get_detect_function(app_key, app_def):
    """Return detect_app() bash function for pre-flight application detection."""
    is_esxi = app_def.get('esxi', False)
    platform = app_def['platform']

    detect_functions = {
        'MY-SQL': '''# --- Pre-flight: MySQL 설치 확인 및 경로 탐지 ---
MYSQL_BIN=""
MYSQLD_BIN=""
MYSQL_CONF="${MYSQL_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    MYSQL_BIN=$(command -v mysql 2>/dev/null)
    MYSQLD_BIN=$(command -v mysqld 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$MYSQLD_BIN" ]; then
        MYSQLD_BIN=$(get_process_snapshot 'mysqld' | awk '{for(i=1;i<=NF;i++) if($i ~ /mysqld$/) print $i}' | head -1)
    fi

    # 프로세스에서 --defaults-file 추출
    local defaults_file
    defaults_file=$(get_process_snapshot 'mysqld' | sed -n 's/.*--defaults-file=\\([^ ]*\\).*/\\1/p' | head -1)
    if [ -n "$defaults_file" ] && [ -f "$defaults_file" ]; then
        MYSQL_CONF="$defaults_file"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$MYSQL_CONF" ]; then
        for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf ~/.my.cnf /usr/local/mysql/my.cnf /opt/cce/mysql/my.cnf; do
            if [ -f "$f" ]; then
                MYSQL_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$MYSQL_BIN" ] && [ -z "$MYSQLD_BIN" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'mysql-server\\|mysql-client\\|mariadb-server' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'mysql-server\\|mysql-community\\|mariadb-server' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$MYSQL_BIN" ] || [ -n "$MYSQLD_BIN" ] || [ -n "$MYSQL_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'MS-SQL': '''# --- Pre-flight: MSSQL 설치 확인 및 경로 탐지 ---
SQLCMD_BIN=""
MSSQL_CONF="${MSSQL_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    SQLCMD_BIN=$(command -v sqlcmd 2>/dev/null)
    if [ -z "$SQLCMD_BIN" ]; then
        SQLCMD_BIN=$(command -v mssql-cli 2>/dev/null)
    fi

    # 2) 프로세스에서 탐지
    if [ -z "$SQLCMD_BIN" ]; then
        ps -ef 2>/dev/null | grep -q '[s]qlservr' && APP_FOUND="true"
    fi

    # 3) 공통 설정 파일 경로 탐색
    for f in /var/opt/mssql/mssql.conf /opt/mssql/lib/mssql-conf/mssql.conf; do
        if [ -f "$f" ]; then
            MSSQL_CONF="$f"
            break
        fi
    done

    # 4) 패키지 매니저 확인
    if [ -z "$SQLCMD_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'mssql-server\\|mssql-tools' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'mssql-server\\|mssql-tools' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$SQLCMD_BIN" ] || [ -n "$MSSQL_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'PostgreSQL': '''# --- Pre-flight: PostgreSQL 설치 확인 및 경로 탐지 ---
PSQL_BIN=""
PG_DATA="${PG_DATA:-}"
PG_CONF="${PG_CONF:-}"
PG_HBA="${PG_HBA:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    PSQL_BIN=$(command -v psql 2>/dev/null)
    local pg_config_bin
    pg_config_bin=$(command -v pg_config 2>/dev/null)

    # 2) 프로세스에서 data dir 추출
    local pg_proc
    pg_proc=$(get_process_snapshot 'postgres')
    if [ -n "$pg_proc" ]; then
        PG_DATA=$(echo "$pg_proc" | sed -n 's/.*-D[[:space:]]*\\([^ ]*\\).*/\\1/p')
    fi

    # pg_config 으로 경로 추출
    if [ -z "$PG_DATA" ] && [ -n "$pg_config_bin" ]; then
        local sharedir
        sharedir=$($pg_config_bin --sharedir 2>/dev/null)
        if [ -n "$sharedir" ]; then
            PG_DATA=$(dirname "$sharedir")/data
            [ ! -d "$PG_DATA" ] && PG_DATA=""
        fi
    fi

    # 3) 공통 경로 탐색
    if [ -z "$PG_DATA" ]; then
        for d in /var/lib/postgresql/*/main /var/lib/pgsql/*/data /var/lib/pgsql/data /usr/local/pgsql/data /opt/cce/postgresql/data; do
            if [ -d "$d" ]; then
                PG_DATA="$d"
                break
            fi
        done
    fi

    # 설정 파일 경로 확정
    if [ -n "$PG_DATA" ]; then
        [ -f "$PG_DATA/postgresql.conf" ] && PG_CONF="$PG_DATA/postgresql.conf"
        [ -f "$PG_DATA/pg_hba.conf" ] && PG_HBA="$PG_DATA/pg_hba.conf"
    fi
    # Debian/Ubuntu 스타일
    if [ -z "$PG_CONF" ]; then
        for f in /etc/postgresql/*/main/postgresql.conf; do
            if [ -f "$f" ]; then
                PG_CONF="$f"
                PG_HBA="$(dirname "$f")/pg_hba.conf"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$PSQL_BIN" ] && [ -z "$PG_DATA" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'postgresql' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'postgresql' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$PSQL_BIN" ] || [ -n "$PG_DATA" ] || [ -n "$PG_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Redis': '''# --- Pre-flight: Redis 설치 확인 및 경로 탐지 ---
REDIS_CLI=""
REDIS_CONF="${REDIS_CONF:-}"
REDIS_DATA_DIR="${REDIS_DATA_DIR:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    REDIS_CLI=$(command -v redis-cli 2>/dev/null)
    local redis_server_bin
    redis_server_bin=$(command -v redis-server 2>/dev/null)

    # 2) 프로세스에서 config 경로 추출
    local redis_proc
    redis_proc=$(get_process_snapshot 'redis-server')
    if [ -n "$redis_proc" ]; then
        # redis-server /path/to/redis.conf 형태에서 추출
        local conf_from_proc
        conf_from_proc=$(echo "$redis_proc" | grep -oP '\\S+redis\\.conf' | head -1)
        if [ -n "$conf_from_proc" ] && [ -f "$conf_from_proc" ]; then
            REDIS_CONF="$conf_from_proc"
        fi
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$REDIS_CONF" ]; then
        for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf /usr/local/etc/redis.conf /opt/cce/redis/redis.conf; do
            if [ -f "$f" ]; then
                REDIS_CONF="$f"
                break
            fi
        done
    fi
    if [ -z "$REDIS_DATA_DIR" ] && [ -n "$REDIS_CONF" ] && [ -f "$REDIS_CONF" ]; then
        REDIS_DATA_DIR=$(sed -n 's/^[[:space:]]*dir[[:space:]]\\+\\([^#].*\\)$/\\1/p' "$REDIS_CONF" | head -1 | tr -d '"')
    fi
    if [ -z "$REDIS_DATA_DIR" ]; then
        REDIS_DATA_DIR="/data"
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$REDIS_CLI" ] && [ -z "$redis_server_bin" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'redis-server' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'redis' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$REDIS_CLI" ] || [ -n "$redis_server_bin" ] || [ -n "$REDIS_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Elasticsearch': '''# --- Pre-flight: Elasticsearch 설치 확인 및 경로 탐지 ---
ES_CONF="${ES_CONF:-}"
ES_URL="${ES_URL:-http://localhost:9200}"
APP_FOUND="false"

detect_app() {
    local es_bin
    es_bin=$(command -v elasticsearch 2>/dev/null)

    # 1) curl 로 ES 응답 확인
    local es_response
    es_response=$(curl -s -m 5 "$ES_URL" 2>/dev/null)
    if echo "$es_response" | grep -q '"tagline"'; then
        APP_FOUND="true"
    fi

    # 2) 프로세스에서 탐지
    local es_proc
    es_proc=$(ps -ef 2>/dev/null | grep '[e]lasticsearch' | grep -v grep | head -1)
    if [ -n "$es_proc" ]; then
        APP_FOUND="true"
        # -Epath.conf 추출
        local conf_from_proc
        conf_from_proc=$(echo "$es_proc" | grep -oP '\\-Epath\\.conf=\\K[^ ]+' | head -1)
        if [ -n "$conf_from_proc" ] && [ -d "$conf_from_proc" ]; then
            ES_CONF="$conf_from_proc/elasticsearch.yml"
        fi
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$ES_CONF" ]; then
        for f in /etc/elasticsearch/elasticsearch.yml /usr/local/etc/elasticsearch/elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml; do
            if [ -f "$f" ]; then
                ES_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ "$APP_FOUND" = "false" ] && [ -z "$es_bin" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'elasticsearch' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'elasticsearch' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$es_bin" ] || [ -n "$ES_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'MongoDB': '''# --- Pre-flight: MongoDB 설치 확인 및 경로 탐지 ---
MONGO_BIN=""
MONGOD_CONF="${MONGOD_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    MONGO_BIN=$(command -v mongosh 2>/dev/null)
    if [ -z "$MONGO_BIN" ]; then
        MONGO_BIN=$(command -v mongo 2>/dev/null)
    fi
    local mongod_bin
    mongod_bin=$(command -v mongod 2>/dev/null)

    # 2) 프로세스에서 --config 추출
    local mongod_proc
    mongod_proc=$(ps -ef 2>/dev/null | grep '[m]ongod' | grep -v mongos | head -1)
    if [ -n "$mongod_proc" ]; then
        APP_FOUND="true"
        local conf_from_proc
        conf_from_proc=$(echo "$mongod_proc" | sed -n 's/.*--config[= ]\\([^ ]*\\).*/\\1/p')
        if [ -n "$conf_from_proc" ] && [ -f "$conf_from_proc" ]; then
            MONGOD_CONF="$conf_from_proc"
        fi
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$MONGOD_CONF" ]; then
        for f in /etc/mongod.conf /etc/mongodb.conf /usr/local/etc/mongod.conf; do
            if [ -f "$f" ]; then
                MONGOD_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$MONGO_BIN" ] && [ -z "$mongod_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'mongodb\\|mongod' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'mongodb\\|mongod' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$MONGO_BIN" ] || [ -n "$mongod_bin" ] || [ -n "$MONGOD_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Apache': '''# --- Pre-flight: Apache 설치 확인 및 경로 탐지 ---
APACHE_BIN=""
APACHE_CONF="${APACHE_CONF:-}"
APACHE_CONF_DIR="${APACHE_CONF_DIR:-}"
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
        apache_proc=$(get_process_snapshot 'httpd|apache2' | head -1)
        if [ -n "$apache_proc" ]; then
            APACHE_BIN=$(echo "$apache_proc" | awk '{print $8}')
            APP_FOUND="true"
        fi
    fi

    # 3) -V 로 설정 경로 추출
    if [ -n "$APACHE_BIN" ]; then
        local server_root
        server_root=$("$APACHE_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\\(.*\\)"/\\1/p')
        local server_config
        server_config=$("$APACHE_BIN" -V 2>/dev/null | sed -n 's/.*SERVER_CONFIG_FILE="\\(.*\\)"/\\1/p')
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
            dpkg -l 2>/dev/null | grep -qi 'apache2\\|httpd' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'httpd\\|apache' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$APACHE_BIN" ] || [ -n "$APACHE_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Nginx': '''# --- Pre-flight: Nginx 설치 확인 및 경로 탐지 ---
NGINX_BIN=""
NGINX_CONF="${NGINX_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NGINX_BIN=$(command -v nginx 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$NGINX_BIN" ]; then
        local nginx_proc
        nginx_proc=$(get_process_snapshot 'nginx.*master' | head -1)
        if [ -n "$nginx_proc" ]; then
            NGINX_BIN=$(echo "$nginx_proc" | awk '{print $8}')
            APP_FOUND="true"
        fi
    fi

    # 3) nginx -t 로 conf 경로 추출
    if [ -n "$NGINX_BIN" ]; then
        local nginx_test
        nginx_test=$("$NGINX_BIN" -t 2>&1)
        local conf_from_test
        conf_from_test=$(echo "$nginx_test" | sed -n 's/.*configuration file \\(.*\\) test.*/\\1/p')
        if [ -n "$conf_from_test" ] && [ -f "$conf_from_test" ]; then
            NGINX_CONF="$conf_from_test"
        fi
    fi

    # 4) 공통 설정 파일 경로 탐색
    if [ -z "$NGINX_CONF" ]; then
        for f in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf /usr/local/etc/nginx/nginx.conf; do
            if [ -f "$f" ]; then
                NGINX_CONF="$f"
                break
            fi
        done
    fi

    # 5) 패키지 매니저 확인
    if [ -z "$NGINX_BIN" ] && [ -z "$NGINX_CONF" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'nginx' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'nginx' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$NGINX_BIN" ] || [ -n "$NGINX_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Tomcat': '''# --- Pre-flight: Tomcat 설치 확인 및 경로 탐지 ---
APP_FOUND="false"

detect_app() {
    # 1) CATALINA_HOME 이 이미 설정되어 있는지 확인
    if [ -n "$CATALINA_HOME" ] && [ -d "$CATALINA_HOME" ]; then
        APP_FOUND="true"
    fi

    # 2) 프로세스에서 -Dcatalina.home 추출
    if [ "$APP_FOUND" = "false" ]; then
        local tomcat_proc
        tomcat_proc=$(get_process_snapshot 'catalina|tomcat' | head -1)
        if [ -n "$tomcat_proc" ]; then
            local home_from_proc
            home_from_proc=$(echo "$tomcat_proc" | grep -oP '\\-Dcatalina\\.home=\\K[^ ]+' | head -1)
            if [ -n "$home_from_proc" ] && [ -d "$home_from_proc" ]; then
                CATALINA_HOME="$home_from_proc"
                APP_FOUND="true"
            fi
        fi
    fi

    # 3) 공통 설치 경로 탐색
    if [ "$APP_FOUND" = "false" ]; then
        for d in /usr/share/tomcat* /opt/tomcat* /var/lib/tomcat* /usr/local/tomcat*; do
            if [ -d "$d" ] && [ -f "$d/conf/server.xml" ]; then
                CATALINA_HOME="$d"
                APP_FOUND="true"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'tomcat' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'tomcat' && APP_FOUND="true"
        fi
    fi
}

''',
        'Docker': '''# --- Pre-flight: Docker 설치 확인 및 경로 탐지 ---
DOCKER_BIN=""
DOCKER_CONF="${DOCKER_CONF:-}"
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
        if command -v dpkg >/dev/null 2>&1; then
            dpkg -l 2>/dev/null | grep -qi 'docker-ce\\|docker.io' && APP_FOUND="true"
        elif command -v rpm >/dev/null 2>&1; then
            rpm -qa 2>/dev/null | grep -qi 'docker-ce\\|docker' && APP_FOUND="true"
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

''',
        'K8s(Master)': '''# --- Pre-flight: Kubernetes Master 설치 확인 및 경로 탐지 ---
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

''',
        'K8s(Worker)': '''# --- Pre-flight: Kubernetes Worker 설치 확인 및 경로 탐지 ---
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
        conf_from_proc=$(echo "$kubelet_proc" | sed -n 's/.*--config[= ]\\([^ ]*\\).*/\\1/p')
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

''',
        'KVM': '''# --- Pre-flight: KVM 설치 확인 및 경로 탐지 ---
VIRSH_BIN=""
LIBVIRT_CONF="${LIBVIRT_CONF:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    VIRSH_BIN=$(command -v virsh 2>/dev/null)

    # 2) 프로세스에서 libvirtd/qemu 탐지
    if ps -ef 2>/dev/null | grep -qE '[l]ibvirtd|[q]emu'; then
        APP_FOUND="true"
    fi

    # 3) 공통 설정 경로 탐색
    if [ -d "/etc/libvirt" ]; then
        LIBVIRT_CONF="/etc/libvirt"
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$VIRSH_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'libvirt\\|qemu-kvm' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'libvirt\\|qemu-kvm' && APP_FOUND="true"
        fi
    fi

    # 5) KVM 모듈 확인
    if lsmod 2>/dev/null | grep -q kvm; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$VIRSH_BIN" ] || [ -n "$LIBVIRT_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Xenserver': '''# --- Pre-flight: Xenserver 설치 확인 및 경로 탐지 ---
XE_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    XE_BIN=$(command -v xe 2>/dev/null)

    # 2) 프로세스에서 xapi 탐지
    if ps -ef 2>/dev/null | grep -q '[x]api'; then
        APP_FOUND="true"
    fi

    # 3) Xenserver 환경 파일 확인
    if [ -f "/etc/xensource-inventory" ]; then
        APP_FOUND="true"
    fi

    # 판정
    if [ -n "$XE_BIN" ]; then
        APP_FOUND="true"
    fi
}

''',
        'ESXi': '''# --- Pre-flight: ESXi 설치 확인 및 경로 탐지 ---
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

''',
        'PHP': '''# --- Pre-flight: PHP 설치 확인 및 경로 탐지 ---
PHP_BIN=""
PHP_INI="${PHP_INI:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    PHP_BIN=$(command -v php 2>/dev/null)

    # 2) 프로세스에서 php-fpm 탐지
    if [ -n "$(get_process_snapshot 'php-fpm|php ')" ]; then
        APP_FOUND="true"
    fi

    # 3) php --ini 로 설정 경로 추출
    if [ -z "$PHP_INI" ] && [ -n "$PHP_BIN" ]; then
        PHP_INI=$("$PHP_BIN" --ini 2>/dev/null | sed -n 's/.*Loaded Configuration File:[[:space:]]*\\(.*\\)/\\1/p')
        if [ -z "$PHP_INI" ] || [ "$PHP_INI" = "(none)" ]; then
            PHP_INI=""
        fi
    fi
    if [ -z "$PHP_INI" ]; then
        local php_proc
        php_proc=$(get_process_snapshot 'php-fpm|php ' | head -1)
        if [ -n "$php_proc" ]; then
            PHP_INI=$(echo "$php_proc" | sed -n 's/.*[[:space:]]-c[[:space:]]\\([^ ]*\\).*/\\1/p' | head -1)
        fi
    fi

    # 4) 공통 설정 파일 경로 탐색
    if [ -z "$PHP_INI" ]; then
        for f in /etc/php/*/cli/php.ini /etc/php/*/fpm/php.ini /etc/php.ini /usr/local/etc/php/php.ini /opt/cce/php/php.ini; do
            if [ -f "$f" ]; then
                PHP_INI="$f"
                break
            fi
        done
    fi

    # 5) 패키지 매니저 확인
    if [ -z "$PHP_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'php[0-9]' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'php' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$PHP_BIN" ] || [ -n "$PHP_INI" ]; then
        APP_FOUND="true"
    fi
}

''',
        'NodeJS': '''# --- Pre-flight: Node.js 설치 확인 및 경로 탐지 ---
NODE_BIN=""
NPM_BIN=""
NODE_MAIN="${NODE_MAIN:-}"
NODE_APP_ROOT="${NODE_APP_ROOT:-}"
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NODE_BIN=$(command -v node 2>/dev/null)
    NPM_BIN=$(command -v npm 2>/dev/null)

    # 2) 프로세스에서 node 탐지
    local node_proc
    node_proc=$(get_process_snapshot 'node ' | head -1)
    if [ -n "$node_proc" ]; then
        APP_FOUND="true"
        if [ -z "$NODE_MAIN" ]; then
            NODE_MAIN=$(printf '%s\n' "$node_proc" | awk '{for(i=1;i<=NF;i++) if ($i ~ /\\.js$/) {print $i; exit}}')
        fi
        if [ -n "$NODE_MAIN" ]; then
            NODE_APP_ROOT=$(dirname "$NODE_MAIN")
        fi
    fi

    # 3) nvm 환경 확인
    if [ -z "$NODE_BIN" ] && [ -d "$HOME/.nvm" ]; then
        local nvm_node
        nvm_node=$(ls -d "$HOME/.nvm/versions/node"/*/bin/node 2>/dev/null | tail -1)
        if [ -n "$nvm_node" ] && [ -x "$nvm_node" ]; then
            NODE_BIN="$nvm_node"
        fi
    fi
    if [ -z "$NODE_MAIN" ]; then
        for f in /workspace/app.js /workspace/server.js /workspace/docker/test-lab/fixtures/node/server.js; do
            if [ -f "$f" ]; then
                NODE_MAIN="$f"
                NODE_APP_ROOT=$(dirname "$f")
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$NODE_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'nodejs' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'nodejs' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$NODE_BIN" ] || [ -n "$NODE_MAIN" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Hadoop': '''# --- Pre-flight: Hadoop 설치 확인 및 경로 탐지 ---
HADOOP_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    HADOOP_BIN=$(command -v hadoop 2>/dev/null)
    local hdfs_bin
    hdfs_bin=$(command -v hdfs 2>/dev/null)

    # 2) 프로세스에서 hadoop/NameNode 탐지
    if ps -ef 2>/dev/null | grep -qE '[h]adoop|[N]ameNode|[D]ataNode'; then
        APP_FOUND="true"
    fi

    # 3) HADOOP_HOME 환경 변수 확인
    if [ -n "$HADOOP_HOME" ] && [ -d "$HADOOP_HOME" ]; then
        APP_FOUND="true"
        if [ -z "$HADOOP_BIN" ] && [ -x "$HADOOP_HOME/bin/hadoop" ]; then
            HADOOP_BIN="$HADOOP_HOME/bin/hadoop"
        fi
    fi

    # 4) HADOOP_CONF_DIR 확인 및 탐색
    if [ ! -d "$HADOOP_CONF_DIR" ]; then
        for d in /etc/hadoop/conf /opt/hadoop*/etc/hadoop /usr/lib/hadoop/etc/hadoop /usr/local/hadoop/etc/hadoop; do
            if [ -d "$d" ]; then
                HADOOP_CONF_DIR="$d"
                break
            fi
        done
    fi

    # 5) 패키지 매니저 확인
    if [ -z "$HADOOP_BIN" ] && [ -z "$hdfs_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'hadoop' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'hadoop' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$HADOOP_BIN" ] || [ -n "$hdfs_bin" ] || [ -d "$HADOOP_CONF_DIR" ]; then
        APP_FOUND="true"
    fi
}

''',
        'Ceph': '''# --- Pre-flight: Ceph 설치 확인 및 경로 탐지 ---
CEPH_BIN=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    CEPH_BIN=$(command -v ceph 2>/dev/null)
    local rados_bin
    rados_bin=$(command -v rados 2>/dev/null)

    # 2) 프로세스에서 ceph-mon/ceph-osd 탐지
    if ps -ef 2>/dev/null | grep -qE '[c]eph-mon|[c]eph-osd|[c]eph-mgr'; then
        APP_FOUND="true"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ ! -f "$CEPH_CONF" ]; then
        for f in /etc/ceph/ceph.conf /usr/local/etc/ceph/ceph.conf; do
            if [ -f "$f" ]; then
                CEPH_CONF="$f"
                break
            fi
        done
    fi

    # 4) 패키지 매니저 확인
    if [ -z "$CEPH_BIN" ] && [ -z "$rados_bin" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'ceph-common\\|ceph-mon' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'ceph' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$CEPH_BIN" ] || [ -n "$rados_bin" ] || [ -f "$CEPH_CONF" ]; then
        APP_FOUND="true"
    fi
}

''',
    }

    return detect_functions.get(app_key, f'''# --- Pre-flight: {platform} 설치 확인 ---
APP_FOUND="false"

detect_app() {{
    APP_FOUND="true"
}}

''')


def _build_json_output(platform, total_items, is_esxi=False):
    """Build JSON output section."""
    if is_esxi:
        return f'''###############################################################################
# Generate JSON output
###############################################################################

# System info
SYS_HOSTNAME=$(hostname 2>/dev/null)
SYS_OS="VMware ESXi"
SYS_KERNEL=$(uname -r 2>/dev/null)
SYS_DATE=$(date '+%Y-%m-%d %H:%M:%S')
SYS_IP=$(esxcli network ip interface ipv4 get 2>/dev/null | awk 'NR>1 {{print $2}}' | head -1)

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
{{
    echo '{{'
    echo '  "scan_info": {{'
    echo "    \\"hostname\\": \\"$SYS_HOSTNAME\\","
    echo "    \\"os\\": \\"$SYS_OS\\","
    echo "    \\"kernel\\": \\"$SYS_KERNEL\\","
    echo "    \\"ip\\": \\"$SYS_IP\\","
    echo "    \\"scan_date\\": \\"$SYS_DATE\\","
    echo '    "platform": "{platform}",'
    echo '    "guide_sources": ['
    echo '      "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)",'
    echo '      "클라우드 취약점 점검 가이드 (2024)"'
    echo '    ]'
    echo '  }},'
    echo '  "summary": {{'
    echo "    \\"total\\": $total_checks,"
    echo "    \\"양호\\": $good_count,"
    echo "    \\"취약\\": $vuln_count,"
    echo "    \\"N/A\\": $na_count,"
    echo "    \\"수동점검\\": $manual_count"
    echo '  }},'
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
    echo '}}'
}} > "$OUTPUT_FILE"

echo "===== {platform} CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
'''
    else:
        return f'''###############################################################################
# Generate JSON output
###############################################################################

# System info
SYS_HOSTNAME=$(hostname 2>/dev/null)
SYS_OS=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d'"' -f2)
SYS_KERNEL=$(uname -r 2>/dev/null)
SYS_DATE=$(date '+%Y-%m-%d %H:%M:%S')
SYS_IP=$(hostname -I 2>/dev/null | awk '{{print $1}}')

# Count results
total_checks=${{#results[@]}}
good_count=0
vuln_count=0
na_count=0
manual_count=0

for r in "${{results[@]}}"; do
    case "$r" in
        *'"status":"양호"'*) good_count=$((good_count + 1)) ;;
        *'"status":"취약"'*) vuln_count=$((vuln_count + 1)) ;;
        *'"status":"N/A"'*) na_count=$((na_count + 1)) ;;
        *'"status":"수동점검"'*) manual_count=$((manual_count + 1)) ;;
    esac
done

# Build JSON
{{
    echo '{{'
    echo '  "scan_info": {{'
    echo "    \\"hostname\\": \\"$SYS_HOSTNAME\\","
    echo "    \\"os\\": \\"$SYS_OS\\","
    echo "    \\"kernel\\": \\"$SYS_KERNEL\\","
    echo "    \\"ip\\": \\"$SYS_IP\\","
    echo "    \\"scan_date\\": \\"$SYS_DATE\\","
    echo '    "platform": "{platform}",'
    echo '    "guide_sources": ['
    echo '      "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)",'
    echo '      "클라우드 취약점 점검 가이드 (2024)"'
    echo '    ]'
    echo '  }},'
    echo '  "summary": {{'
    echo "    \\"total\\": $total_checks,"
    echo "    \\"양호\\": $good_count,"
    echo "    \\"취약\\": $vuln_count,"
    echo "    \\"N/A\\": $na_count,"
    echo "    \\"수동점검\\": $manual_count"
    echo '  }},'
    echo '  "results": ['

    first=true
    for r in "${{results[@]}}"; do
        if [ "$first" = true ]; then
            echo "    $r"
            first=false
        else
            echo "    ,$r"
        fi
    done

    echo '  ]'
    echo '}}'
}} > "$OUTPUT_FILE"

echo "===== {platform} CCE 취약점 진단 완료 ====="
echo ""
echo "결과 요약:"
echo "  총 점검 항목: $total_checks"
echo "  양호: $good_count"
echo "  취약: $vuln_count"
echo "  N/A: $na_count"
echo "  수동점검: $manual_count"
echo ""
echo "결과 파일: $OUTPUT_FILE"
'''


# ── PowerShell script builder ────────────────────────────────────────────────

def build_powershell_script(items):
    """Build a complete PowerShell script for Windows."""
    total_items = len(items)

    parts = []
    parts.append(f'''#Requires -RunAsAdministrator
###############################################################################
# Windows CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: .\\windows_cce_check.ps1 [-OutputFile <path>]
# Output: JSON file with all check results
###############################################################################

param(
    [string]$OutputFile = "cce_check_result_windows_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$ErrorActionPreference = "SilentlyContinue"

# --- JSON helper ---
$script:results = @()

function Write-ResultTrace {{
    param(
        [string]$Code,
        [string]$Status,
        [string]$Title,
        [string]$Command,
        [string]$CurrentState,
        [string]$Detail
    )

    $commandText = (($Command ?? '') -replace "`r?`n", ' ').Trim()
    $stateText = (($CurrentState ?? '') -replace "`r?`n", ' ').Trim()
    $detailText = (($Detail ?? '') -replace "`r?`n", ' ').Trim()
    if (-not $commandText) {{ $commandText = '-' }}
    if (-not $stateText) {{ $stateText = '-' }}
    if (-not $detailText) {{ $detailText = '-' }}

    Write-Host ""
    Write-Host "[TRACE] code=$Code status=$Status title=$Title"
    Write-Host "[TRACE] command=$commandText"
    Write-Host "[TRACE] current_state=$stateText"
    Write-Host "[TRACE] detail=$detailText"
}}

function Add-Result {{
    param(
        [string]$Code,
        [string]$Category,
        [string]$Title,
        [string]$Importance,
        [string]$Status,
        [string]$Detail,
        [string]$Source,
        [string]$Command,
        [string]$CurrentState,
        [string]$Remediation
    )

    $script:results += [PSCustomObject]@{{
        code          = $Code
        category      = $Category
        title         = $Title
        importance    = $Importance
        status        = $Status
        detail        = $Detail
        source        = $Source
        command       = $Command
        current_state = $CurrentState
        remediation   = $Remediation
    }}
    Write-ResultTrace -Code $Code -Status $Status -Title $Title -Command $Command -CurrentState $CurrentState -Detail $Detail
}}

function Get-OutputSummary {{
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {{ return "" }}
    return (($Text -replace "`r?`n", ' ') -replace '\\s+', ' ').Trim()
}}

function Get-FirstNumber {{
    param([string]$Text)
    $match = [regex]::Match(($Text ?? ''), '\\d+')
    if ($match.Success) {{ return [int]$match.Value }}
    return $null
}}

function Test-NegativeMarker {{
    param([string]$Text)
    return [regex]::IsMatch(($Text ?? ''), '(^|[^A-Za-z0-9_-])(0|false|off|disabled|inactive|none|no|deny|never)([^A-Za-z0-9_-]|$)|계정 사용 안함|사용 안함|비활성', 'IgnoreCase')
}}

function Test-PositiveMarker {{
    param([string]$Text)
    return [regex]::IsMatch(($Text ?? ''), '(^|[^A-Za-z0-9_-])(1|true|on|enabled|enable|active|yes|allow)([^A-Za-z0-9_-]|$)|활성', 'IgnoreCase')
}}

''')

    # Generate check functions
    func_names = []
    for item in items:
        func_code, func_name = generate_ps_check_function(item)
        parts.append(func_code)
        func_names.append((item['code'], func_name))

    # Execution section
    parts.append(f'''
###############################################################################
# Execute all checks
###############################################################################

Write-Host "===== Windows CCE 취약점 진단 시작 =====" -ForegroundColor Cyan
Write-Host "호스트: $env:COMPUTERNAME"
Write-Host "날짜: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

$totalChecks = {total_items}
$currentCheck = 0

function Show-Progress {{
    param([string]$CheckName)
    $script:currentCheck++
    Write-Progress -Activity "CCE 취약점 진단" -Status "$currentCheck/$totalChecks - $CheckName 점검 중..." -PercentComplete (($script:currentCheck / $totalChecks) * 100)
}}

''')

    for code, func_name in func_names:
        code_safe = code.split('/')[0].strip()
        parts.append(f'Show-Progress "{code_safe}"; {func_name}')

    parts.append(f'''

Write-Progress -Activity "CCE 취약점 진단" -Completed

###############################################################################
# Generate JSON output
###############################################################################

$scanInfo = [PSCustomObject]@{{
    hostname      = $env:COMPUTERNAME
    os            = (Get-CimInstance Win32_OperatingSystem).Caption
    kernel        = [System.Environment]::OSVersion.Version.ToString()
    ip            = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -notlike "*Loopback*" }} | Select-Object -First 1).IPAddress
    scan_date     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    platform      = "Windows"
    guide_sources = @(
        "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)",
        "클라우드 취약점 점검 가이드 (2024)"
    )
}}

$goodCount = ($script:results | Where-Object {{ $_.status -eq "양호" }}).Count
$vulnCount = ($script:results | Where-Object {{ $_.status -eq "취약" }}).Count
$naCount = ($script:results | Where-Object {{ $_.status -eq "N/A" }}).Count
$manualCount = ($script:results | Where-Object {{ $_.status -eq "수동점검" }}).Count

$summary = [PSCustomObject]@{{
    total    = $script:results.Count
    "양호"   = $goodCount
    "취약"   = $vulnCount
    "N/A"    = $naCount
    "수동점검" = $manualCount
}}

$output = [PSCustomObject]@{{
    scan_info = $scanInfo
    summary   = $summary
    results   = $script:results
}}

$output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host ""
Write-Host "===== Windows CCE 취약점 진단 완료 =====" -ForegroundColor Cyan
Write-Host ""
Write-Host "결과 요약:" -ForegroundColor Yellow
Write-Host "  총 점검 항목: $($script:results.Count)"
Write-Host "  양호: $goodCount" -ForegroundColor Green
Write-Host "  취약: $vulnCount" -ForegroundColor Red
Write-Host "  N/A: $naCount" -ForegroundColor Gray
Write-Host "  수동점검: $manualCount" -ForegroundColor Yellow
Write-Host ""
Write-Host "결과 파일: $OutputFile"
''')

    return '\n'.join(parts)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("Excel 데이터 읽기...")
    items_by_target = read_excel_items()

    print(f"총 {sum(len(v) for v in items_by_target.values())}개 항목, {len(items_by_target)}개 대상")

    generated = 0
    for app_key, app_def in APP_DEFS.items():
        items = items_by_target.get(app_key, [])
        if not items:
            print(f"  [SKIP] {app_key}: 항목 없음")
            continue

        script_name = app_def['script']
        output_path = OUTPUT_DIR / script_name

        if app_def.get('powershell'):
            script_content = build_powershell_script(items)
        else:
            script_content = build_bash_script(app_key, app_def, items)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(script_content)

        # Make bash scripts executable
        if not app_def.get('powershell'):
            os.chmod(output_path, 0o755)

        print(f"  [OK] {script_name} ({len(items)}개 항목)")
        generated += 1

    print(f"\n완료: {generated}개 스크립트 생성 → {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
