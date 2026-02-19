#!/usr/bin/env python3
"""
CCE 애플리케이션별 진단 스크립트 자동 생성기
진단항목통합.xlsx를 읽어 21개 애플리케이션별 진단 스크립트를 생성한다.
linux_cce_check.sh와 동일한 패턴의 JSON 출력 구조를 따른다.
"""
import os
import re
import textwrap
from openpyxl import load_workbook

BASE_DIR = '/home/seongjin0526/cce_vuln_check'
EXCEL_FILE = os.path.join(BASE_DIR, '진단항목통합.xlsx')
OUTPUT_DIR = os.path.join(BASE_DIR, 'scripts')

os.makedirs(OUTPUT_DIR, exist_ok=True)

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
        'helpers': ['docker_helper'],
    },
    'K8s(Master)': {
        'script': 'k8s_master_cce_check.sh', 'platform': 'Kubernetes(Master)',
        'helpers': ['k8s_helper'],
    },
    'K8s(Worker)': {
        'script': 'k8s_worker_cce_check.sh', 'platform': 'Kubernetes(Worker)',
        'helpers': ['k8s_helper'],
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
            'code': code.strip(),
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
    """Extract command lines (starting with # or $) from diagnosis text."""
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
    return commands


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


def classify_check_type(diag_text, commands):
    """Classify the check type based on diagnosis text and commands."""
    diag_lower = diag_text.lower()

    if '인터뷰' in diag_text and not commands:
        return 'manual'

    for cmd in commands:
        if re.search(r'ls\s+-[la]', cmd) or 'chmod' in cmd or 'chown' in cmd:
            return 'file_perm'
        if 'grep' in cmd and ('conf' in cmd or 'cfg' in cmd or '.ini' in cmd or '.xml' in cmd or '.yaml' in cmd or '.yml' in cmd):
            return 'config_check'
        if 'systemctl' in cmd or 'service ' in cmd:
            return 'service_check'
        if 'curl' in cmd or 'http' in cmd.lower():
            return 'api_check'
        if any(x in cmd for x in ['virsh', 'xe ', 'esxcli', 'docker', 'kubectl',
                                    'mysql', 'psql', 'mongo', 'redis-cli',
                                    'hadoop', 'ceph', 'rados']):
            return 'cli_tool'

    if commands:
        return 'command_check'

    return 'manual'


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
    cmd = cmd.replace('–', '-')
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
    if re.match(r'^\s*(rm|rmdir|del|format|mkfs|dd|shutdown|reboot|halt|poweroff)\b', cmd):
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
    commands = extract_commands_from_diagnosis(diag)
    good_criteria, bad_criteria = extract_good_bad_criteria(diag)
    check_type = classify_check_type(diag, commands)

    code_escaped = escape_bash_string(code)

    # Build the check logic
    lines = []
    lines.append(f'# {code}: {item["title"]}')
    lines.append(f'{func_name}() {{')
    lines.append(f'    local status="양호"')
    lines.append(f'    local detail=""')

    # Sanitize extracted commands
    commands = [sanitize_command(c) for c in commands]
    commands = [c for c in commands if is_safe_command(c)]

    # Build command string from extracted commands
    if commands:
        cmd_str = '; '.join(commands[:3])
        cmd_str = escape_bash_string(cmd_str)
    else:
        cmd_str = '수동점검 필요'
    lines.append(f'    local cmd="{cmd_str}"')
    lines.append(f'    local cur_state=""')
    lines.append(f'    local remediation="{remediation}"')
    lines.append('')

    if check_type == 'manual':
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="수동 점검 필요 항목입니다. {escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')
        # Try to collect some info if there are safe commands
        if commands and is_safe_command(commands[0]):
            safe_cmd = commands[0]
            lines.append(f'    local output')
            lines.append(f'    output=$({safe_cmd} 2>/dev/null || echo "명령 실행 실패")')
            lines.append(f'    cur_state="$output"')
    elif check_type == 'file_perm':
        _generate_file_perm_check(lines, diag, commands, good_criteria)
    elif check_type == 'config_check':
        _generate_config_check(lines, diag, commands, good_criteria, bad_criteria)
    elif check_type == 'service_check':
        _generate_service_check(lines, diag, commands, good_criteria)
    elif check_type == 'api_check':
        _generate_api_check(lines, diag, commands, good_criteria)
    elif check_type == 'cli_tool':
        _generate_cli_check(lines, diag, commands, good_criteria, bad_criteria, app_def)
    else:  # command_check
        _generate_command_check(lines, diag, commands, good_criteria, bad_criteria)

    lines.append('')
    lines.append(f'    add_result "{code_escaped}" "{category}" "{title}" "{importance}" "$status" "$detail" "{source}" "$cmd" "$cur_state" "$remediation"')
    lines.append(f'}}')
    lines.append('')

    return '\n'.join(lines), func_name


def _extract_file_paths(diag, commands):
    """Extract file paths from diagnostic text/commands."""
    paths = []
    for cmd in commands:
        # Look for absolute paths
        for m in re.finditer(r'(/[a-zA-Z0-9_./-]+(?:\.\w+)?)', cmd):
            p = m.group(1)
            if len(p) > 4 and not p.startswith('/bin') and not p.startswith('/usr/bin'):
                paths.append(p)
    # Also look for paths in diagnosis text
    for m in re.finditer(r'(/etc/[a-zA-Z0-9_./-]+)', diag):
        p = m.group(1)
        if p not in paths:
            paths.append(p)
    return paths


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
    m = re.search(r'소유자가?\s*(root|mysql|postgres|redis|mongod|elasticsearch|www-data|apache|nginx|tomcat|ceph|hadoop|nobody)', diag, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return 'root'


def _generate_file_perm_check(lines, diag, commands, good_criteria):
    """Generate file permission check logic."""
    paths = _extract_file_paths(diag, commands)
    expected_perm = _extract_perm_info(diag)
    expected_owner = _extract_owner_info(diag)

    if not paths:
        paths = ['/etc/unknown_config_file']

    # Use the first concrete path, or build a pattern
    target_files = paths[:3]

    lines.append(f'    local vuln_found=false')
    for f in target_files:
        # Handle wildcard/template paths
        if '[' in f or '디렉' in f:
            continue
        var_name = re.sub(r'[^a-zA-Z0-9]', '_', f.strip('/'))
        lines.append(f'    if [ -e "{f}" ]; then')
        lines.append(f'        local result_{var_name}')
        lines.append(f'        result_{var_name}=$(check_file_owner_perm "{f}" "{expected_owner}" "{expected_perm}")')
        lines.append(f'        cur_state+="{f}: $result_{var_name}; "')
        lines.append(f'        case "$result_{var_name}" in')
        lines.append(f'            VULN*) vuln_found=true; detail+="{f} 소유자/권한 부적절($result_{var_name}). " ;;')
        lines.append(f'            GOOD*) detail+="{f} 소유자/권한 적절($result_{var_name}). " ;;')
        lines.append(f'            NOT_FOUND) detail+="{f} 파일 없음. " ;;')
        lines.append(f'        esac')
        lines.append(f'    else')
        lines.append(f'        detail+="{f} 파일 없음. "')
        lines.append(f'        cur_state+="{f}: 파일 없음; "')
        lines.append(f'    fi')
    lines.append(f'    if [ "$vuln_found" = "true" ]; then')
    lines.append(f'        status="취약"')
    lines.append(f'    fi')
    lines.append(f'    [ -z "$detail" ] && detail="{escape_bash_string(good_criteria)}" && cur_state="점검 대상 파일 없음"')


def _generate_config_check(lines, diag, commands, good_criteria, bad_criteria):
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

    if not config_file:
        # Fallback: search for any path
        paths = _extract_file_paths(diag, commands)
        config_file = paths[0] if paths else '/etc/app/config'

    # Clean up template paths and Korean text
    config_file_clean = re.sub(r'\[.*?\]', '*', config_file)
    config_file_clean = re.sub(r'[^\x00-\x7F*]', '', config_file_clean)  # remove non-ASCII
    config_file_clean = config_file_clean.strip()
    if not config_file_clean or config_file_clean == '*':
        config_file_clean = '/etc/app/config'

    lines.append(f'    local config_file="{config_file_clean}"')
    lines.append(f'    # Expand wildcards/find actual config')
    lines.append(f'    local actual_config')
    lines.append(f'    actual_config=$(ls $config_file 2>/dev/null | head -1)')
    lines.append(f'    if [ -z "$actual_config" ]; then')
    lines.append(f'        detail="설정 파일 없음($config_file). "')
    lines.append(f'        cur_state="설정 파일 없음"')
    lines.append(f'        status="N/A"')
    lines.append(f'    else')
    if grep_pattern:
        grep_safe = escape_bash_string(grep_pattern)
        lines.append(f'        local grep_result')
        lines.append(f'        grep_result=$(grep -i "{grep_safe}" "$actual_config" 2>/dev/null)')
        lines.append(f'        cur_state="$grep_result"')
        lines.append(f'        if [ -n "$grep_result" ]; then')
        lines.append(f'            detail="설정 확인됨: $grep_result. "')
        lines.append(f'        else')
        lines.append(f'            detail="설정 미확인: {grep_safe} 패턴 미발견. "')
        lines.append(f'            status="취약"')
        lines.append(f'        fi')
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
        m = re.search(r'systemctl\s+\w+\s+([\w.-]+)', cmd)
        if m:
            service_name = m.group(1)
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


def _generate_api_check(lines, diag, commands, good_criteria):
    """Generate API/curl-based check logic."""
    curl_cmd = ''
    for cmd in commands:
        if 'curl' in cmd:
            curl_cmd = cmd
            break
    if curl_cmd:
        curl_safe = escape_bash_string(curl_cmd)
        lines.append(f'    local api_result')
        lines.append(f'    api_result=$({curl_cmd} 2>/dev/null)')
        lines.append(f'    if [ -n "$api_result" ]; then')
        lines.append(f'        cur_state="$api_result"')
        lines.append(f'        detail="API 응답 확인됨. 수동 검증 필요. "')
        lines.append(f'        status="수동점검"')
        lines.append(f'    else')
        lines.append(f'        cur_state="API 응답 없음"')
        lines.append(f'        detail="API 호출 실패 또는 서비스 미실행. "')
        lines.append(f'        status="N/A"')
        lines.append(f'    fi')
    else:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="API 기반 점검 항목. {escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')


def _generate_cli_check(lines, diag, commands, good_criteria, bad_criteria, app_def):
    """Generate CLI tool-specific check logic (docker, kubectl, virsh, etc)."""
    safe_commands = [c for c in commands if is_safe_command(c)]
    if not safe_commands:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="{escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')
        return

    primary_cmd = safe_commands[0]

    lines.append(f'    local output')
    lines.append(f'    output=$({primary_cmd} 2>/dev/null)')
    lines.append(f'    cur_state="$output"')
    lines.append('')

    lines.append(f'    if [ -z "$output" ]; then')
    lines.append(f'        detail="명령 실행 결과 없음 또는 대상 미설치. "')
    lines.append(f'        status="N/A"')
    lines.append(f'    else')
    lines.append(f'        detail="명령 실행 결과 확인. 수동 검증 필요. "')
    lines.append(f'        status="수동점검"')
    lines.append(f'    fi')


def _generate_command_check(lines, diag, commands, good_criteria, bad_criteria):
    """Generate generic command execution check."""
    safe_commands = [c for c in commands if is_safe_command(c)]
    if not safe_commands:
        lines.append(f'    status="수동점검"')
        lines.append(f'    detail="{escape_bash_string(good_criteria)}"')
        lines.append(f'    cur_state="수동점검 필요"')
        return

    primary_cmd = safe_commands[0]

    lines.append(f'    local output')
    lines.append(f'    output=$({primary_cmd} 2>/dev/null)')
    lines.append(f'    cur_state="$output"')
    lines.append('')
    lines.append(f'    if [ -z "$output" ]; then')
    lines.append(f'        detail="명령 실행 결과 없음. "')

    # Determine if empty = good or bad
    if '않' in good_criteria or '없' in good_criteria or '미' in good_criteria:
        lines.append(f'        # 결과 없음이 양호한 경우')
    else:
        lines.append(f'        status="수동점검"')

    lines.append(f'    else')
    lines.append(f'        detail="결과: $(echo "$output" | head -5 | tr \'\\n\' \' \'). "')
    lines.append(f'        status="수동점검"')
    lines.append(f'    fi')


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
        # secedit, net user, wmic, auditpol, fsutil, etc
        for keyword in ['secedit', 'net user', 'net share', 'wmic', 'auditpol',
                         'fsutil', 'reg query', 'sc query', 'netstat', 'winver',
                         'systeminfo', 'icacls', 'netsh', 'schtasks']:
            if keyword in stripped.lower() and not stripped.startswith('[') and not stripped.startswith('※'):
                commands.append(stripped)
                break
    return commands


def _generate_windows_check_logic(lines, diag, commands, good_criteria, bad_criteria, item):
    """Generate Windows PowerShell check logic."""
    diag_lower = diag.lower()

    # Categorize Windows checks
    if 'secedit' in diag_lower:
        _gen_windows_secedit_check(lines, diag, commands, good_criteria)
    elif 'net user' in diag_lower:
        _gen_windows_net_check(lines, diag, commands, good_criteria)
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
        lines.append(f'        $detail = "명령 실행 결과 확인. 수동 검증 필요."')
        lines.append(f'        $status = "수동점검"')
        lines.append(f'    }} catch {{')
        lines.append(f'        $curState = "명령 실행 실패: $_"')
        lines.append(f'        $detail = "점검 명령 실행 실패."')
        lines.append(f'        $status = "N/A"')
        lines.append(f'    }}')
    else:
        lines.append(f'    $status = "수동점검"')
        lines.append(f'    $detail = "수동 점검 필요 항목입니다. {escape_ps_string(good_criteria)}"')
        lines.append(f'    $curState = "수동점검 필요"')


def _gen_windows_secedit_check(lines, diag, commands, good_criteria):
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

    lines.append(f'    # Export security policy')
    lines.append(f'    $tempFile = "$env:TEMP\\secedit_export.cfg"')
    lines.append(f'    secedit /export /cfg $tempFile 2>$null | Out-Null')
    lines.append(f'    if (Test-Path $tempFile) {{')
    if policy_key:
        lines.append(f'        $content = Get-Content $tempFile | Select-String "{policy_key}"')
        lines.append(f'        if ($content) {{')
        lines.append(f'            $curState = $content.ToString().Trim()')
        lines.append(f'            $detail = "보안정책 확인됨: $curState"')
        lines.append(f'            # 수동 검증 필요 - 값의 적절성은 정책에 따라 다름')
        lines.append(f'            $status = "수동점검"')
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


def _gen_windows_net_check(lines, diag, commands, good_criteria):
    """Generate net user-based check."""
    lines.append(f'    try {{')
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
    detail=$(echo "$detail" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
    command=$(echo "$command" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/\\t/ /g' | tr '\\n' ' ' | sed 's/  */ /g')

    results+=("{\\"code\\":\\"$code\\",\\"category\\":\\"$category\\",\\"title\\":\\"$title\\",\\"importance\\":\\"$importance\\",\\"status\\":\\"$status\\",\\"detail\\":\\"$detail\\",\\"source\\":\\"$source\\",\\"command\\":\\"$command\\",\\"current_state\\":\\"$current_state\\",\\"remediation\\":\\"$remediation\\"}")
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

'''


def _build_esxi_helpers():
    """Build ESXi-compatible (BusyBox ash) helper functions."""
    return '''# --- JSON helper functions (ESXi BusyBox compatible) ---
RESULTS_FILE="$TEMP_DIR/results.txt"
: > "$RESULTS_FILE"

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

    # Escape strings for JSON
    detail=$(echo "$detail" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    title=$(echo "$title" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
    command=$(echo "$command" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    current_state=$(echo "$current_state" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')
    remediation=$(echo "$remediation" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g; s/	/ /g' | tr '\\n' ' ' | sed 's/  */ /g')

    echo "{\\"code\\":\\"$code\\",\\"category\\":\\"$category\\",\\"title\\":\\"$title\\",\\"importance\\":\\"$importance\\",\\"status\\":\\"$status\\",\\"detail\\":\\"$detail\\",\\"source\\":\\"$source\\",\\"command\\":\\"$command\\",\\"current_state\\":\\"$current_state\\",\\"remediation\\":\\"$remediation\\"}" >> "$RESULTS_FILE"
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
    if [ "$owner" = "$expected_owner" ]; then
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
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -N -e "$query" 2>/dev/null
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
    if [ -n "$DB_PASS" ] && [ -n "$DB_USER" ]; then
        mongosh --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>/dev/null || \
        mongo --host "$DB_HOST" --port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" --authenticationDatabase admin --quiet --eval "$query" "$db" 2>/dev/null
    else
        mongosh --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>/dev/null || \
        mongo --host "$DB_HOST" --port "$DB_PORT" --quiet --eval "$query" "$db" 2>/dev/null
    fi
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

''',
        'nginx_helper': '''# --- Nginx helper ---
NGINX_CONF=""
for f in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf; do
    if [ -f "$f" ]; then
        NGINX_CONF="$f"
        break
    fi
done

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
MYSQL_CONF=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    MYSQL_BIN=$(command -v mysql 2>/dev/null)
    MYSQLD_BIN=$(command -v mysqld 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$MYSQLD_BIN" ]; then
        MYSQLD_BIN=$(ps -ef 2>/dev/null | grep '[m]ysqld' | awk '{for(i=1;i<=NF;i++) if($i ~ /mysqld$/) print $i}' | head -1)
    fi

    # 프로세스에서 --defaults-file 추출
    local defaults_file
    defaults_file=$(ps -ef 2>/dev/null | grep '[m]ysqld' | sed -n 's/.*--defaults-file=\\([^ ]*\\).*/\\1/p' | head -1)
    if [ -n "$defaults_file" ] && [ -f "$defaults_file" ]; then
        MYSQL_CONF="$defaults_file"
    fi

    # 3) 공통 설정 파일 경로 탐색
    if [ -z "$MYSQL_CONF" ]; then
        for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf ~/.my.cnf /usr/local/mysql/my.cnf; do
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
MSSQL_CONF=""
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
PG_DATA=""
PG_CONF=""
PG_HBA=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    PSQL_BIN=$(command -v psql 2>/dev/null)
    local pg_config_bin
    pg_config_bin=$(command -v pg_config 2>/dev/null)

    # 2) 프로세스에서 data dir 추출
    local pg_proc
    pg_proc=$(ps -ef 2>/dev/null | grep '[p]ostgres.*-D' | head -1)
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
        for d in /var/lib/postgresql/*/main /var/lib/pgsql/*/data /var/lib/pgsql/data /usr/local/pgsql/data; do
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
REDIS_CONF=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    REDIS_CLI=$(command -v redis-cli 2>/dev/null)
    local redis_server_bin
    redis_server_bin=$(command -v redis-server 2>/dev/null)

    # 2) 프로세스에서 config 경로 추출
    local redis_proc
    redis_proc=$(ps -ef 2>/dev/null | grep '[r]edis-server' | head -1)
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
        for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf /usr/local/etc/redis.conf; do
            if [ -f "$f" ]; then
                REDIS_CONF="$f"
                break
            fi
        done
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
ES_CONF=""
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
        for f in /etc/elasticsearch/elasticsearch.yml /usr/local/etc/elasticsearch/elasticsearch.yml; do
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
MONGOD_CONF=""
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
NGINX_CONF=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NGINX_BIN=$(command -v nginx 2>/dev/null)

    # 2) 프로세스에서 탐지
    if [ -z "$NGINX_BIN" ]; then
        local nginx_proc
        nginx_proc=$(ps -ef 2>/dev/null | grep '[n]ginx.*master' | head -1)
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
        tomcat_proc=$(ps -ef 2>/dev/null | grep -E '[c]atalina|[t]omcat' | head -1)
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
            dpkg -l 2>/dev/null | grep -qi 'docker-ce\\|docker.io' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
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

''',
        'K8s(Worker)': '''# --- Pre-flight: Kubernetes Worker 설치 확인 및 경로 탐지 ---
KUBECTL_BIN=""
KUBELET_CONF=""
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
LIBVIRT_CONF=""
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
PHP_INI=""
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    PHP_BIN=$(command -v php 2>/dev/null)

    # 2) 프로세스에서 php-fpm 탐지
    if ps -ef 2>/dev/null | grep -q '[p]hp-fpm'; then
        APP_FOUND="true"
    fi

    # 3) php --ini 로 설정 경로 추출
    if [ -n "$PHP_BIN" ]; then
        PHP_INI=$("$PHP_BIN" --ini 2>/dev/null | sed -n 's/.*Loaded Configuration File:[[:space:]]*\\(.*\\)/\\1/p')
        if [ -z "$PHP_INI" ] || [ "$PHP_INI" = "(none)" ]; then
            PHP_INI=""
        fi
    fi

    # 4) 공통 설정 파일 경로 탐색
    if [ -z "$PHP_INI" ]; then
        for f in /etc/php/*/cli/php.ini /etc/php/*/fpm/php.ini /etc/php.ini /usr/local/etc/php/php.ini; do
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
APP_FOUND="false"

detect_app() {
    # 1) command -v 로 바이너리 탐지
    NODE_BIN=$(command -v node 2>/dev/null)
    NPM_BIN=$(command -v npm 2>/dev/null)

    # 2) 프로세스에서 node 탐지
    if [ -z "$NODE_BIN" ]; then
        if ps -ef 2>/dev/null | grep -q '[n]ode '; then
            APP_FOUND="true"
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

    # 4) 패키지 매니저 확인
    if [ -z "$NODE_BIN" ] && [ "$APP_FOUND" = "false" ]; then
        if command -v dpkg &>/dev/null; then
            dpkg -l 2>/dev/null | grep -qi 'nodejs' && APP_FOUND="true"
        elif command -v rpm &>/dev/null; then
            rpm -qa 2>/dev/null | grep -qi 'nodejs' && APP_FOUND="true"
        fi
    fi

    # 판정
    if [ -n "$NODE_BIN" ]; then
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
        output_path = os.path.join(OUTPUT_DIR, script_name)

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
