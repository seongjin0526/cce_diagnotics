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
