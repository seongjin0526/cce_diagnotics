#!/usr/bin/env python3
"""
CCE 취약점 항목 통합 → Excel 출력 스크립트
두 PDF에서 추출한 CCE 항목을 애플리케이션별로 통합하여
진단항목통합.xlsx로 출력한다.

컬럼: 진단대상, 중요도, 항목번호, 항목명, 진단방법, 조치방법, 조치영향도
"""
import fitz
import re
import json
import os
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side

BASE_DIR = '/home/seongjin0526/cce_vuln_check'
CLOUD_PDF = os.path.join(BASE_DIR, '클라우드 취약점 점검 가이드(2024).pdf')
MAIN_PDF = os.path.join(BASE_DIR, '주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf')

CLOUD_OFFSET = 5

# All cloud guide sections with content page numbers (for calculating ranges)
CLOUD_SECTIONS_ALL = [
    ('KVM', 7), ('Xenserver', 15), ('ESXi', 61), ('Hyper-V', 101),
    ('Server(Linux)', 119), ('Server(Windows)', 163),
    ('PC(Windows)', 225), ('PC(MAC)', 253), ('PC(Linux)', 283),
    ('MY-SQL', 299), ('MS-SQL', 311), ('Redis', 325), ('Elasticsearch', 335),
    ('MongoDB', 351), ('PostgresSQL', 363), ('Cubrid', 377), ('CouchDB', 389),
    ('SQLite', 407), ('Tibero', 417), ('InfluxDB', 429), ('Oracle', 441),
    ('Apache', 457), ('Nginx', 467), ('IIS', 477), ('Tomcat', 493),
    ('Docker', 505), ('Kubernetes(Master)', 543), ('Kubernetes(Worker)', 565),
    ('OpenStack', 579), ('PHP', 639), ('RabbitMQ', 647), ('Node.js', 659),
    ('Ceph', 671), ('Hadoop', 681), ('Network Device', 693),
    ('정보보호시스템', 721), ('스토리지', 737), ('BOSH(Director)', 745), ('BOSH(UAA)', 753),
]

# Target sections (display name -> cloud guide section name)
CLOUD_TARGETS = {
    'KVM': 'KVM',
    'Xenserver': 'Xenserver',
    'ESXi': 'ESXi',
    'Linux': 'Server(Linux)',
    'Windows': 'Server(Windows)',
    'MY-SQL': 'MY-SQL',
    'MS-SQL': 'MS-SQL',
    'Redis': 'Redis',
    'Elasticsearch': 'Elasticsearch',
    'MongoDB': 'MongoDB',
    'PostgreSQL': 'PostgresSQL',
    'Apache': 'Apache',
    'Nginx': 'Nginx',
    'Tomcat': 'Tomcat',
    'Docker': 'Docker',
    'K8s(Master)': 'Kubernetes(Master)',
    'K8s(Worker)': 'Kubernetes(Worker)',
    'PHP': 'PHP',
    'NodeJS': 'Node.js',
    'Hadoop': 'Hadoop',
    'Ceph': 'Ceph',
}

# Main guide chapters (PDF 0-indexed start, end)
MAIN_CHAPTERS = {
    'Ch1_UNIX': {'start': 6, 'end': 171, 'prefix': 'U', 'pattern': r'(U-\d+)\s*\n\s*\(([상중하])\)'},
    'Ch2_Windows': {'start': 171, 'end': 270, 'prefix': 'W', 'pattern': r'(W-\d+)\s*\n\s*\(([상중하])\)'},
    'Ch3_Web': {'start': 270, 'end': 352, 'prefix': 'WEB', 'pattern': r'(WEB-\d+)\s*\n\s*\(([상중하])\)'},
    'Ch8_DBMS': {'start': 592, 'end': 669, 'prefix': 'D', 'pattern': r'(D-\d+)\s*\n\s*\(([상중하])\)'},
    'Ch11_Virtual': {'start': 786, 'end': 850, 'prefix': 'HV', 'pattern': r'(HV-\d+)\s*\n\s*\(([상중하])\)'},
}

# Main guide chapter -> target app mapping
MAIN_TO_APP = {
    'Ch1_UNIX': ['Linux'],
    'Ch2_Windows': ['Windows'],
    'Ch3_Web': ['Apache', 'Nginx', 'Tomcat'],
    'Ch8_DBMS': ['MY-SQL', 'MS-SQL', 'PostgreSQL'],
    'Ch11_Virtual': ['KVM', 'Xenserver', 'ESXi'],
}


def get_cloud_page_range(section_name):
    """Get PDF page range (0-indexed) for a cloud guide section"""
    for i, (name, start_page) in enumerate(CLOUD_SECTIONS_ALL):
        if name == section_name:
            pdf_start = start_page + CLOUD_OFFSET - 1  # 0-indexed
            if i + 1 < len(CLOUD_SECTIONS_ALL):
                pdf_end = CLOUD_SECTIONS_ALL[i + 1][1] + CLOUD_OFFSET - 1
            else:
                pdf_end = pdf_start + 20
            return pdf_start, pdf_end
    return None, None


def extract_pages_text(doc, start_page, end_page):
    """Extract text from a range of pages (0-indexed)"""
    text_parts = []
    for page_num in range(start_page, min(end_page, len(doc))):
        page = doc[page_num]
        text = page.get_text()
        text_parts.append(f"<<PAGE_{page_num + 1}>>\n{text}")
    return '\n'.join(text_parts)


def clean_text(text):
    """Clean extracted text for display"""
    if not text:
        return ""
    # Remove page markers
    text = re.sub(r'<<PAGE_\d+>>', '', text)
    # Remove common PDF headers/footers
    text = re.sub(r'\d+\s*_\s*클라우드\s*취약점\s*점검\s*가이드', '', text)
    text = re.sub(r'\|\s*한국인터넷진흥원\s*\|', '', text)
    text = re.sub(r'\d{4}\s*주요정보통신기반시설.*?가이드', '', text)
    text = re.sub(r'\d{2}\.\s*(Unix|Windows|가상화|DBMS).*?가이드', '', text)
    text = re.sub(r'2\.\s*보안가이드_\s*\d+', '', text)
    # Clean up whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = text.strip()
    return text


def parse_cloud_section(doc, section_name):
    """Parse a cloud guide section and return list of items"""
    start, end = get_cloud_page_range(section_name)
    if start is None:
        return []

    text = extract_pages_text(doc, start, end)
    items = []

    # Split by pages and find items by 항목설명 marker
    pages = text.split('<<PAGE_')
    current_item = None

    for page_block in pages:
        if not page_block.strip():
            continue

        page_lines = page_block.split('\n', 1)
        if len(page_lines) < 2:
            continue
        page_text = page_lines[1]

        if '항목설명' in page_text:
            if current_item:
                items.append(current_item)

            # Find item name
            lines = page_text.split('\n')
            item_name = ""
            for j, line in enumerate(lines):
                if '항목설명' in line:
                    for k in range(j - 1, -1, -1):
                        candidate = lines[k].strip()
                        if candidate and not re.match(r'^\d+\s*_', candidate) and \
                           not re.match(r'^2\.\d+\.?$', candidate) and \
                           not re.match(r'^[0-9]+$', candidate) and \
                           candidate not in ['보안가이드', '클라우드 취약점 점검 가이드'] and \
                           not candidate.startswith('2. 보안가이드') and \
                           len(candidate) > 1:
                            item_name = candidate
                            break
                    break

            current_item = {
                'name': item_name,
                'raw_text': page_text,
            }
        elif current_item:
            current_item['raw_text'] += '\n' + page_text

    if current_item:
        items.append(current_item)

    # Parse each item's fields
    parsed_items = []
    for item in items:
        raw = item['raw_text']

        # Extract good/bad criteria
        good_criteria = ''
        bad_criteria = ''

        # Find the 진단기준 block (between 항목설명 and 진단방법)
        # The structure is: 양호 ... 취약 ... 진단방법
        criteria_block = re.search(r'(?:진단\s*\n?기준|기준)\s*\n(.*?)(?=진단\s*\n?방법)', raw, re.DOTALL)
        if criteria_block:
            cb = criteria_block.group(1)
            good_m = re.search(r'양호\s*\n?(.*?)(?=취약)', cb, re.DOTALL)
            if good_m:
                good_criteria = good_m.group(1).strip()
            bad_m = re.search(r'취약\s*\n?(.*?)$', cb, re.DOTALL)
            if bad_m:
                bad_criteria = bad_m.group(1).strip()
        else:
            # Fallback: try broader match
            good_match = re.search(r'[◼￭●]?\s*양호\s*\n?(.*?)(?=[◼￭●]?\s*취약)', raw, re.DOTALL)
            if good_match:
                good_criteria = good_match.group(1).strip()
            bad_match = re.search(r'[◼￭●]?\s*취약\s*\n?(.*?)(?=진단\s*\n?방법)', raw, re.DOTALL)
            if bad_match:
                bad_criteria = bad_match.group(1).strip()

        # Extract 진단방법
        diagnosis = ''
        diag_match = re.search(r'진단\s*\n?방법\s*\n(.*?)(?=조치\s*\n?방법)', raw, re.DOTALL)
        if diag_match:
            diagnosis = diag_match.group(1).strip()

        # Extract 조치방법 - capture until 비고 or next 항목설명 or end
        remediation = ''
        remed_match = re.search(r'조치\s*\n?방법\s*\n(.*?)(?=비고\s*\n|$)', raw, re.DOTALL)
        if remed_match:
            remediation = remed_match.group(1).strip()

        # Extract 비고
        note = ''
        note_match = re.search(r'비고\s*\n(.*?)(?=<<PAGE_|$)', raw, re.DOTALL)
        if note_match:
            note = note_match.group(1).strip()

        # Build 진단방법 with criteria
        diagnosis_full = ""
        if good_criteria:
            diagnosis_full += f"[양호] {clean_text(good_criteria)}\n"
        if bad_criteria:
            diagnosis_full += f"[취약] {clean_text(bad_criteria)}\n"
        if diagnosis:
            diagnosis_full += f"\n[진단방법]\n{clean_text(diagnosis)}"
        if note:
            diagnosis_full += f"\n\n[비고] {clean_text(note)}"

        parsed_items.append({
            'name': item['name'],
            'diagnosis': diagnosis_full.strip(),
            'remediation': clean_text(remediation),
        })

    return parsed_items


def parse_cloud_checklist_categories(doc, section_name):
    """Parse the checklist table to get item names and categories"""
    start, end = get_cloud_page_range(section_name)
    if start is None:
        return {}

    # Read first 2 pages of section (checklist is usually on first page)
    text = extract_pages_text(doc, start, min(start + 3, end))

    item_categories = {}
    lines = text.split('\n')
    in_checklist = False
    current_category = ""

    for line in lines:
        line = line.strip()
        if '진단 체크리스트' in line or '진단 항목' in line:
            in_checklist = True
            continue
        if in_checklist and '구분' in line:
            continue
        if in_checklist and '진단 항목' == line:
            continue
        if in_checklist:
            cat_match = re.match(r'^([가-힣])\.\s*(.+)', line)
            if cat_match:
                current_category = cat_match.group(2).strip()
                continue
            if '항목설명' in line or ('<<PAGE_' in line and '항목설명' not in text[text.index(line):text.index(line)+200]):
                break
            if not line or line.startswith('[') or line.startswith('총') or re.match(r'^\d+$', line):
                continue
            if len(line) > 2 and current_category:
                item_categories[line] = current_category

    return item_categories


def parse_main_chapter(doc, chapter_key):
    """Parse a main guide chapter and return list of items"""
    config = MAIN_CHAPTERS[chapter_key]
    text = extract_pages_text(doc, config['start'], config['end'])

    items = []
    pattern = config['pattern']
    matches = list(re.finditer(pattern, text))

    for i, match in enumerate(matches):
        code = match.group(1)
        severity = match.group(2)

        start_pos = match.start()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        item_text = text[start_pos:end_pos]

        # Parse item name
        lines = item_text.split('\n')
        item_name = ''
        category_path = ''
        found_severity = False

        for j, line in enumerate(lines):
            line_s = line.strip()
            if re.match(rf'^{re.escape(config["prefix"])}-\d+$', line_s):
                continue
            if re.match(r'^\([상중하]\)$', line_s):
                found_severity = True
                continue
            if found_severity and '>' in line_s and not item_name:
                category_path = line_s
                continue
            if found_severity and line_s and category_path and not item_name:
                # Skip known non-name lines
                if line_s.startswith('개요') or line_s.startswith('점검') or \
                   line_s.startswith('보안 위협') or line_s.startswith('참고'):
                    continue
                item_name = line_s
                break

        # Extract 점검 내용
        check_content = ''
        check_match = re.search(r'점검\s*내용\s*\n?(.*?)(?=점검\s*목적)', item_text, re.DOTALL)
        if check_match:
            check_content = check_match.group(1).strip()

        # Extract 판단 기준
        good_criteria = ''
        bad_criteria = ''
        good_match = re.search(r'양호\s*[：:]\s*(.*?)(?=취약\s*[：:])', item_text, re.DOTALL)
        if good_match:
            good_criteria = good_match.group(1).strip()
        bad_match = re.search(r'취약\s*[：:]\s*(.*?)(?=조치\s*방법)', item_text, re.DOTALL)
        if bad_match:
            bad_criteria = bad_match.group(1).strip()

        # Extract 조치 방법 (brief)
        remedy_brief = ''
        remedy_match = re.search(r'조치\s*방법\s*\n(.*?)(?=조치\s*시\s*영향)', item_text, re.DOTALL)
        if remedy_match:
            remedy_brief = remedy_match.group(1).strip()

        # Extract 조치 시 영향
        impact = ''
        impact_match = re.search(r'조치\s*시\s*영향\s*\n(.*?)(?=점검\s*및\s*조치\s*사례)', item_text, re.DOTALL)
        if impact_match:
            impact = impact_match.group(1).strip()

        # Extract 점검 및 조치 사례 (detailed commands)
        detail = ''
        detail_match = re.search(r'점검\s*및\s*조치\s*사례\s*\n(.*?)$', item_text, re.DOTALL)
        if detail_match:
            detail = detail_match.group(1).strip()

        # Build diagnosis method text
        diagnosis_full = ""
        if check_content:
            diagnosis_full += f"[점검내용] {clean_text(check_content)}\n"
        if good_criteria:
            diagnosis_full += f"[양호] {clean_text(good_criteria)}\n"
        if bad_criteria:
            diagnosis_full += f"[취약] {clean_text(bad_criteria)}\n"
        if detail:
            diagnosis_full += f"\n[점검 및 조치 사례]\n{clean_text(detail)}"

        # Build remediation text
        remediation_full = ""
        if remedy_brief:
            remediation_full = clean_text(remedy_brief)
        if detail:
            remediation_full += f"\n\n[상세 조치 사례]\n{clean_text(detail)}"

        items.append({
            'code': code,
            'severity': severity,
            'name': item_name,
            'category': category_path,
            'diagnosis': diagnosis_full.strip(),
            'remediation': remediation_full.strip(),
            'impact': clean_text(impact) if impact else '',
        })

    return items


def create_excel(all_data, output_path):
    """Create the integrated Excel file"""
    wb = Workbook()
    ws = wb.active
    ws.title = "CCE 항목 통합"

    # Styles
    header_font = Font(name='맑은 고딕', bold=True, size=11, color='FFFFFF')
    header_fill = PatternFill(start_color='2F5496', end_color='2F5496', fill_type='solid')
    header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

    section_font = Font(name='맑은 고딕', bold=True, size=11)
    section_fill = PatternFill(start_color='D6E4F0', end_color='D6E4F0', fill_type='solid')

    cloud_fill = PatternFill(start_color='E2EFDA', end_color='E2EFDA', fill_type='solid')
    main_fill = PatternFill(start_color='FCE4D6', end_color='FCE4D6', fill_type='solid')

    cell_font = Font(name='맑은 고딕', size=10)
    cell_alignment = Alignment(vertical='top', wrap_text=True)
    center_alignment = Alignment(horizontal='center', vertical='top', wrap_text=True)

    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )

    # Headers
    headers = ['진단대상', '출처', '중요도', '항목번호', '항목명', '항목분류', '진단방법\n(판단기준 및 명령어)', '조치방법\n(조치 명령어)', '조치영향도']
    col_widths = [14, 10, 8, 12, 30, 18, 70, 70, 30]

    for col_idx, (header, width) in enumerate(zip(headers, col_widths), 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = thin_border
        ws.column_dimensions[chr(64 + col_idx) if col_idx <= 26 else 'A' + chr(64 + col_idx - 26)].width = width

    # Set column widths properly
    from openpyxl.utils import get_column_letter
    for col_idx, width in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    # Freeze first row
    ws.freeze_panes = 'A2'

    row = 2
    total_items = 0

    for app_name, items_data in all_data.items():
        cloud_items = items_data.get('cloud', [])
        main_items = items_data.get('main', [])

        if not cloud_items and not main_items:
            continue

        # Section header row
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=len(headers))
        section_cell = ws.cell(row=row, column=1,
                              value=f"  {app_name} (클라우드: {len(cloud_items)}건, 주요기반시설: {len(main_items)}건, 합계: {len(cloud_items) + len(main_items)}건)")
        section_cell.font = section_font
        section_cell.fill = section_fill
        section_cell.alignment = Alignment(vertical='center')
        for c in range(1, len(headers) + 1):
            ws.cell(row=row, column=c).border = thin_border
            ws.cell(row=row, column=c).fill = section_fill
        row += 1

        # Cloud guide items
        for idx, item in enumerate(cloud_items, 1):
            item_code = f"CLD-{app_name.replace('(', '').replace(')', '').replace(' ', '')}-{idx:02d}"

            cells = [
                (app_name, center_alignment),
                ('클라우드', center_alignment),
                ('-', center_alignment),
                (item_code, center_alignment),
                (item.get('name', ''), cell_alignment),
                (item.get('category', ''), cell_alignment),
                (item.get('diagnosis', ''), cell_alignment),
                (item.get('remediation', ''), cell_alignment),
                ('', cell_alignment),  # 조치영향도 - cloud guide doesn't have this
            ]

            for col_idx, (value, alignment) in enumerate(cells, 1):
                cell = ws.cell(row=row, column=col_idx, value=value)
                cell.font = cell_font
                cell.alignment = alignment
                cell.border = thin_border
                if col_idx == 2:
                    cell.fill = cloud_fill

            row += 1
            total_items += 1

        # Main guide items
        for item in main_items:
            cells = [
                (app_name, center_alignment),
                ('주요기반시설', center_alignment),
                (item.get('severity', ''), center_alignment),
                (item.get('code', ''), center_alignment),
                (item.get('name', ''), cell_alignment),
                (item.get('category', ''), cell_alignment),
                (item.get('diagnosis', ''), cell_alignment),
                (item.get('remediation', ''), cell_alignment),
                (item.get('impact', ''), cell_alignment),
            ]

            for col_idx, (value, alignment) in enumerate(cells, 1):
                cell = ws.cell(row=row, column=col_idx, value=value)
                cell.font = cell_font
                cell.alignment = alignment
                cell.border = thin_border
                if col_idx == 2:
                    cell.fill = main_fill

            row += 1
            total_items += 1

    # Add summary sheet
    ws_summary = wb.create_sheet("요약", 0)
    ws_summary.cell(row=1, column=1, value="진단대상").font = Font(bold=True)
    ws_summary.cell(row=1, column=2, value="클라우드 가이드 항목수").font = Font(bold=True)
    ws_summary.cell(row=1, column=3, value="주요기반시설 가이드 항목수").font = Font(bold=True)
    ws_summary.cell(row=1, column=4, value="합계").font = Font(bold=True)
    ws_summary.column_dimensions['A'].width = 20
    ws_summary.column_dimensions['B'].width = 25
    ws_summary.column_dimensions['C'].width = 30
    ws_summary.column_dimensions['D'].width = 10

    summary_row = 2
    total_cloud = 0
    total_main = 0
    for app_name, items_data in all_data.items():
        c_count = len(items_data.get('cloud', []))
        m_count = len(items_data.get('main', []))
        total_cloud += c_count
        total_main += m_count
        ws_summary.cell(row=summary_row, column=1, value=app_name)
        ws_summary.cell(row=summary_row, column=2, value=c_count)
        ws_summary.cell(row=summary_row, column=3, value=m_count)
        ws_summary.cell(row=summary_row, column=4, value=c_count + m_count)
        summary_row += 1

    # Total row
    ws_summary.cell(row=summary_row, column=1, value="합계").font = Font(bold=True)
    ws_summary.cell(row=summary_row, column=2, value=total_cloud).font = Font(bold=True)
    ws_summary.cell(row=summary_row, column=3, value=total_main).font = Font(bold=True)
    ws_summary.cell(row=summary_row, column=4, value=total_cloud + total_main).font = Font(bold=True)

    wb.save(output_path)
    print(f"\n[완료] {output_path} 저장됨")
    print(f"  - 총 {total_items}개 항목")
    print(f"  - 클라우드 가이드: {total_cloud}개")
    print(f"  - 주요기반시설 가이드: {total_main}개")


def main():
    print("=" * 60)
    print("CCE 취약점 항목 통합 Excel 생성")
    print("=" * 60)

    # =============================
    # 1. Cloud Guide Extraction
    # =============================
    print("\n[1/3] 클라우드 가이드 항목 추출 중...")
    cloud_doc = fitz.open(CLOUD_PDF)

    cloud_data = {}
    for display_name, section_name in CLOUD_TARGETS.items():
        print(f"  - {display_name} ({section_name})...")
        items = parse_cloud_section(cloud_doc, section_name)
        # Get categories
        categories = parse_cloud_checklist_categories(cloud_doc, section_name)
        # Match categories to items
        for item in items:
            if item['name'] in categories:
                item['category'] = categories[item['name']]
            elif not item.get('category'):
                # Try partial match
                for cat_name, cat_val in categories.items():
                    if cat_name in item['name'] or item['name'] in cat_name:
                        item['category'] = cat_val
                        break
                else:
                    item['category'] = ''
        cloud_data[display_name] = items
        print(f"    → {len(items)}개 항목")

    cloud_doc.close()

    # =============================
    # 2. Main Guide Extraction
    # =============================
    print("\n[2/3] 주요정보통신기반시설 가이드 항목 추출 중...")
    main_doc = fitz.open(MAIN_PDF)

    main_data = {}
    for chapter_key, config in MAIN_CHAPTERS.items():
        print(f"  - {chapter_key}...")
        items = parse_main_chapter(main_doc, chapter_key)
        main_data[chapter_key] = items
        print(f"    → {len(items)}개 항목")

    main_doc.close()

    # =============================
    # 3. Integrate and generate Excel
    # =============================
    print("\n[3/3] 항목 통합 및 Excel 생성 중...")

    # Build integrated data structure
    all_data = {}

    # Ordered list of target apps
    app_order = [
        'KVM', 'Xenserver', 'ESXi',
        'Linux', 'Windows',
        'MY-SQL', 'MS-SQL', 'Redis', 'Elasticsearch', 'MongoDB', 'PostgreSQL',
        'Apache', 'Nginx', 'Tomcat',
        'Docker', 'K8s(Master)', 'K8s(Worker)',
        'PHP', 'NodeJS', 'Hadoop', 'Ceph',
    ]

    for app_name in app_order:
        all_data[app_name] = {
            'cloud': cloud_data.get(app_name, []),
            'main': [],
        }

    # Map main guide items to apps
    for chapter_key, target_apps in MAIN_TO_APP.items():
        items = main_data.get(chapter_key, [])
        for app_name in target_apps:
            if app_name in all_data:
                all_data[app_name]['main'] = items

    # Generate Excel
    output_path = os.path.join(BASE_DIR, '진단항목통합.xlsx')
    create_excel(all_data, output_path)


if __name__ == '__main__':
    main()
