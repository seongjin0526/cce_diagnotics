#!/usr/bin/env python3
"""
CCE 취약점 항목 통합 추출 스크립트
- 클라우드 취약점 점검 가이드(2024).pdf
- 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf
"""
import fitz
import re
import json

from code_scheme import to_preferred_code_text
from project_paths import CLOUD_GUIDE_PDF, CLOUD_ITEMS_JSON, MAIN_GUIDE_PDF, MAIN_ITEMS_JSON

CLOUD_PDF = str(CLOUD_GUIDE_PDF)
MAIN_PDF = str(MAIN_GUIDE_PDF)

# Cloud guide: content page -> PDF page offset is 5
CLOUD_OFFSET = 5

# Cloud guide sections with content page numbers
CLOUD_SECTIONS_ALL = {
    'KVM': 7,
    'Xenserver': 15,
    'ESXi': 61,
    'Hyper-V': 101,
    'Server(Linux)': 119,
    'Server(Windows)': 163,
    'PC(Windows)': 225,
    'PC(MAC)': 253,
    'PC(Linux)': 283,
    'MY-SQL': 299,
    'MS-SQL': 311,
    'Redis': 325,
    'Elasticsearch': 335,
    'MongoDB': 351,
    'PostgresSQL': 363,
    'Cubrid': 377,
    'CouchDB': 389,
    'SQLite': 407,
    'Tibero': 417,
    'InfluxDB': 429,
    'Oracle': 441,
    'Apache': 457,
    'Nginx': 467,
    'IIS': 477,
    'Tomcat': 493,
    'Docker': 505,
    'Kubernetes(Master)': 543,
    'Kubernetes(Worker)': 565,
    'OpenStack': 579,
    'PHP': 639,
    'RabbitMQ': 647,
    'Node.js': 659,
    'Ceph': 671,
    'Hadoop': 681,
    'Network Device': 693,
    '정보보호시스템': 721,
    '스토리지': 737,
    'BOSH(Director)': 745,
    'BOSH(UAA)': 753,
}

# Target sections only
CLOUD_TARGETS = [
    'KVM', 'Xenserver', 'ESXi', 'Server(Linux)', 'Server(Windows)',
    'MY-SQL', 'MS-SQL', 'Redis', 'Elasticsearch', 'MongoDB', 'PostgresSQL',
    'Apache', 'Nginx', 'Tomcat', 'Docker',
    'Kubernetes(Master)', 'Kubernetes(Worker)',
    'PHP', 'Node.js', 'Ceph', 'Hadoop'
]

# Main guide chapters (PDF page numbers, 0-indexed)
MAIN_CHAPTERS = {
    'Ch1_UNIX': (6, 171),      # pages 7-172 (0-indexed 6-171)
    'Ch2_Windows': (171, 270),  # pages 172-271
    'Ch3_Web': (270, 352),      # pages 271-353
    'Ch8_DBMS': (592, 669),     # pages 593-670
    'Ch11_Virtual': (786, 850), # pages 787-851
}


def get_section_page_range(section_name):
    """Get PDF page range for a cloud guide section"""
    sorted_sections = sorted(CLOUD_SECTIONS_ALL.items(), key=lambda x: x[1])
    for i, (name, start_page) in enumerate(sorted_sections):
        if name == section_name:
            pdf_start = start_page + CLOUD_OFFSET
            if i + 1 < len(sorted_sections):
                pdf_end = sorted_sections[i + 1][1] + CLOUD_OFFSET
            else:
                pdf_end = pdf_start + 20  # last section
            return pdf_start, pdf_end
    return None, None


def extract_cloud_section_text(doc, section_name):
    """Extract text from a cloud guide section"""
    start, end = get_section_page_range(section_name)
    if start is None:
        return ""

    text_parts = []
    for page_num in range(start - 1, min(end - 1, len(doc))):  # 0-indexed
        page = doc[page_num]
        text = page.get_text()
        text_parts.append(f"<<PAGE_{page_num + 1}>>\n{text}")

    return '\n'.join(text_parts)


def parse_cloud_checklist(text, section_name):
    """Parse the checklist table at the start of a cloud guide section to get item names and categories"""
    items = []

    # Find the checklist section
    # Pattern: 구분 followed by 진단 항목, then category + items
    lines = text.split('\n')
    in_checklist = False
    current_category = ""
    checklist_started = False

    for i, line in enumerate(lines):
        line = line.strip()
        if '진단 체크리스트' in line or '진단 항목' in line:
            checklist_started = True
            continue
        if checklist_started and ('진단 항목' in line or '구분' in line):
            in_checklist = True
            continue
        if in_checklist:
            # Check if this is a category line (starts with 가., 나., 다., etc.)
            cat_match = re.match(r'^([가-힣])\.\s*(.+)', line)
            if cat_match:
                current_category = cat_match.group(2).strip()
                continue
            # Check if we've reached the end of the checklist (항목설명 or page break)
            if '항목설명' in line or '<<PAGE_' in line:
                break
            # Skip empty lines and header lines
            if not line or line in ['구분', '진단 항목']:
                continue
            # This should be an item name
            if len(line) > 2 and not line.startswith('[') and not line.startswith('총'):
                items.append({
                    'category': current_category,
                    'name': line
                })

    return items


def parse_cloud_items(text, section_name):
    """Parse individual items from a cloud guide section"""
    items = []

    # First get checklist for item names
    checklist = parse_cloud_checklist(text, section_name)
    item_names = [item['name'] for item in checklist]
    item_categories = {item['name']: item['category'] for item in checklist}

    if not item_names:
        # Fallback: try to find items by 항목설명 pattern
        pass

    # Now parse individual items by finding 항목설명 markers
    # Split text into item blocks
    # Each item starts with the item title followed by 항목설명

    pages = text.split('<<PAGE_')

    current_item = None
    all_items = []

    for page_block in pages:
        if not page_block.strip():
            continue

        page_lines = page_block.split('\n')
        page_text = '\n'.join(page_lines[1:])  # skip page number line

        # Check if this page starts a new item (contains 항목설명)
        if '항목설명' in page_text:
            # Save previous item if exists
            if current_item:
                all_items.append(current_item)

            # Find item name - it's typically the line before 항목설명
            lines = page_text.split('\n')
            item_name = ""
            for j, line in enumerate(lines):
                if '항목설명' in line:
                    # Look backwards for item name
                    for k in range(j - 1, -1, -1):
                        candidate = lines[k].strip()
                        # Skip headers, page numbers, section markers
                        if candidate and not re.match(r'^\d+\s*_', candidate) and \
                           not re.match(r'^2\.\d+\.?$', candidate) and \
                           not re.match(r'^[0-9]+$', candidate) and \
                           candidate not in ['보안가이드', '클라우드 취약점 점검 가이드'] and \
                           not candidate.startswith('2. 보안가이드'):
                            item_name = candidate
                            break
                    break

            current_item = {
                'name': item_name,
                'raw_text': page_text,
                'description': '',
                'good_criteria': '',
                'bad_criteria': '',
                'diagnosis_method': '',
                'remediation': '',
                'note': '',
            }
        elif current_item:
            # Continuation of current item
            current_item['raw_text'] += '\n' + page_text

    if current_item:
        all_items.append(current_item)

    # Now parse each item's raw text
    for item in all_items:
        raw = item['raw_text']

        # Extract 항목설명
        desc_match = re.search(r'항목설명\s*\n(.*?)(?=진단\s*\n?기준|진단기준)', raw, re.DOTALL)
        if desc_match:
            item['description'] = desc_match.group(1).strip()

        # Extract 진단기준 (양호/취약)
        good_match = re.search(r'양호\s*\n?(.*?)(?=취약)', raw, re.DOTALL)
        if good_match:
            item['good_criteria'] = good_match.group(1).strip()
            # Clean up
            item['good_criteria'] = re.sub(r'[◼￭●]\s*', '', item['good_criteria'])

        bad_match = re.search(r'취약\s*\n?(.*?)(?=진단\s*\n?방법|진단방법)', raw, re.DOTALL)
        if bad_match:
            item['bad_criteria'] = bad_match.group(1).strip()
            item['bad_criteria'] = re.sub(r'[◼￭●]\s*', '', item['bad_criteria'])

        # Extract 진단방법
        diag_match = re.search(r'진단\s*\n?방법\s*\n(.*?)(?=조치\s*\n?방법)', raw, re.DOTALL)
        if diag_match:
            item['diagnosis_method'] = diag_match.group(1).strip()

        # Extract 조치방법
        remed_match = re.search(r'조치\s*\n?방법\s*\n(.*?)(?=비고|$)', raw, re.DOTALL)
        if remed_match:
            item['remediation'] = remed_match.group(1).strip()

        # Extract 비고
        note_match = re.search(r'비고\s*\n(.*?)$', raw, re.DOTALL)
        if note_match:
            item['note'] = note_match.group(1).strip()

        # Match to checklist category
        item['category'] = item_categories.get(item['name'], '')

        # Clean up raw_text to save memory
        del item['raw_text']

    return all_items


def extract_main_chapter_text(doc, chapter_name):
    """Extract text from a main guide chapter"""
    start, end = MAIN_CHAPTERS[chapter_name]
    text_parts = []
    for page_num in range(start, min(end, len(doc))):
        page = doc[page_num]
        text = page.get_text()
        text_parts.append(f"<<PAGE_{page_num + 1}>>\n{text}")
    return '\n'.join(text_parts)


def parse_main_items(text, chapter_name):
    """Parse items from main guide chapter"""
    items = []

    # Determine item code prefix based on chapter
    prefixes = {
        'Ch1_UNIX': 'U',
        'Ch2_Windows': 'W',
        'Ch3_Web': 'WEB',  # The web chapter might use different codes
        'Ch8_DBMS': 'D',
        'Ch11_Virtual': 'V',
    }

    # Split text by item codes
    # Pattern: X-NN at start of section followed by (상/중/하)
    # e.g., "U-01\n(상)\n" or "W-01\n(상)"

    # First, let's find all item blocks
    # Items are marked by their code pattern
    prefix = prefixes.get(chapter_name, '')

    # Find all item start positions
    # Pattern: code like U-01, W-01, D-01, V-01 followed by severity
    pattern = rf'({prefix}-\d+)\s*\n\s*\(([상중하])\)'

    matches = list(re.finditer(pattern, text))

    for i, match in enumerate(matches):
        code = match.group(1)
        severity = match.group(2)

        # Extract text from this match to the next match
        start_pos = match.start()
        if i + 1 < len(matches):
            end_pos = matches[i + 1].start()
        else:
            end_pos = len(text)

        item_text = text[start_pos:end_pos]

        # Parse item name - it's on the line after severity and category
        lines = item_text.split('\n')
        item_name = ''
        category_path = ''

        # Find the item name - typically after the category line
        found_severity = False
        for j, line in enumerate(lines):
            line = line.strip()
            if re.match(rf'^{prefix}-\d+$', line):
                continue
            if re.match(r'^\([상중하]\)$', line):
                found_severity = True
                continue
            if found_severity and '>' in line:
                category_path = line
                continue
            if found_severity and line and not line.startswith('개요') and \
               not line.startswith('점검') and not line.startswith('보안') and \
               category_path:
                item_name = line
                break

        # Extract 판단 기준
        good_criteria = ''
        bad_criteria = ''
        good_match = re.search(r'양호\s*[：:]\s*(.*?)(?=취약)', item_text, re.DOTALL)
        if good_match:
            good_criteria = good_match.group(1).strip()
        bad_match = re.search(r'취약\s*[：:]\s*(.*?)(?=조치\s*방법|조치방법)', item_text, re.DOTALL)
        if bad_match:
            bad_criteria = bad_match.group(1).strip()

        # Extract 점검 내용
        check_content = ''
        check_match = re.search(r'점검\s*내용\s*\n?(.*?)(?=점검\s*목적)', item_text, re.DOTALL)
        if check_match:
            check_content = check_match.group(1).strip()

        # Extract 조치 방법 (brief)
        remedy_brief = ''
        remedy_match = re.search(r'조치\s*방법\s*\n(.*?)(?=조치\s*시\s*영향)', item_text, re.DOTALL)
        if remedy_match:
            remedy_brief = remedy_match.group(1).strip()

        # Extract 조치 시 영향
        impact = ''
        impact_match = re.search(r'조치\s*시\s*영향\s*\n(.*?)(?=점검\s*및\s*조치\s*사례|$)', item_text, re.DOTALL)
        if impact_match:
            impact = impact_match.group(1).strip()

        # Extract 점검 및 조치 사례 (detailed commands)
        detail = ''
        detail_match = re.search(r'점검\s*및\s*조치\s*사례\s*\n(.*?)$', item_text, re.DOTALL)
        if detail_match:
            detail = detail_match.group(1).strip()
            # Clean up page markers
            detail = re.sub(r'<<PAGE_\d+>>', '', detail)
            # Remove common headers
            detail = re.sub(r'\d+\s*_\s*클라우드.*?\n', '', detail)
            detail = re.sub(r'\|\s*한국인터넷진흥원\s*\|', '', detail)
            detail = re.sub(r'\d{4}\s*주요정보통신기반시설.*?\n', '', detail)
            detail = re.sub(r'\d{2}\.\s*(Unix|Windows).*?\n', '', detail)

        items.append({
            'code': to_preferred_code_text(code),
            'severity': severity,
            'name': item_name,
            'category': category_path,
            'check_content': check_content,
            'good_criteria': good_criteria,
            'bad_criteria': bad_criteria,
            'remedy_brief': remedy_brief,
            'impact': impact,
            'detail': detail,
        })

    return items


def main():
    print("=" * 60)
    print("CCE 취약점 항목 통합 추출 시작")
    print("=" * 60)

    # =============================
    # 1. Cloud Guide Extraction
    # =============================
    print("\n[1/4] 클라우드 가이드 텍스트 추출 중...")
    cloud_doc = fitz.open(CLOUD_PDF)

    cloud_data = {}
    for section in CLOUD_TARGETS:
        print(f"  - {section} 추출 중...")
        text = extract_cloud_section_text(cloud_doc, section)
        items = parse_cloud_items(text, section)
        cloud_data[section] = items
        print(f"    → {len(items)}개 항목 추출")

    cloud_doc.close()

    # Save cloud data for inspection
    with CLOUD_ITEMS_JSON.open('w', encoding='utf-8') as f:
        json.dump(cloud_data, f, ensure_ascii=False, indent=2)
    print(f"\n클라우드 가이드: 총 {sum(len(v) for v in cloud_data.values())}개 항목 추출 완료")

    # =============================
    # 2. Main Guide Extraction
    # =============================
    print("\n[2/4] 주요정보통신기반시설 가이드 텍스트 추출 중...")
    main_doc = fitz.open(MAIN_PDF)

    main_data = {}
    for chapter in MAIN_CHAPTERS:
        print(f"  - {chapter} 추출 중...")
        text = extract_main_chapter_text(main_doc, chapter)
        items = parse_main_items(text, chapter)
        main_data[chapter] = items
        print(f"    → {len(items)}개 항목 추출")

    main_doc.close()

    # Save main data for inspection
    with MAIN_ITEMS_JSON.open('w', encoding='utf-8') as f:
        json.dump(main_data, f, ensure_ascii=False, indent=2)
    print(f"\n주요정보통신기반시설: 총 {sum(len(v) for v in main_data.values())}개 항목 추출 완료")

    print("\n[완료] JSON 파일 저장됨:")
    print(f"  - {CLOUD_ITEMS_JSON}")
    print(f"  - {MAIN_ITEMS_JSON}")


if __name__ == '__main__':
    main()
