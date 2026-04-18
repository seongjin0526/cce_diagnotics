#!/usr/bin/env python3
"""Repository-relative path helpers shared by local generator scripts."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

CLOUD_GUIDE_PDF = REPO_ROOT / "클라우드 취약점 점검 가이드(2024).pdf"
MAIN_GUIDE_PDF = REPO_ROOT / "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"
MERGED_ITEMS_XLSX = REPO_ROOT / "진단항목통합.xlsx"
CLOUD_ITEMS_JSON = REPO_ROOT / "cloud_items.json"
MAIN_ITEMS_JSON = REPO_ROOT / "main_items.json"
