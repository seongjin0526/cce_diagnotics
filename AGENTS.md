# Repository Guide

## Overview
- This repository builds CCE vulnerability-check scripts from Korean source guides.
- The working pipeline is `PDF -> JSON -> Excel -> platform scripts`.
- `linux_cce_check.sh` is the hand-maintained reference implementation for the JSON output schema.
- `scripts/*.sh` and `scripts/windows_cce_check.ps1` are generated outputs unless a task explicitly calls for a manual hotfix.

## Preferred Workflow
- Use `extract_cce.py` to refresh `cloud_items.json` and `main_items.json` from the source PDFs.
- Use `dedup_excel.py` as the default Excel builder because it applies platform filtering and deduplication.
- Treat `generate_excel.py` as the legacy comparison path, not the default regeneration flow.
- Use `generate_scripts.py` after workbook changes to regenerate the platform scripts.

## Editing Rules
- Do not reintroduce workspace-specific absolute paths. Use `project_paths.py`.
- Keep the existing JSON schema and Korean status strings stable unless the user explicitly asks for a format change.
- If a change affects many generated scripts, edit `generate_scripts.py` first and regenerate the outputs instead of hand-editing each generated script.
- Preserve `linux_cce_check.sh` as the schema reference when aligning generator output.

## Validation
- Run `python3 tools/codex_harness.py` after code changes.
- When generator logic changes, regenerate the affected artifacts before running the harness.

## AI Harness
- The repo-local Codex plugin lives at `plugins/cce-vuln-check`.
- The primary repo-local skill lives at `plugins/cce-vuln-check/skills/cce-maintainer`.
- The script-development skill lives at `plugins/cce-vuln-check/skills/cce-script-developer`.
- Keep reusable Codex workflow guidance in the repo-local skill and keep executable verification in `tools/codex_harness.py`.
- Prefer repo-local plugin/skill updates over repeating ad-hoc repository instructions across sessions.
- For script-development work, prefer modifying scripts and generator logic so command-checkable controls return `양호` or `취약` instead of remaining `수동점검`.
