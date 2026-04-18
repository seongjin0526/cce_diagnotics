---
name: cce-script-developer
description: "Develop and upgrade generated CCE check scripts so command-checkable items return `양호` or `취약` whenever the target state can be determined reliably from commands, config inspection, or queries. Use when Codex is editing `generate_scripts.py`, generated `scripts/*`, `linux_cce_check.sh`, `dashboard/auto_judgement.py`, or `tools/codex_harness.py` to reduce unnecessary `수동점검` results, add stronger automated judgement, or codify command-driven verdict rules."
---

# Cce Script Developer

## Overview

Use this skill when working on script-generation or judgement logic in this repository.
Prefer converting checkable controls into automated verdicts and treat `수동점검` as the fallback, not the default.

## Judgement Policy

- If a shell command, config parse, SQL query, or process inspection can determine compliance with acceptable reliability, implement the script so it returns `양호` or `취약`.
- Leave `수동점검` only when the control still requires human context, environment-specific interpretation, or evidence the repository cannot collect safely and repeatably.
- Before accepting `수동점검`, try to express the control as one of: exact config presence, forbidden config presence, version threshold, process argument check, ownership/permission check, account existence check, network/listener check, or queryable object existence check.
- Preserve `command`, `current_state`, and `detail` fields so automated verdicts remain explainable in logs and dashboard output.

## Implementation Rules

- If the same verdict rule affects many generated scripts, edit `generate_scripts.py` first and regenerate `scripts/*`.
- Use `linux_cce_check.sh` as the schema and trace-format reference for generated shell output.
- When raw command output is already collected but the result still lands as `수동점검`, prefer strengthening judgement logic in `generate_scripts.py` or `dashboard/auto_judgement.py` instead of leaving the item manual.
- If an item stays manual, state the specific blocker in `detail` so a later pass can target the missing automation boundary.

## Workflow

1. Inspect the current check path in `generate_scripts.py`, the generated script, and any auto-judgement post-processing in `dashboard/auto_judgement.py`.
2. Decide whether the control can be expressed as a deterministic command or query.
3. Implement the automated verdict in the generator or shared logic, not as repeated ad-hoc edits, unless the task is a narrow hotfix.
4. Regenerate affected scripts when generator behavior changes.
5. Add or update harness coverage when a previously manual case is now expected to auto-resolve.

## Validation

- Run the flow in `references/auto-judgement.md`.
- At minimum, regenerate affected scripts after generator changes and run `python3 tools/codex_harness.py`.
- When adding new automatic verdict behavior, update or extend harness cases so regressions fail loudly.
