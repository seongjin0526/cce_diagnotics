---
name: cce-maintainer
description: "Maintain and extend the `cce_vuln_check` repository workflow, generated CCE scripts, Codex validation harness, dashboard harness, Docker test lab, and repo-local Codex plugin/skill setup. Use when Codex is working in this repository on: (1) `extract_cce.py`, `dedup_excel.py`, `generate_scripts.py`, `project_paths.py`, or generated `scripts/*`; (2) `tools/codex_harness.py`, dashboard code, or Docker test-lab validation; (3) adding or updating repo-local `AGENTS.md`, plugins, skills, or marketplace entries for repeated repository work."
---

# Cce Maintainer

## Overview

Use this skill to keep repository work aligned with the stored CCE regeneration flow and the repo-local AI harness.
Keep executable verification in `tools/codex_harness.py` and keep reusable Codex behavior in this plugin's skill and marketplace files.

## Workflow Decision Tree

- If the task changes PDF extraction, Excel generation, or generated platform scripts, follow the regeneration flow in `references/workflows.md`.
- If the task is specifically about reducing `수동점검` by improving command-driven verdicts in scripts, use the sibling skill `../cce-script-developer`.
- If the task changes many generated scripts, edit `generate_scripts.py` first and regenerate the outputs instead of hand-editing `scripts/*`.
- If the task changes dashboard behavior, run repository validation after edits and use the dashboard commands in `references/workflows.md` when local runtime confirmation is needed.
- If the task changes repo-local Codex behavior, update `AGENTS.md`, this skill, and plugin marketplace metadata together so the repository instructions stay consistent.

## Parallel Work

- Use `multi_tool_use.parallel` for independent read-only exploration such as `rg`, `sed`, `ls`, `git status`, `git show`, and targeted file reads.
- Use parallel execution for independent validations only when they do not mutate the same files and do not depend on each other's outputs.
- Keep writes and dependent validation sequential. Do not run `generate_scripts.py` in parallel with `tools/codex_harness.py`; regenerate first, then validate.
- If a task needs additional plugin or skill support for repeated repository work, scaffold or update it in the same turn instead of leaving it as a manual follow-up.

## Repo-Local AI Harness Rules

- Prefer repo-local Codex components for this repository. Keep the plugin under `plugins/cce-vuln-check` and the marketplace entry in `.agents/plugins/marketplace.json`.
- Use the `plugin-creator` and `skill-creator` scaffold scripts when adding new plugin or skill components rather than hand-creating the directory structure.
- Keep repository-specific guidance in repo-local files instead of relying on home-local Codex configuration.
- When plugin installation policy matters for repository onboarding, keep this plugin installed by default in the repo-local marketplace unless the user explicitly asks for a different policy.

## Validation

- Run `python3 tools/codex_harness.py` after repository code changes.
- When generator logic changes, regenerate the affected outputs before running the harness.
- When this skill changes, run the skill validator and then run the repository harness so the AI harness and code harness stay aligned.
- Read `references/workflows.md` for the exact command sequences and file map before running less-common repository flows.
