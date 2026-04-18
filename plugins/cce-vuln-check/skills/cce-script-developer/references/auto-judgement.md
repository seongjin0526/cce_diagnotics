# CCE Script Auto-Judgement Policy

## Goal

Reduce unnecessary `수동점검` results in generated CCE scripts.

The default bias for script-development work in this repository is:

- Prefer `양호` or `취약` when the target state is determinable from commands or queries.
- Use `수동점검` only when the repository cannot determine the control reliably.

## Strong Candidates For Automation

Promote a control away from `수동점검` when it can be checked through:

- config key present or absent
- config value equal, not equal, or matching a threshold
- file owner, group, or permission mode
- process argument or service startup option
- package or server version threshold
- local user, group, or role existence
- database user, role, schema, or setting existence
- listener or bind-address exposure
- presence of audit, log, or authentication settings

## Escalation Order

1. Prefer improving `generate_scripts.py` so the generated script emits `양호` or `취약` directly.
2. If command output is already collected and only interpretation is missing, improve `dashboard/auto_judgement.py`.
3. If the rule is platform-agnostic and repeats, implement it once in shared generation logic rather than patching many generated scripts.
4. If no reliable automated boundary exists, keep `수동점검` and write the blocker explicitly in `detail`.

## Required Checks Before Leaving A Manual Result

Before leaving a control as `수동점검`, check whether one of these would work:

- `grep`, `awk`, `sed`, `find`, `stat`, `ls`, `ps`, `ss`, `netstat`
- service-specific CLIs
- database shells or SQL queries
- reading environment-specific override paths already stored by the dashboard
- post-processing the collected `current_state` into a final verdict

## Validation Flow

```bash
python3 generate_scripts.py
python3 tools/codex_harness.py
```

If you changed only post-processing heuristics and not script generation, still run:

```bash
python3 tools/codex_harness.py
```

Add or extend harness cases whenever a known manual case is promoted to an automatic verdict.
