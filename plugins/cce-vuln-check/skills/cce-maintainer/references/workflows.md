# CCE Maintainer Workflows

## Key Paths

- Repository guide: `AGENTS.md`
- Repo-local plugin: `plugins/cce-vuln-check/.codex-plugin/plugin.json`
- Repo-local skill: `plugins/cce-vuln-check/skills/cce-maintainer/`
- Marketplace entry: `.agents/plugins/marketplace.json`
- Verification harness: `tools/codex_harness.py`
- Dashboard entrypoint: `run_dashboard.py`

## Default Regeneration Flow

Use this when the source guides or workbook outputs need refresh:

```bash
python3 extract_cce.py
python3 dedup_excel.py
python3 generate_scripts.py
python3 tools/codex_harness.py
```

## Generator Change Flow

Use this when changing `generate_scripts.py` or script output behavior:

```bash
python3 generate_scripts.py
python3 tools/codex_harness.py
```

Do not hand-edit many generated `scripts/*` files when a generator change can express the same rule once.

## Script Judgement Flow

Use `../cce-script-developer` when the task is to reduce unnecessary `수동점검` results and convert command-checkable controls into automated `양호` or `취약` verdicts.

## Dashboard Flow

Use this when checking the Flask dashboard locally:

```bash
python3 run_dashboard.py init-db
python3 run_dashboard.py create-user security security123! security
python3 run_dashboard.py create-user operator operator123! user
python3 run_dashboard.py serve --host 0.0.0.0 --port 5001
```

## Docker Test-Lab Flow

Use this when validating supported Linux targets in containers:

```bash
docker compose -f docker/test-lab/compose.yml --profile common up -d
docker/test-lab/run_check.sh nginx-lab Nginx
```

Check `docker/test-lab/README.md` and `docker/test-lab/targets.md` before using less-common targets.

## AI Harness Maintenance Flow

Use this when changing the repo-local skill or plugin:

```bash
python3 "${CODEX_HOME:-$HOME/.codex}/skills/.system/skill-creator/scripts/quick_validate.py" plugins/cce-vuln-check/skills/cce-maintainer
python3 tools/codex_harness.py
```

Update the plugin manifest, marketplace entry, and `AGENTS.md` together when the repository-wide Codex behavior changes.
