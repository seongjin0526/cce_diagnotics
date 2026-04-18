"""Control-code helpers for preferred and legacy naming schemes."""

from __future__ import annotations

import re


CODE_TOKEN_RE = re.compile(
    r"\b(?:CLD|CSAP)-[A-Za-z0-9()]+(?:-[A-Za-z0-9()]+)*-\d+\b"
    r"|\b(?:ISMS-)?(?:U|W|WEB|D|HV)-\d+\b"
)
LEGACY_MAIN_RE = re.compile(r"^(U|W|WEB|D|HV)-(\d+)$")
PREFERRED_MAIN_RE = re.compile(r"^ISMS-(U|W|WEB|D|HV)-(\d+)$")
LEGACY_CLOUD_RE = re.compile(r"^CLD-(.+)$")
PREFERRED_CLOUD_RE = re.compile(r"^CSAP-(.+)$")


def _to_preferred_token(token: str) -> str:
    if PREFERRED_MAIN_RE.match(token) or PREFERRED_CLOUD_RE.match(token):
        return token
    if LEGACY_MAIN_RE.match(token):
        return f"ISMS-{token}"
    if LEGACY_CLOUD_RE.match(token):
        return f"CSAP-{token[4:]}"
    return token


def _to_legacy_token(token: str) -> str:
    preferred_main = PREFERRED_MAIN_RE.match(token)
    if preferred_main:
        return f"{preferred_main.group(1)}-{preferred_main.group(2)}"
    preferred_cloud = PREFERRED_CLOUD_RE.match(token)
    if preferred_cloud:
        return f"CLD-{preferred_cloud.group(1)}"
    return token


def to_preferred_code_text(value: str | None) -> str:
    if not value:
        return ""
    return CODE_TOKEN_RE.sub(lambda match: _to_preferred_token(match.group(0)), value)


def to_legacy_code_text(value: str | None) -> str:
    if not value:
        return ""
    return CODE_TOKEN_RE.sub(lambda match: _to_legacy_token(match.group(0)), value)


def make_cloud_control_code(app_name: str, index: int) -> str:
    code_app = app_name.replace("(", "").replace(")", "").replace(" ", "")
    return f"CSAP-{code_app}-{index:02d}"


def control_code_aliases(value: str | None) -> set[str]:
    if not value:
        return set()
    code = value.strip()
    aliases = {
        code,
        to_preferred_code_text(code),
        to_legacy_code_text(code),
    }
    for part in (segment.strip() for segment in code.split("/") if segment.strip()):
        aliases.add(part)
        aliases.add(to_preferred_code_text(part))
        aliases.add(to_legacy_code_text(part))
    return {alias for alias in aliases if alias}
