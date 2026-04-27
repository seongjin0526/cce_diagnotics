#!/usr/bin/env python3
"""Export dashboard test-client pages as static HTML snapshots."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard import create_app  # noqa: E402
from dashboard.db import create_user, fetch_one, init_db  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "docs" / "dashboard-test-pages"
STATIC_CSS = REPO_ROOT / "dashboard" / "static" / "app.css"

PAGES = (
    ("/login", "login.html", False),
    ("/", "dashboard.html", True),
    ("/hosts", "hosts.html", True),
    ("/controls", "controls.html", True),
    ("/approvals", "approvals.html", True),
)


def ensure_test_users() -> None:
    for username, password, role in (
        ("security", "security123!", "security"),
        ("operator", "operator123!", "user"),
    ):
        if fetch_one("SELECT id FROM users WHERE username = ?", (username,)) is None:
            create_user(username, password, role)


def rewrite_static_links(html: str) -> str:
    html = html.replace('/static/app.css', 'app.css')

    def replace_href(match: re.Match[str]) -> str:
        href = match.group(1)
        route = href.split("?", 1)[0]
        page = {
            "": "dashboard.html",
            "login": "login.html",
            "hosts": "hosts.html",
            "controls": "controls.html",
            "approvals": "approvals.html",
            "logout": "login.html",
        }.get(route)
        if page is None and route.startswith("hosts/"):
            page = "hosts.html"
        if page is None and route.startswith("runs/"):
            page = "dashboard.html"
        if page is None and route.startswith("results/"):
            page = "dashboard.html"
        if page:
            return f'href="{page}"'
        return 'href="#"'

    return re.sub(r'href="/([^"#]*)"', replace_href, html)


def export_pages(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STATIC_CSS, output_dir / "app.css")

    app = create_app()
    with app.app_context():
        init_db()
        ensure_test_users()

    exported = []
    with app.test_client() as anonymous_client:
        for path, filename, needs_auth in PAGES:
            if needs_auth:
                continue
            response = anonymous_client.get(path)
            (output_dir / filename).write_text(
                rewrite_static_links(response.get_data(as_text=True)),
                encoding="utf-8",
            )
            exported.append(filename)

    with app.test_client() as client:
        login_response = client.post(
            "/login",
            data={"username": "security", "password": "security123!"},
            follow_redirects=True,
        )
        (output_dir / "post-login.html").write_text(
            rewrite_static_links(login_response.get_data(as_text=True)),
            encoding="utf-8",
        )
        exported.append("post-login.html")

        for path, filename, needs_auth in PAGES:
            if not needs_auth:
                continue
            response = client.get(path)
            (output_dir / filename).write_text(
                rewrite_static_links(response.get_data(as_text=True)),
                encoding="utf-8",
            )
            exported.append(filename)

    index_links = "\n".join(
        f'      <li><a href="{filename}">{filename}</a></li>' for filename in exported
    )
    (output_dir / "index.html").write_text(
        "\n".join(
            [
                "<!doctype html>",
                '<html lang="ko">',
                "<head>",
                '  <meta charset="utf-8">',
                '  <meta name="viewport" content="width=device-width, initial-scale=1">',
                "  <title>CCE Dashboard Test Pages</title>",
                '  <link rel="stylesheet" href="app.css">',
                "</head>",
                "<body>",
                '  <main class="page">',
                '    <section class="panel">',
                "      <h1>CCE Dashboard Test Pages</h1>",
                "      <p>Static snapshots exported from the Flask test client.</p>",
                "      <ul>",
                index_links,
                "      </ul>",
                "    </section>",
                "  </main>",
                "</body>",
                "</html>",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    export_pages(args.output_dir)
    print(f"exported dashboard test pages to {args.output_dir}")


if __name__ == "__main__":
    main()
