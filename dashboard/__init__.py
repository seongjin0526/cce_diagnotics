from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask

from project_paths import REPO_ROOT

from . import auth, db


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("CCE_DASHBOARD_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=str(REPO_ROOT / "instance" / "dashboard.sqlite3"),
        EXPORT_SHEET_NAME="진단결과",
    )

    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    auth.init_app(app)
    with app.app_context():
        db.init_db()

    from .views import bp as main_bp

    app.register_blueprint(main_bp)
    return app
