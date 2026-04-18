from __future__ import annotations

from functools import wraps

from flask import g, redirect, session, url_for

from .db import fetch_one


def init_app(app) -> None:
    @app.before_request
    def load_current_user() -> None:
        user_id = session.get("user_id")
        if not user_id:
            g.user = None
            return
        g.user = fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.get("user") is None:
            return redirect(url_for("main.login"))
        return view(**kwargs)

    return wrapped_view


def security_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(**kwargs):
        if g.user["role"] != "security":
            return redirect(url_for("main.index"))
        return view(**kwargs)

    return wrapped_view
