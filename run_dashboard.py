#!/usr/bin/env python3
from __future__ import annotations

import argparse

from dashboard import create_app
from dashboard.db import create_user, init_db


def main() -> None:
    parser = argparse.ArgumentParser(description="CCE dashboard harness")
    subparsers = parser.add_subparsers(dest="command")

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", default=5001, type=int)
    serve_parser.add_argument("--debug", action="store_true")

    create_user_parser = subparsers.add_parser("create-user")
    create_user_parser.add_argument("username")
    create_user_parser.add_argument("password")
    create_user_parser.add_argument("role", choices=["security", "user"])

    subparsers.add_parser("init-db")

    args = parser.parse_args()
    app = create_app()

    with app.app_context():
        if args.command == "init-db":
            init_db()
            print("initialized database")
            return
        if args.command == "create-user":
            init_db()
            create_user(args.username, args.password, args.role)
            print(f"created user {args.username}")
            return

    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 5001)
    debug = getattr(args, "debug", False)
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
