"""BugHunter AI command-line utilities."""
import argparse
import json
import sys

from app.database.db import SessionLocal, init_db
from app.services.passive_recon import run_passive_recon
from app.services.auth import create_owner, authenticate
from getpass import getpass
from sqlalchemy import select
from app.models.entities import User


def main():
    parser = argparse.ArgumentParser(
        prog="bughunter",
        description="Local BugHunter AI project utilities",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    account = sub.add_parser(
        "create-account",
        help="Create a user account from the terminal",
    )
    account.add_argument("--username", required=True)

    recon = sub.add_parser(
        "passive-recon",
        help="DNS resolution and Certificate Transparency discovery",
    )
    recon.add_argument("--project-id", type=int, required=True)
    recon.add_argument(
        "--no-ct",
        action="store_true",
        help="Perform local DNS resolution only; do not contact crt.sh",
    )
    recon.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between CT queries in seconds (0 to 10)",
    )

    args = parser.parse_args()
    init_db()
    db = SessionLocal()
    try:
        if args.command == "create-account":
            password = getpass("New account password (minimum 12 characters): ")
            confirmation = getpass("Confirm password: ")
            if password != confirmation:
                print("Passwords do not match.", file=sys.stderr)
                return 1
            user = create_owner(db, args.username, password)
            print(f"Account created: {user.username} (ID {user.id})")
            return 0

        if args.command == "passive-recon":
            username = input("Account username: ").strip()
            password = getpass("Account password: ")
            if not authenticate(db, username, password):
                print("Invalid credentials.", file=sys.stderr)
                return 1
            user = db.scalar(select(User).where(User.username == username))
            if user is None:
                print("Account not found.", file=sys.stderr)
                return 1
            db.info["owner_id"] = user.id

            if not 0 <= args.delay <= 10:
                parser.error("--delay must be between 0 and 10 seconds")
            result = run_passive_recon(
                db,
                args.project_id,
                use_certificate_transparency=not args.no_ct,
                delay_seconds=args.delay,
            )
            print(json.dumps(result, indent=2))
            return 0
    except KeyboardInterrupt:
        db.rollback()
        print("Interrupted. Pending database changes rolled back.", file=sys.stderr)
        return 130
    except Exception as exc:
        db.rollback()
        print(f"BugHunter error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
