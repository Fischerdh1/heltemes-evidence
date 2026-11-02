"""Command-line entry point; run from the project with python3 -m heltemes."""
import argparse
import json
import os
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description="HELTEMES Evidence — Earnings Research Platform")
    parser.add_argument("--data-dir", default=os.getenv("HELTEMES_DATA_DIR", "data"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("configure", help="Save a private SEC contact email locally")
    sub.add_parser("demo", help="Load clearly labeled synthetic learning records")
    collect = sub.add_parser("collect", help="Collect real SEC filings using SEC_USER_AGENT")
    collect.add_argument("--cik", required=True)
    collect.add_argument("--forms", nargs="+", default=["10-Q"])
    collect.add_argument("--limit", type=int, default=3)
    sub.add_parser("verify", help="Check preserved evidence against recorded hashes")
    sub.add_parser("status", help="Show local collection status")
    backup = sub.add_parser("backup", help="Create a verified backup archive")
    backup.add_argument("destination")
    restore = sub.add_parser("restore", help="Restore an archive to a new empty directory")
    restore.add_argument("archive")
    restore.add_argument("destination")
    restore.add_argument("--trust-receipt", help="Independently saved public verification receipt for a protected backup")
    protect = sub.add_parser("protect", help="Manage local signed checkpoints separately from collection")
    protection_commands = protect.add_subparsers(dest="protection_command", required=True)
    protection_commands.add_parser("init", help="Enroll this archive and seal its first checkpoint")
    seal = protection_commands.add_parser("seal", help="Check prior history, then sign newly added records")
    seal.add_argument("--key-dir", help="Explicit matching signing-key directory for a restored verifier-only archive")
    receipt = protection_commands.add_parser("receipt", help="Save public trust receipt separately from an evidence backup")
    receipt.add_argument("destination")
    protection_commands.add_parser("status", help="Read signed-checkpoint verification status")
    recovery = protection_commands.add_parser("recover", help="Inspect or explicitly complete an authorized signing-key recovery")
    recovery_commands = recovery.add_subparsers(dest="recovery_command", required=True)
    recovery_commands.add_parser("status", help="Check archive verification and whether signing is permitted")
    plan = recovery_commands.add_parser("plan", help="Create a public request for independent review; does not authorize recovery")
    plan.add_argument("--candidate-key", required=True)
    plan.add_argument("--trust-receipt", required=True)
    plan.add_argument("--output", required=True)
    prepare = recovery_commands.add_parser("prepare", help="Record a specifically authorized recovery and block ordinary signing")
    prepare.add_argument("--candidate-key", required=True)
    prepare.add_argument("--authorization", required=True)
    prepare.add_argument("--authorization-sha256", required=True)
    recovery_commands.add_parser("resume", help="Revalidate and finish the recorded recovery without repeating a completed transition")
    server = sub.add_parser("serve", help="Open the loopback-only local dashboard")
    server.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    from .core import Repository, restore_backup
    from .config import save_contact, user_agent
    try:
        from .local_accounts import policy_for
        policy = policy_for(args.data_dir)
        # Recovery owns its locking and managed private snapshot. Dispatch before
        # Repository construction or the generic managed protection-status path.
        if args.command == "protect" and args.protection_command == "recover":
            from .key_recovery import recovery_status, plan_recovery, prepare_recovery, resume_recovery
            if args.recovery_command == "status":
                result = recovery_status(args.data_dir)
            elif args.recovery_command == "plan":
                result = plan_recovery(args.data_dir, args.candidate_key, args.trust_receipt, args.output)
            elif args.recovery_command == "prepare":
                result = prepare_recovery(args.data_dir, args.candidate_key, args.authorization, args.authorization_sha256)
            else:
                result = resume_recovery(args.data_dir)
            print(json.dumps(result, indent=2, default=str))
            return 0 if result.get("ok", True) else 1
        if policy and args.command in {"configure", "serve", "demo", "collect", "backup"}:
            policy.require("collector")
        if policy and args.command == "protect" and args.protection_command in {"init", "seal"}:
            if args.protection_command == "init":
                raise ValueError("Managed protection cannot be initialized or reset. Use the administrator migration installer.")
            from .protection import seal_checkpoint
            result = seal_checkpoint(args.data_dir, key_dir=args.key_dir)
            print(json.dumps(result, indent=2))
            return 0
        if policy and os.geteuid() == policy.custodian_uid and (args.command == "verify" or args.command == "protect"):
            from .local_accounts import verify_managed, private_snapshot
            from .protection import export_receipt
            if args.command == "protect" and args.protection_command == "receipt":
                with private_snapshot(policy) as staging:
                    result = {"receipt": export_receipt(staging, args.destination, policy.trust_dir)}
            else:
                result = verify_managed(policy)
                if args.command == "protect":
                    result = result["protection"]
            print(json.dumps(result, indent=2))
            return 0 if result.get("ok", True) else 1
        if args.command == "configure":
            print("Your contact email identifies automated requests to the SEC. It stays in the ignored local data directory.")
            email = input("SEC contact email: ").strip()
            save_contact(args.data_dir, email)
            print("Contact saved locally. Refresh the dashboard to enable live collection.")
            return 0
        if args.command == "serve":
            from .server import serve
            serve(args.data_dir, args.port)
            return 0
        if args.command == "restore":
            result = restore_backup(Path(args.archive), Path(args.destination), trust_receipt=args.trust_receipt)
            print(json.dumps({"restored": str(result)}, indent=2))
            return 0
        repo = Repository(Path(args.data_dir))
        if args.command == "protect":
            from .protection import initialize_protection, seal_checkpoint, export_receipt, verify_protection, repository_lock
            if args.protection_command == "status":
                result = verify_protection(repo.data_dir)
            elif args.protection_command == "receipt":
                with repository_lock(repo.data_dir):
                    result = {"receipt": str(export_receipt(repo.data_dir, args.destination))}
            else:
                with repository_lock(repo.data_dir):
                    verified = repo.verify_integrity()
                    if not verified["ok"]:
                        raise ValueError("Verification failed. No checkpoint was signed; investigate the recorded issues.")
                    repo.make_evidence_readonly()
                    if args.protection_command == "init":
                        result = initialize_protection(repo.data_dir)
                    else:
                        result = seal_checkpoint(repo.data_dir, key_dir=args.key_dir)
        elif args.command == "demo":
            result = repo.seed_demo()
        elif args.command == "collect":
            result = repo.collect(args.cik, user_agent(args.data_dir), forms=args.forms, limit=args.limit)
        elif args.command == "verify":
            result = repo.verify_integrity()
        elif args.command == "status":
            result = repo.dashboard()
        elif args.command == "backup":
            result = {"backup": str(repo.backup(Path(args.destination)))}
        print(json.dumps(result, indent=2, default=str))
        return 1 if isinstance(result, dict) and (result.get("ok") is False or result.get("status") in {"failed", "partial"}) else 0
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
