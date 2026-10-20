import argparse
from app.config import Config
from app.repository import Repository

def main():
    parser=argparse.ArgumentParser(description="SentinelScope operator administration")
    sub=parser.add_subparsers(dest="command",required=True)
    p=sub.add_parser("promote-admin",help="Grant system administrator access")
    p.add_argument("email")
    d=sub.add_parser("demote-admin",help="Remove system administrator access")
    d.add_argument("email")
    sub.add_parser("list-admins",help="List active system administrators")
    args=parser.parse_args()

    repo=Repository(Config.DATABASE_PATH);repo.init_schema()
    if args.command=="list-admins":
        for u in repo.admin_list_users():
            if u.get("system_admin") and u.get("active"):print(f"{u['email']}  {u['name']}")
        return
    user=repo.get_user_by_email(args.email)
    if not user:raise SystemExit("User not found")
    if args.command=="promote-admin":
        repo.set_system_admin(user["id"],True);print(f"Promoted {user['email']} to system administrator")
    elif args.command=="demote-admin":
        if user.get("system_admin") and repo.system_admin_count()<=1:
            raise SystemExit("Cannot remove the last active system administrator")
        repo.set_system_admin(user["id"],False);print(f"Removed system administrator access from {user['email']}")

if __name__=="__main__":main()
