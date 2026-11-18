import argparse
import getpass

from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.user import User, UserRole, UserStatus


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or promote a service administrator")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    email = args.email.strip().lower()
    password = getpass.getpass("Admin password (10+ chars, letter and number): ")
    if len(password) < 10 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise SystemExit("Password policy not met")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(
                email=email,
                password_hash=hash_password(password),
                role=UserRole.ADMIN,
                status=UserStatus.ACTIVE,
            )
            db.add(user)
        else:
            user.password_hash = hash_password(password)
            user.role = UserRole.ADMIN
            user.status = UserStatus.ACTIVE
        db.commit()
    print(f"Administrator ready: {email}")


if __name__ == "__main__":
    main()

