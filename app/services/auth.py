from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from sqlalchemy import select
from app.models.entities import User
_hasher=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
def create_owner(db,username,password):
    username=username.strip()
    if not username or len(password)<12: raise ValueError("Username required; password must be at least 12 characters.")
    if db.scalar(select(User).where(User.username==username)): raise ValueError("Account already exists.")
    u=User(username=username,password_hash=_hasher.hash(password)); db.add(u); db.commit(); return u
def authenticate(db,username,password):
    u=db.scalar(select(User).where(User.username==username.strip()))
    if not u: return False
    try: return _hasher.verify(u.password_hash,password)
    except (VerifyMismatchError,InvalidHashError): return False
