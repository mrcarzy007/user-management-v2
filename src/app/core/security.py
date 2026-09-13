from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

password_hasher = PasswordHash([Argon2Hasher()])


def hash_password(plain_password: str) -> str:
    return password_hasher.hash(plain_password)
