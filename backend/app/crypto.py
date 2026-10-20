import hashlib
import hmac
import secrets


def hash_password(password: str, salt: str | None = None) -> str:
    if not password or len(password) < 10:
        raise ValueError("Password must be at least 10 characters")
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 310_000)
    return "pbkdf2_sha256$310000$"+salt_bytes.hex()+"$"+digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, expected = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt_secret(value: str, key: str | None) -> str:
    if not value:
        return value
    if not key:
        return "plain$"+value
    from cryptography.fernet import Fernet
    token=Fernet(key.encode()).encrypt(value.encode()).decode()
    return "fernet$"+token

def decrypt_secret(value: str | None, key: str | None) -> str:
    if not value:
        return ""
    if value.startswith("fernet$"):
        if not key:
            raise ValueError("APP_ENCRYPTION_KEY is required to decrypt protected secrets")
        from cryptography.fernet import Fernet
        return Fernet(key.encode()).decrypt(value.split("$",1)[1].encode()).decode()
    if value.startswith("plain$"):
        return value.split("$",1)[1]
    return value
