from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import bcrypt
import jwt
import base64
import hashlib
from cryptography.fernet import Fernet

from app.core.config import settings


def hash_password(password: str) -> str:
    """Genera un hash seguro para una contraseña en texto plano."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña ingresada coincide con el hash almacenado."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


def create_access_token(
    subject: str | Any,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict[str, Any]] = None,
) -> str:
    """Crea un JWT de acceso con tiempo de expiración y claims personalizados."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "iat": now,
        "exp": expire,
        "sub": str(subject),
        "type": "access",
    }
    
    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decodifica y valida un token JWT."""
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

def _get_fernet_cipher() -> Fernet:
    """Genera una clave Fernet válida de 32 bytes en base64 a partir de SECRET_KEY."""
    derived_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))

def encrypt_secret(secret_text: str) -> str:
    """Cifra un secreto (API token / password de red) para guardarlo en BD."""
    if not secret_text:
        return ""
    cipher = _get_fernet_cipher()
    return cipher.encrypt(secret_text.encode("utf-8")).decode("utf-8")

def decrypt_secret(encrypted_text: str) -> str:
    """Descifra un secreto recuperado de la base de datos."""
    if not encrypted_text:
        return ""
    cipher = _get_fernet_cipher()
    return cipher.decrypt(encrypted_text.encode("utf-8")).decode("utf-8")