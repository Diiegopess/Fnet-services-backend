from datetime import timedelta
import pytest
import jwt
from cryptography.fernet import InvalidToken

from app.core.exceptions import UnauthorizedError
from app.core.security import (
    create_access_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    verify_password,
)


# ============================================================================
# 1. PRUEBAS DE HASHING DE CONTRASEÑAS
# ============================================================================
class TestPasswordHashing:
    """Valida la seguridad y robustez del hashing con Bcrypt."""

    def test_hash_password_success(self):
        # Arrange
        password = "my_secure_password_123"

        # Act
        hashed = hash_password(password)

        # Assert
        assert hashed != password
        assert hashed.startswith("$2b$")

    def test_hash_password_uses_unique_salt(self):
        # Arrange
        password = "my_secure_password_123"

        # Act
        hash_1 = hash_password(password)
        hash_2 = hash_password(password)

        # Assert (Misma contraseña produce hashes distintos por el salt)
        assert hash_1 != hash_2

    def test_verify_password_correct(self):
        # Arrange
        password = "my_secure_password_123"
        hashed = hash_password(password)

        # Act & Assert
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        # Arrange
        password = "my_secure_password_123"
        hashed = hash_password(password)

        # Act & Assert
        assert verify_password("wrong_password_123", hashed) is False

    def test_verify_password_edge_cases(self):
        # Arrange
        password = "my_secure_password_123"

        # Act & Assert (Manejo seguro de valores vacíos)
        assert verify_password("", "$2b$12$invalidhashstructure") is False
        assert verify_password(password, "") is False

    def test_verify_password_with_corrupted_hash_format(self):
        """Prueba que un hash corrupto capture la excepción y retorne False sin lanzar error."""
        # Arrange
        corrupted_hash = "$2b$12$0000000000000000000000INVALIDHASHFORMAT!!!!!!"

        # Act & Assert
        assert verify_password("my_password", corrupted_hash) is False


# ============================================================================
# 2. PRUEBAS DE TOKENS JWT
# ============================================================================
class TestJWTTokens:
    """Valida la emisión, expiración y seguridad de los tokens JWT."""

    def test_create_and_decode_access_token_success(self):
        # Arrange
        subject = "user_12345"

        # Act
        token = create_access_token(subject=subject)
        decoded = decode_token(token)

        # Assert
        assert decoded["sub"] == "user_12345"
        assert decoded["type"] == "access"
        assert "exp" in decoded
        assert "iat" in decoded

    def test_create_access_token_with_extra_claims(self):
        # Arrange
        subject = "user_12345"
        extra = {"role": "admin", "tenant_id": "tenant_abc"}

        # Act
        token = create_access_token(subject=subject, extra_claims=extra)
        decoded = decode_token(token)

        # Assert
        assert decoded["sub"] == "user_12345"
        assert decoded["role"] == "admin"
        assert decoded["tenant_id"] == "tenant_abc"

    def test_expired_token_raises_error(self):
        # Arrange
        subject = "user_12345"
        expired_token = create_access_token(
            subject=subject, expires_delta=timedelta(seconds=-10)
        )

        # Act & Assert
        with pytest.raises((jwt.ExpiredSignatureError, UnauthorizedError)):
            decode_token(expired_token)

    def test_decode_invalid_token_format_raises_error(self):
        # Arrange
        invalid_token = "invalid.jwt.token.payload"

        # Act & Assert
        with pytest.raises((jwt.PyJWTError, UnauthorizedError)):
            decode_token(invalid_token)

    def test_decode_token_signed_with_different_secret_raises_error(self):
        # Arrange (Falsificación de firma con clave de al menos 32 bytes/256 bits)
        fake_payload = {"sub": "user_12345", "type": "access"}
        forged_token = jwt.encode(
            fake_payload,
            "clave_falsa_extremadamente_larga_de_mas_de_32_bytes!",
            algorithm="HS256",
        )

        # Act & Assert
        with pytest.raises((jwt.PyJWTError, UnauthorizedError)):
            decode_token(forged_token)


# ============================================================================
# 3. PRUEBAS DE CIFRADO FERNET
# ============================================================================
class TestFernetEncryption:
    """Valida el cifrado y descifrado simétrico de credenciales y secretos."""

    def test_encrypt_and_decrypt_secret_success(self):
        # Arrange
        raw_secret = "FortiGate_API_Token_XYZ_987654321"

        # Act
        encrypted = encrypt_secret(raw_secret)
        decrypted = decrypt_secret(encrypted)

        # Assert
        assert encrypted != raw_secret
        assert decrypted == raw_secret

    def test_encrypt_and_decrypt_empty_string(self):
        # Act & Assert
        assert encrypt_secret("") == ""
        assert decrypt_secret("") == ""

    def test_decrypt_tampered_ciphertext_raises_error(self):
        # Arrange
        invalid_encrypted_text = "gAAAAABk_invalid_fernet_token_payload=="

        # Act & Assert
        with pytest.raises((InvalidToken, Exception)):
            decrypt_secret(invalid_encrypted_text)

    def test_decrypt_malformed_string_raises_error(self):
        # Arrange
        malformed_text = "not_even_base64_!@#$%"

        # Act & Assert
        with pytest.raises((InvalidToken, Exception)):
            decrypt_secret(malformed_text)