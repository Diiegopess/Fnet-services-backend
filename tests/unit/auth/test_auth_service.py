import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.auth.exceptions import (
    EmailAlreadyExistsError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidGoogleTokenError,
)
from app.auth.models import AuthCredential
from app.auth.schemas import RegisterRequest
from app.auth.service import AuthService, verify_google_token
from app.core.events.base import EventMetadata
from app.core.security import hash_password


# ============================================================================
# FIXTURES BASE (AJUSTADOS)
# ============================================================================
@pytest.fixture
def mock_db():
    """Mock de AsyncSession de SQLAlchemy configurando métodos sincrónicos correctamente."""
    session = AsyncMock()
    session.add = MagicMock()  # Método sincrónico para evitar RuntimeWarning
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result
    return session


@pytest.fixture
def mock_publisher():
    return AsyncMock()


@pytest.fixture
def sample_metadata():
    return EventMetadata(
        correlation_id="test-corr-123",
        user_id=None,
        client_ip="127.0.0.1",
        user_agent="pytest",
    )


# ============================================================================
# 1. PRUEBAS DE GOOGLE TOKEN VERIFIER
# ============================================================================
class TestGoogleTokenVerification:

    @patch("app.auth.service.id_token.verify_oauth2_token")
    def test_verify_google_token_success(self, mock_google_verify):
        mock_google_verify.return_value = {"sub": "12345", "email": "user@google.com"}
        result = verify_google_token("valid_token")
        assert result == {"sub": "12345", "email": "user@google.com"}

    @patch("app.auth.service.id_token.verify_oauth2_token")
    def test_verify_google_token_invalid_returns_none(self, mock_google_verify):
        mock_google_verify.side_effect = ValueError("Invalid token")
        result = verify_google_token("invalid_token")
        assert result is None


# ============================================================================
# 2. PRUEBAS DE REGISTRO
# ============================================================================
class TestRegisterUser:

    @pytest.mark.asyncio
    async def test_register_user_success(self, mock_db, mock_publisher, sample_metadata):
        service = AuthService(db=mock_db, publisher=mock_publisher)
        register_data = RegisterRequest(
            email="newuser@fnet.com",
            password="SecurePassword123!",
            first_name="Diego",
            last_name="Piamba",
        )

        credential = await service.register_user(data=register_data, metadata=sample_metadata)

        assert credential.email == "newuser@fnet.com"
        assert credential.is_active is True
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        mock_publisher.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_user_email_already_exists_raises_error(
        self, mock_db, mock_publisher, sample_metadata
    ):
        existing_account = AuthCredential(email="existing@fnet.com")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_account
        mock_db.execute.return_value = mock_result

        service = AuthService(db=mock_db, publisher=mock_publisher)
        register_data = RegisterRequest(
            email="existing@fnet.com", password="SecurePassword123!"
        )

        with pytest.raises(EmailAlreadyExistsError):
            await service.register_user(data=register_data, metadata=sample_metadata)

        mock_db.add.assert_not_called()
        mock_publisher.publish.assert_not_called()


# ============================================================================
# 3. PRUEBAS DE AUTENTICACIÓN LOCAL
# ============================================================================
class TestAuthenticateUser:

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, mock_db, mock_publisher, sample_metadata):
        hashed = hash_password("CorrectPassword123!")
        account = AuthCredential(
            id=uuid.uuid4(),
            email="user@fnet.com",
            password_hash=hashed,
            is_active=True,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = account
        mock_db.execute.return_value = mock_result

        service = AuthService(db=mock_db, publisher=mock_publisher)

        result = await service.authenticate_user(
            email="user@fnet.com", password="CorrectPassword123!", metadata=sample_metadata
        )

        assert result.email == "user@fnet.com"
        mock_publisher.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password_publishes_failed_event(
        self, mock_db, mock_publisher, sample_metadata
    ):
        hashed = hash_password("CorrectPassword123!")
        account = AuthCredential(
            id=uuid.uuid4(),
            email="user@fnet.com",
            password_hash=hashed,
            is_active=True,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = account
        mock_db.execute.return_value = mock_result

        service = AuthService(db=mock_db, publisher=mock_publisher)

        with pytest.raises(InvalidCredentialsError):
            await service.authenticate_user(
                email="user@fnet.com", password="WrongPassword!", metadata=sample_metadata
            )

        mock_publisher.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user_raises_error(
        self, mock_db, mock_publisher, sample_metadata
    ):
        hashed = hash_password("CorrectPassword123!")
        account = AuthCredential(
            id=uuid.uuid4(),
            email="inactive@fnet.com",
            password_hash=hashed,
            is_active=False,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = account
        mock_db.execute.return_value = mock_result

        service = AuthService(db=mock_db, publisher=mock_publisher)

        with pytest.raises(InactiveUserError):
            await service.authenticate_user(
                email="inactive@fnet.com", password="CorrectPassword123!", metadata=sample_metadata
            )


# ============================================================================
# 4. PRUEBAS DE AUTENTICACIÓN GOOGLE OAUTH
# ============================================================================
class TestAuthenticateGoogleUser:

    @pytest.mark.asyncio
    @patch("app.auth.service.verify_google_token")
    async def test_google_login_invalid_token_raises_error(
        self, mock_verify_token, mock_db, mock_publisher, sample_metadata
    ):
        mock_verify_token.return_value = None
        service = AuthService(db=mock_db, publisher=mock_publisher)

        with pytest.raises(InvalidGoogleTokenError):
            await service.authenticate_google_user(token="bad_token", metadata=sample_metadata)

    @pytest.mark.asyncio
    @patch("app.auth.service.verify_google_token")
    async def test_google_login_missing_sub_or_email_raises_error(
        self, mock_verify_token, mock_db, mock_publisher, sample_metadata
    ):
        """Cubre Línea 146: Token verificado pero incompleto."""
        mock_verify_token.return_value = {"email": "no_sub@fnet.com"}  # Le falta 'sub'
        service = AuthService(db=mock_db, publisher=mock_publisher)

        with pytest.raises(InvalidGoogleTokenError):
            await service.authenticate_google_user(token="incomplete_token", metadata=sample_metadata)

    @pytest.mark.asyncio
    @patch("app.auth.service.verify_google_token")
    async def test_google_login_link_existing_email_account(
        self, mock_verify_token, mock_db, mock_publisher, sample_metadata
    ):
        """Cubre Líneas 161-165: Vincular google_id a un usuario ya existente por email."""
        mock_verify_token.return_value = {
            "sub": "google-new-id-999",
            "email": "existing_local@fnet.com",
        }

        existing_account = AuthCredential(
            id=uuid.uuid4(),
            email="existing_local@fnet.com",
            google_id=None,
            is_active=True,
        )

        # 1er execute (por google_id): None. 2do execute (por email): Encontrado.
        res_by_google = MagicMock()
        res_by_google.scalar_one_or_none.return_value = None

        res_by_email = MagicMock()
        res_by_email.scalar_one_or_none.return_value = existing_account

        mock_db.execute.side_effect = [res_by_google, res_by_email]

        service = AuthService(db=mock_db, publisher=mock_publisher)
        service.users_api = AsyncMock()

        account = await service.authenticate_google_user(
            token="valid_token", metadata=sample_metadata
        )

        assert account.google_id == "google-new-id-999"
        assert account.is_email_verified is True
        mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.auth.service.verify_google_token")
    async def test_google_login_inactive_user_raises_error(
        self, mock_verify_token, mock_db, mock_publisher, sample_metadata
    ):
        """Cubre Línea 180: Usuario de Google con cuenta inactiva."""
        mock_verify_token.return_value = {
            "sub": "google-inactive-123",
            "email": "inactive_google@fnet.com",
        }

        inactive_account = AuthCredential(
            id=uuid.uuid4(),
            email="inactive_google@fnet.com",
            google_id="google-inactive-123",
            is_active=False,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = inactive_account
        mock_db.execute.return_value = mock_result

        service = AuthService(db=mock_db, publisher=mock_publisher)

        with pytest.raises(InactiveUserError):
            await service.authenticate_google_user(
                token="valid_token", metadata=sample_metadata
            )

    @pytest.mark.asyncio
    @patch("app.auth.service.verify_google_token")
    async def test_google_login_new_user_creation(
        self, mock_verify_token, mock_db, mock_publisher, sample_metadata
    ):
        mock_verify_token.return_value = {
            "sub": "google-12345",
            "email": "newgoogle@fnet.com",
            "given_name": "Diego",
            "family_name": "Piamba",
        }

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        service = AuthService(db=mock_db, publisher=mock_publisher)
        service.users_api = AsyncMock()
        service.users_api.get_user_by_id.return_value = None

        account = await service.authenticate_google_user(
            token="valid_google_token", metadata=sample_metadata
        )

        assert account.email == "newgoogle@fnet.com"
        service.users_api.create_profile.assert_called_once()


# ============================================================================
# 5. PRUEBAS DE LOGOUT
# ============================================================================
class TestLogoutUser:

    @pytest.mark.asyncio
    async def test_logout_user_publishes_event(self, mock_db, mock_publisher, sample_metadata):
        service = AuthService(db=mock_db, publisher=mock_publisher)
        user_id = uuid.uuid4()

        await service.logout_user(user_id=user_id, metadata=sample_metadata)

        mock_publisher.publish.assert_called_once()