from unittest.mock import AsyncMock, MagicMock
import pytest

from app.auth.exceptions import InvalidCredentialsError, InactiveUserError
from app.auth.service import AuthService
from app.core.security import hash_password


# ============================================================================
# FIXTURES Y MOCKS PARA AUTENTICACIÓN
# ============================================================================
@pytest.fixture
def mock_user_repo():
    """Mock del repositorio de usuarios para no tocar la BD real."""
    return AsyncMock()


@pytest.fixture
def sample_hashed_password():
    return hash_password("SecretPassword123!")


@pytest.fixture
def active_user(sample_hashed_password):
    """Crea una entidad de usuario activo simulada."""
    user = MagicMock()
    user.id = "user-uuid-1234"
    user.email = "admin@fnet.com"
    user.hashed_password = sample_hashed_password
    user.is_active = True
    user.role = "admin"
    return user


@pytest.fixture
def inactive_user(sample_hashed_password):
    """Crea una entidad de usuario inactivo simulada."""
    user = MagicMock()
    user.id = "user-uuid-5678"
    user.email = "inactive@fnet.com"
    user.hashed_password = sample_hashed_password
    user.is_active = False
    return user


# ============================================================================
# PRUEBAS UNITARIAS DE AUTH SERVICE
# ============================================================================
class TestAuthServiceLogin:
    """Pruebas para el flujo de autenticación de usuarios."""

    @pytest.mark.asyncio
    async def test_login_success(self, mock_user_repo, active_user):
        # Arrange
        mock_user_repo.get_by_email.return_value = active_user
        auth_service = AuthService(user_repo=mock_user_repo)

        # Act
        result = await auth_service.authenticate_user(
            email="admin@fnet.com", password="SecretPassword123!"
        )

        # Assert
        assert result is not None
        assert "access_token" in result
        mock_user_repo.get_by_email.assert_called_once_with("admin@fnet.com")

    @pytest.mark.asyncio
    async def test_login_user_not_found_raises_error(self, mock_user_repo):
        # Arrange (El repositorio no encuentra al usuario)
        mock_user_repo.get_by_email.return_value = None
        auth_service = AuthService(user_repo=mock_user_repo)

        # Act & Assert
        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user(
                email="nonexistent@fnet.com", password="Password123!"
            )

    @pytest.mark.asyncio
    async def test_login_wrong_password_raises_error(self, mock_user_repo, active_user):
        # Arrange
        mock_user_repo.get_by_email.return_value = active_user
        auth_service = AuthService(user_repo=mock_user_repo)

        # Act & Assert
        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user(
                email="admin@fnet.com", password="WrongPassword123!"
            )

    @pytest.mark.asyncio
    async def test_login_inactive_user_raises_error(self, mock_user_repo, inactive_user):
        # Arrange
        mock_user_repo.get_by_email.return_value = inactive_user
        auth_service = AuthService(user_repo=mock_user_repo)

        # Act & Assert
        with pytest.raises(UserInactiveError):
            await auth_service.authenticate_user(
                email="inactive@fnet.com", password="SecretPassword123!"
            )