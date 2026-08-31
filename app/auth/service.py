"""
Módulo de Servicios para el Dominio de Autenticación.

Gestiona la verificación de credenciales locales, validación de tokens
de Google OAuth 2.0 y el aprovisionamiento de perfiles vía UsersFacade.
"""

from google.auth.transport import requests
from google.oauth2 import id_token
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.exceptions import (
    InactiveUserError,
    InvalidCredentialsError,
    InvalidGoogleTokenError,
)
from app.auth.models import AuthCredential
from app.auth.schemas import RegisterRequest
from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.exceptions import AppException
from app.core.security import hash_password, verify_password
from app.users.api import UsersAPI


# ==============================================================================
# 1. UTILIDAD DE GOOGLE OAUTH
# ==============================================================================
def verify_google_token(token: str) -> dict | None:
    """Verifica la firma y validez de un ID Token emitido por Google."""
    try:
        id_info = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            settings.GOOGLE_CLIENT_ID,
        )
        return id_info
    except ValueError:
        return None


# ==============================================================================
# 2. SERVICIO DE AUTENTICACIÓN
# ==============================================================================
class AuthService:
    """Servicio que encapsula las operaciones de autenticación y emisión de eventos."""

    def __init__(self, db: AsyncSession, publisher: IEventPublisher):
        self.db = db
        self.publisher = publisher
        self.users_api = UsersAPI(db)

    async def register_user(
        self,
        data: RegisterRequest,
        metadata: EventMetadata,
    ) -> AuthCredential:
        """
        Registra una nueva credencial y emite el evento 'auth.user_registered'.
        """
        # 1. Verificar si el correo ya existe
        stmt = select(AuthCredential).where(AuthCredential.email == data.email)
        result = await self.db.execute(stmt)
        if result.scalar_one_or_none():
            raise AppException(
                message="El correo electrónico ya se encuentra registrado.",
                status_code=409,
                error_code="EMAIL_ALREADY_EXISTS",
            )

        # 2. Crear y persistir la credencial en la base de datos
        hashed_pwd = hash_password(data.password)
        credential = AuthCredential(
            email=data.email,
            password_hash=hashed_pwd,
            is_active=True,
            is_email_verified=False,
        )
        self.db.add(credential)
        await self.db.commit()
        await self.db.refresh(credential)

        # 3. Publicar evento en Redis Streams (Desacoplado hacia Users y Audit)
        event = DomainEvent(
            event_type="auth.user_registered",
            metadata=metadata,
            payload={
                "user_id": str(credential.id),
                "email": credential.email,
                "first_name": data.first_name,
                "last_name": data.last_name,
                "auth_provider": "local",
            },
        )
        await self.publisher.publish(stream_or_topic=settings.AUTH_STREAM_NAME, event=event)

        return credential

    async def authenticate_user(
        self,
        email: str,
        password: str,
        metadata: EventMetadata,
    ) -> AuthCredential:
        """
        Autentica credenciales locales y publica el evento 'auth.login_success'.
        """
        stmt = select(AuthCredential).where(AuthCredential.email == email)
        result = await self.db.execute(stmt)
        account = result.scalar_one_or_none()

        if not account or not account.password_hash or not verify_password(password, account.password_hash):
            raise InvalidCredentialsError()

        if not account.is_active:
            raise InactiveUserError()

        # Emitir evento de auditoría de inicio de sesión exitoso
        event = DomainEvent(
            event_type="auth.login_success",
            metadata=metadata,
            payload={
                "user_id": str(account.id),
                "email": account.email,
                "auth_provider": "local",
            },
        )
        await self.publisher.publish(stream_or_topic=settings.AUTH_STREAM_NAME, event=event)

        return account

    async def authenticate_google_user(
        self,
        token: str,
        metadata: EventMetadata,
    ) -> AuthCredential:
        """
        Valida token de Google, vincula o crea credenciales y perfil de forma síncrona
        vía UsersFacade, y emite los eventos de auditoría correspondientes.
        """
        id_info = verify_google_token(token)
        if not id_info:
            raise InvalidGoogleTokenError()

        google_id: str | None = id_info.get("sub")
        email: str | None = id_info.get("email")

        if not google_id or not email:
            raise InvalidGoogleTokenError(
                message="El token de Google no contiene la información requerida (email o sub)."
            )

        # 1. Buscar por google_id
        stmt_google = select(AuthCredential).where(AuthCredential.google_id == google_id)
        result_google = await self.db.execute(stmt_google)
        account = result_google.scalar_one_or_none()

        # 2. Si no existe por google_id, buscar por email para vincular
        is_new_user = False
        if not account:
            stmt_email = select(AuthCredential).where(AuthCredential.email == email)
            result_email = await self.db.execute(stmt_email)
            account = result_email.scalar_one_or_none()

            if account:
                account.google_id = google_id
                account.is_email_verified = True
                self.db.add(account)
                await self.db.commit()
                await self.db.refresh(account)
            else:
                # 3. Crear nueva cuenta
                is_new_user = True
                account = AuthCredential(
                    email=email,
                    google_id=google_id,
                    password_hash=None,
                    is_active=True,
                    is_email_verified=True,
                )
                self.db.add(account)
                await self.db.commit()
                await self.db.refresh(account)

        if not account.is_active:
            raise InactiveUserError()

        # 4. Asegurar perfil síncrono en Users mediante la Fachada
        existing_profile = await self.users_api.get_user_by_id(account.id)
        if not existing_profile:
            given_name = id_info.get("given_name") or ""
            family_name = id_info.get("family_name") or ""
            full_name = f"{given_name} {family_name}".strip() or email.split("@")[0]

            await self.users_api.create_profile(
                user_id=account.id,
                email=account.email,
                full_name=full_name,
                is_active=True,
                is_superuser=False,
                role_names=["USER"],
            )

        # 5. Publicar evento si es nuevo usuario registrado con Google
        if is_new_user:
            register_event = DomainEvent(
                event_type="auth.user_registered",
                metadata=metadata,
                payload={
                    "user_id": str(account.id),
                    "email": account.email,
                    "first_name": id_info.get("given_name"),
                    "last_name": id_info.get("family_name"),
                    "auth_provider": "google",
                },
            )
            await self.publisher.publish(stream_or_topic=settings.AUTH_STREAM_NAME, event=register_event)

        # 6. Publicar evento de login exitoso
        login_event = DomainEvent(
            event_type="auth.login_success",
            metadata=metadata,
            payload={
                "user_id": str(account.id),
                "email": account.email,
                "auth_provider": "google",
            },
        )
        await self.publisher.publish(stream_or_topic=settings.AUTH_STREAM_NAME, event=login_event)

        return account