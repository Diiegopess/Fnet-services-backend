from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración global de la aplicación cargada desde variables de entorno."""

    # --- Proyecto ---
    PROJECT_NAME: str = "App_Log API"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # --- Seguridad y JWT ---
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- Base de Datos Relacional (PostgreSQL) ---
    DATABASE_URL: str

    # --- Base de Datos en Memoria (Redis) ---
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 20

    # --- Broker de Eventos ---
    BROKER_TYPE: str = "REDIS"
    AUTH_STREAM_NAME: str = "stream:auth_events"
    SYSTEM_STREAM_NAME: str = "stream:system_events"
    
    # Grupos de Consumidores
    USERS_CONSUMER_GROUP: str = "users_service_group"
    AUDIT_CONSUMER_GROUP: str = "audit_service_group"

    # --- Autenticación Externa ---
    GOOGLE_CLIENT_ID: str = ""

    # --- Superusuario Inicial (Seeding) ---
    FIRST_SUPERUSER_EMAIL: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "admin123"
    FIRST_SUPERUSER_FULL_NAME: str = "Administrador del Sistema"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()