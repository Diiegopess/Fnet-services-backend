"""
Módulo de Esquemas Pydantic v2 para el Dominio de Autenticación.
"""

from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --- 1. CONTRATO DE ENTRADA: REGISTRO LOCAL ---
class RegisterRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Correo electrónico corporativo o personal del usuario",
        examples=["usuario@ejemplo.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        description="Contraseña segura en texto plano (mínimo 8 caracteres)",
        examples=["PasswordSeguro123!"],
    )
    # Datos opcionales de perfil inicial que viajarán en el evento hacia el dominio 'users'
    first_name: str | None = Field(default=None, examples=["Juan"])
    last_name: str | None = Field(default=None, examples=["Pérez"])


# --- 2. CONTRATO DE ENTRADA: LOGIN LOCAL ---
class LoginRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Correo electrónico registrado del usuario",
        examples=["usuario@ejemplo.com"],
    )
    password: str = Field(
        ...,
        description="Contraseña en texto plano ingresada en el formulario",
    )


# --- 3. CONTRATO DE ENTRADA: GOOGLE OAUTH 2.0 ---
class GoogleAuthRequest(BaseModel):
    id_token: str = Field(
        ...,
        description="ID Token JWT emitido y firmado por Google",
    )


# --- 4. CONTRATO DE SALIDA: RESPUESTA DE AUTENTICACIÓN ---
class TokenResponse(BaseModel):
    access_token: str = Field(
        ...,
        description="Token de acceso firmado en formato JWT",
    )
    token_type: str = Field(
        default="bearer",
        description="Tipo de token emitido según el esquema Bearer Auth",
    )


# --- 5. CONTRATO DE SALIDA: REGISTRO EXITOSO ---
class AuthCredentialResponse(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool
    is_email_verified: bool

    model_config = ConfigDict(from_attributes=True)