from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.hardening.models import (
    ExecutionType,
    FindingStatus,
    ProfileType,
    RuleScope,
    RuleSeverity,
)


# --- SCHEMAS DE CATÁLOGO Y REGLAS ---

class RuleCatalogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    standard_version: str = "v1.0.0"
    name: str
    description: Optional[str] = None
    category: str
    standard: str
    default_severity: RuleSeverity
    scope: RuleScope = RuleScope.VDOM
    required_endpoint: str
    is_active: bool = True


class RuleGroupResponse(BaseModel):
    """Schema para la respuesta del catálogo agrupado por categoría (frontend Ad-hoc)."""
    category: str
    count: int
    rules: List[RuleCatalogResponse]


# --- SCHEMAS DE PERFILES ---

class HardeningProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str] = None
    standard_version: str
    profile_type: ProfileType
    is_active: bool
    created_at: datetime
    rules: List[RuleCatalogResponse] = []


# --- SCHEMAS DE EJECUCIÓN Y AUDITORÍA ---

class AuditExecutionRequest(BaseModel):
    vdom_id: Optional[UUID] = Field(
        None, description="ID de la VDOM objetivo a evaluar (Recomendado)."
    )
    device_id: Optional[UUID] = Field(
        None, description="ID del chasis físico (opcional si se provee vdom_id o raw_config)."
    )
    execution_type: ExecutionType = Field(
        default=ExecutionType.FULL_STANDARD,
        description="Tipo de ejecución (FULL_STANDARD, ASSIGNED_PROFILE, CUSTOM_ADHOC)"
    )
    profile_id: Optional[UUID] = None
    adhoc_rule_ids: Optional[List[str]] = None
    standard_version: Optional[str] = Field("v1.0.1", description="Versión del benchmark a evaluar.")
    connection_data: Optional[Dict[str, Any]] = Field(
        None, description="Parámetros host/port/token si se extrae en caliente."
    )
    raw_config: Optional[Any] = Field(
        None, description="Configuración estática/mock para pruebas u offline."
    )

    @model_validator(mode="after")
    def validate_execution_payload(self) -> "AuditExecutionRequest":
        # 1. Validación de destino (si no es offline, se requiere vdom_id o device_id)
        if not self.raw_config and not self.vdom_id and not self.device_id:
            raise ValueError("Para auditorías en vivo se requiere al menos 'vdom_id' o 'device_id'.")

        # 2. Validación de reglas según el tipo de ejecución
        if self.execution_type == ExecutionType.CUSTOM_ADHOC:
            if not self.adhoc_rule_ids or len(self.adhoc_rule_ids) == 0:
                raise ValueError("Para ejecuciones CUSTOM_ADHOC se requiere 'adhoc_rule_ids' con al menos una regla.")
        elif self.execution_type == ExecutionType.ASSIGNED_PROFILE:
            if not self.profile_id:
                raise ValueError("Para ejecuciones ASSIGNED_PROFILE se requiere 'profile_id'.")
        elif self.execution_type == ExecutionType.FULL_STANDARD:
            if not self.profile_id and not self.standard_version:
                raise ValueError("Para ejecuciones FULL_STANDARD se requiere 'profile_id' o 'standard_version'.")

        return self


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    standard_version: str = "v1.0.0"
    status: FindingStatus
    compliance_score: float = Field(0.0, description="Porcentaje de cumplimiento de la regla (0.0 a 100.0).")
    severity: RuleSeverity
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation_cmd: Optional[str] = None


class AuditReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: Optional[UUID] = None
    vdom_id: Optional[UUID] = None
    profile_id: Optional[UUID] = None
    execution_type: ExecutionType
    score: float = Field(0.0, description="Porcentaje total de cumplimiento de la auditoría.")
    executed_by: Optional[UUID] = None
    executed_at: datetime

    total_passed: int
    total_failed: int
    total_not_applicable: int = 0
    total_rules_evaluated: int = 0

    findings: List[FindingResponse] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_total_rules(self) -> "AuditReportResponse":
        if self.total_rules_evaluated == 0:
            self.total_rules_evaluated = (
                self.total_passed + self.total_failed + self.total_not_applicable
            )
        return self


# --- SCHEMAS DE AUDITORÍA DESDE ARCHIVO DE BACKUP (OFFLINE) ---

class BackupFindingResponse(BaseModel):
    """Hallazgo individual evaluado en memoria a partir del backup."""
    rule_id: str
    standard_version: str = "v1.0.0"
    status: FindingStatus
    compliance_score: float = Field(0.0, description="Porcentaje de cumplimiento de la regla (0.0 a 100.0).")
    severity: RuleSeverity
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation_cmd: Optional[str] = None


class BackupDeviceInfo(BaseModel):
    """Metadatos extraídos de la cabecera (#config-version) del archivo de backup."""
    model: str = "FortiGate"
    firmware_version: str = "Desconocida"
    build: Optional[str] = None
    vdom_enabled: bool = False


class BackupAuditResponse(BaseModel):
    """Respuesta completa del escaneo offline para renderizar directamente en el frontend."""
    device_info: BackupDeviceInfo
    score: float = Field(0.0, description="Porcentaje total de cumplimiento del backup.")
    
    total_passed: int = 0
    total_partial: int = 0
    total_failed: int = 0
    total_not_applicable: int = 0
    total_rules_evaluated: int = 0

    findings: List[BackupFindingResponse] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_total_rules(self) -> "BackupAuditResponse":
        if self.total_rules_evaluated == 0:
            self.total_rules_evaluated = (
                self.total_passed
                + self.total_partial
                + self.total_failed
                + self.total_not_applicable
            )
        return self