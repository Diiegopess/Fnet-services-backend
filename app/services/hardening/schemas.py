# app/services/hardening/schemas.py

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.services.hardening.models import (
    ExecutionType,
    FindingStatus,
    ProfileType,
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
    device_id: UUID
    execution_type: ExecutionType
    profile_id: Optional[UUID] = None
    adhoc_rule_ids: Optional[List[str]] = None
    standard_version: Optional[str] = Field("v1.0.0", description="Versión del benchmark a evaluar.")
    vdom_id: Optional[UUID] = None
    connection_data: Optional[Dict[str, Any]] = Field(
        None, description="Parámetros host/port/token si se extrae en caliente."
    )
    raw_config: Optional[Any] = Field(
        None, description="Configuración estática/mock para pruebas."
    )

    @model_validator(mode="after")
    def validate_execution_payload(self) -> "AuditExecutionRequest":
        if self.execution_type == ExecutionType.CUSTOM_ADHOC:
            if not self.adhoc_rule_ids or len(self.adhoc_rule_ids) == 0:
                raise ValueError("Para ejecuciones CUSTOM_ADHOC se requiere 'adhoc_rule_ids' con al menos una regla.")
        elif self.execution_type in (ExecutionType.FULL_STANDARD, ExecutionType.ASSIGNED_PROFILE):
            if not self.profile_id:
                raise ValueError("Para ejecuciones por perfil o estándar se requiere 'profile_id'.")
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
    device_id: UUID
    profile_id: Optional[UUID] = None
    execution_type: ExecutionType
    score: float = Field(0.0, description="Porcentaje total de cumplimiento de la auditoría.")
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