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
    name: str
    description: Optional[str] = None
    category: str
    standard: str
    default_severity: RuleSeverity
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
    vdom_id: Optional[UUID] = None
    raw_config: Optional[Any] = Field(
        None, description="Configuración estática para pruebas."
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
    status: FindingStatus
    compliance_score: float = Field(0.0, description="Porcentaje de cumplimiento de la regla (0.0 a 100.0).")
    severity: RuleSeverity
    current_value: Optional[str] = None
    raw_evidence: Optional[str] = Field(
        None, description="Línea o bloque exacto de la configuración analizado."
    )
    reason: Optional[str] = Field(
        None, description="Justificación técnica de la evaluación de la regla."
    )
    expected_value: Optional[str] = None
    remediation_cmd: Optional[str] = None


class AuditReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    execution_id: UUID = Field(..., alias="id")
    device_id: UUID
    profile_id: Optional[UUID] = None
    execution_type: ExecutionType
    score: float = Field(0.0, description="Porcentaje total de cumplimiento de la auditoría.")
    executed_at: datetime = Field(..., alias="created_at")

    passed_count: int = Field(..., alias="total_passed")
    failed_count: int = Field(..., alias="total_failed")
    not_applicable_count: int = Field(0, alias="total_not_applicable")
    total_rules_evaluated: int = 0

    findings: List[FindingResponse] = Field(default_factory=list, alias="findings_data")

    @model_validator(mode="after")
    def compute_total_rules(self) -> "AuditReportResponse":
        if self.total_rules_evaluated == 0:
            self.total_rules_evaluated = (
                self.passed_count + self.failed_count + self.not_applicable_count
            )
        return self