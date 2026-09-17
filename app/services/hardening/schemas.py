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


# --- SCHEMAS DE CATALOGO Y REGLAS ---

class RuleCatalogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: Optional[str] = None
    category: str
    standard: str
    default_severity: RuleSeverity
    is_active: bool


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
    raw_config: Optional[str] = Field(
        None, description="Configuración CLI en texto plano. Si se omite, se extrae en vivo."
    )


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    status: FindingStatus
    severity: RuleSeverity
    current_value: Optional[str] = None
    raw_evidence: Optional[str] = Field(
        None, description="Línea o bloque exacto de la configuración CLI analizado."
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
    executed_at: datetime = Field(..., alias="created_at")

    passed_count: int = Field(..., alias="total_passed")
    failed_count: int = Field(..., alias="total_failed")
    total_rules_evaluated: int = 0

    findings: List[FindingResponse] = Field(default_factory=list, alias="findings_data")

    @model_validator(mode="after")
    def compute_total_rules(self) -> "AuditReportResponse":
        """Calcula dinámicamente el total de reglas evaluadas si el atributo viene en 0."""
        if self.total_rules_evaluated == 0:
            self.total_rules_evaluated = self.passed_count + self.failed_count
        return self