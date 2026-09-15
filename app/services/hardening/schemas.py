from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, computed_field

from app.services.hardening.models import (
    ExecutionType,
    FindingStatus,
    ProfileType,
    RuleSeverity,
)


# --- SCHEMAS DE REGLAS Y PERFILES ---

class RuleCatalogResponse(BaseModel):
    id: str  # Retorna 'CIS-1.1', 'FNT-1.1', etc.
    name: str
    description: Optional[str] = None
    category: str
    standard: str
    default_severity: RuleSeverity
    is_active: bool

    @computed_field
    @property
    def rule_id(self) -> str:
        """Alias computable para asegurar compatibilidad si el frontend busca 'rule_id'."""
        return self.id

    class Config:
        from_attributes = True


class HardeningProfileResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str] = None
    profile_type: ProfileType
    is_active: bool
    created_at: datetime
    rules: List[RuleCatalogResponse] = []

    class Config:
        from_attributes = True


# --- SCHEMAS DE EJECUCIÓN Y AUDITORÍA ---

class AuditExecutionRequest(BaseModel):
    device_id: UUID
    raw_config: str = Field(..., description="Configuración CLI en texto plano extraída de FortiOS")
    execution_type: ExecutionType
    profile_id: Optional[UUID] = None
    adhoc_rule_ids: Optional[List[str]] = None
    vdom_id: Optional[UUID] = None


class FindingResponse(BaseModel):
    id: UUID
    rule_id: str
    status: FindingStatus
    severity: RuleSeverity
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation_cmd: Optional[str] = None

    class Config:
        from_attributes = True


class AuditReportResponse(BaseModel):
    id: UUID
    device_id: UUID
    vdom_id: Optional[UUID] = None
    execution_type: ExecutionType
    profile_id: Optional[UUID] = None
    score: float
    total_passed: int
    total_failed: int
    total_not_applicable: int
    executed_at: datetime
    findings: List[FindingResponse] = []

    class Config:
        from_attributes = True