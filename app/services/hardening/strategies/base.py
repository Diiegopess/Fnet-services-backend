from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.services.hardening.models import FindingStatus, RuleSeverity


@dataclass
class RuleResult:
    """DTO que encapsula el resultado de la evaluación de una regla individual."""

    status: FindingStatus
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation_cmd: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class BaseRule(ABC):
    """Clase base abstracta (Patrón Strategy) que deben heredar todas las reglas."""

    # Atributos de metadatos que coinciden con RuleCatalog en BD
    rule_id: str  # Ej: 'CIS-1.1', 'FORTI-001'
    name: str
    description: str
    category: str  # Ej: 'System', 'Network', 'Admin'
    standard: str  # 'CIS', 'FORTINET', 'GAMMA'
    default_severity: RuleSeverity
    applicable_platforms: List[str] = ["fortigate"]  # Lista de plataformas compatibles (ej. ["fortigate", "fortianalyzer"])
    

    @abstractmethod
    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        """Método principal de evaluación.

        :param parsed_config: Configuración del FortiGate parseada como diccionario/árbol.
        :return: RuleResult indicando PASSED, FAILED, EXEMPT o NOT_APPLICABLE.
        """
        pass