from abc import ABC, abstractmethod
from app.hardening.models import AuditReport


class BaseReportExporter(ABC):
    @abstractmethod
    def export(self, report: AuditReport) -> bytes:
        """Toma la entidad ORM del reporte y genera el contenido en bytes."""
        pass