"""
Interfaces y Contratos Abstractos para la Comunicación con Fortinet (Ports & Adapters).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from app.devices.schemas import ConnectivityCheckResult


class IDeviceProber(ABC):
    """Puerto específico para sondas de diagnóstico de red."""

    @abstractmethod
    async def probe(self, host: str, port: int, api_token: str) -> ConnectivityCheckResult:
        """Ejecuta una sonda L7 contra el hardware FortiOS."""
        pass


class BaseFortiConnector(ABC):
    """Contrato base de comunicación con el hardware."""

    @abstractmethod
    async def test_connectivity(self) -> ConnectivityCheckResult:
        """Verifica alcance HTTP/API y obtiene número de serie y versión."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Cierra sesiones HTTP / conexiones abiertas."""
        pass


class DeviceConnector(BaseFortiConnector):
    """Operaciones a nivel global de chasis / sistema (System Scope)."""

    @abstractmethod
    async def get_system_status(self) -> Dict[str, Any]:
        """Consulta /api/v2/monitor/system/status."""
        pass

    @abstractmethod
    async def list_vdoms(self) -> List[str]:
        """Consulta /api/v2/cmdb/system/vdom para listar nombres de VDOMs existentes."""
        pass

    @abstractmethod
    async def get_ha_status(self) -> Dict[str, Any]:
        """Consulta el estado del cluster High Availability."""
        pass


class VDOMConnector(BaseFortiConnector):
    """Operaciones acotadas a un VDOM específico (Tenant Scope)."""

    def __init__(self, vdom: str):
        self.vdom = vdom

    @abstractmethod
    async def get_firewall_policies(self) -> List[Dict[str, Any]]:
        """Extrae las reglas de firewall: /api/v2/cmdb/firewall/policy?vdom={vdom}."""
        pass

    @abstractmethod
    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """Extrae interfaces de red: /api/v2/cmdb/system/interface?vdom={vdom}."""
        pass

    @abstractmethod
    async def get_admin_settings(self) -> Dict[str, Any]:
        """Extrae configuraciones de acceso global/local del VDOM."""
        pass

    @abstractmethod
    async def get_ipsec_tunnels(self) -> List[Dict[str, Any]]:
        """Extrae configuraciones de túneles VPN: /api/v2/cmdb/vpn.ipsec/phase1-interface?vdom={vdom}."""
        pass