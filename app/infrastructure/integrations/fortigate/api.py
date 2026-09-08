# app/integrations/fortigate/api.py

from typing import Any, Dict, List

# Importación del módulo superior (padre: app/integrations)
from app.infrastructure.integrations.factory import FortiConnectorFactory

# Importaciones relativas dentro del mismo paquete (app/integrations/fortigate)
from .prober import FortiOSHttpProber
from .schemas import FortiGateConnectivityResult


class FortiGateAPI:
    """Sub-fachada exclusiva para operaciones con FortiGate / FortiOS."""

    def __init__(self):
        self._factory = FortiConnectorFactory()
        self._prober = FortiOSHttpProber()

    async def probe(
        self, host: str, port: int, api_token: str
    ) -> FortiGateConnectivityResult:
        """Diagnóstico L7 rápido para validar conexión y extraer versión/serie."""
        return await self._prober.probe(host=host, port=port, api_token=api_token)

    async def get_system_status(
        self, host: str, port: int, api_token: str, version: str = "7.2"
    ) -> Dict[str, Any]:
        """Obtiene el estado general del chasis según la versión configurada."""
        connector = self._factory.get_device_connector(
            host=host, port=port, api_token=api_token, version=version
        )
        try:
            return await connector.get_system_status()
        finally:
            await connector.close()

    async def get_firewall_policies(
        self, host: str, port: int, api_token: str, vdom_name: str, version: str = "7.2"
    ) -> List[Dict[str, Any]]:
        """Extrae la tabla de políticas de firewall para un VDOM específico."""
        connector = self._factory.get_vdom_connector(
            host=host, port=port, api_token=api_token, vdom_name=vdom_name, version=version
        )
        try:
            return await connector.get_firewall_policies()
        finally:
            await connector.close()