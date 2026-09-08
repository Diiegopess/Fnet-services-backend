from typing import Any, Dict, List

from app.infrastructure.integrations.fortigate.base import DeviceConnector, VDOMConnector
from app.infrastructure.integrations.fortigate.client import FortiOSHttpClient
from app.devices.schemas import ConnectivityCheckResult


class FortiOSMockDeviceConnector(DeviceConnector):
    """Conector adaptado para interactuar con el micro-servidor de pruebas Mock."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8001, token: str = "test-token-123", **_kwargs):
        # El mock de desarrollo suele correr en HTTP/HTTPS local
        self.http = FortiOSHttpClient(host=host, port=port, token=token, verify_ssl=False)

    async def test_connectivity(self) -> ConnectivityCheckResult:
        try:
            status_data = await self.get_system_status()
            results = status_data.get("results", {})
            return ConnectivityCheckResult(
                is_reachable=True,
                status_code=200,
                version=results.get("version", "v7.2.4-mock"),
                serial=results.get("serial", "FG100E-MOCK-TEST"),
                message="Conexión exitosa contra el entorno Mock",
            )
        except Exception as e:
            return ConnectivityCheckResult(
                is_reachable=False, status_code=500, version=None, serial=None, message=f"Mock inalcanzable: {str(e)}"
            )

    async def get_system_status(self) -> Dict[str, Any]:
        return await self.http.get("/api/v2/monitor/system/status")

    async def list_vdoms(self) -> List[str]:
        data = await self.http.get("/api/v2/cmdb/system/vdom")
        results = data.get("results", [])
        return [item.get("name") for item in results if "name" in item]

    async def get_ha_status(self) -> Dict[str, Any]:
        return {
            "status": "success",
            "results": {"mode": "standalone", "group_name": "mock-ha-group"}
        }

    async def close(self) -> None:
        await self.http.close()


class FortiOSMockVDOMConnector(VDOMConnector):
    """Conector VDOM para entorno de pruebas/Mock."""

    def __init__(self, vdom: str, host: str = "127.0.0.1", port: int = 8001, token: str = "test-token-123", **_kwargs):
        super().__init__(vdom=vdom)
        self.http = FortiOSHttpClient(host=host, port=port, token=token, verify_ssl=False)

    async def test_connectivity(self) -> ConnectivityCheckResult:
        return ConnectivityCheckResult(
            is_reachable=True, status_code=200, version=None, serial=None, message=f"Mock VDOM {self.vdom} OK"
        )

    async def get_firewall_policies(self) -> List[Dict[str, Any]]:
        return [
            {"policyid": 1, "name": "Mock_Allow_Outbound", "srcintf": ["lan"], "dstintf": ["wan1"], "action": "accept"}
        ]

    async def get_interfaces(self) -> List[Dict[str, Any]]:
        return [
            {"name": "lan", "ip": "192.168.1.1 255.255.255.0", "vdom": self.vdom},
            {"name": "wan1", "ip": "203.0.113.1 255.255.255.252", "vdom": self.vdom},
        ]

    async def get_admin_settings(self) -> Dict[str, Any]:
        return {"vdom": self.vdom, "admin_port": 443, "ssh_port": 22}

    async def get_ipsec_tunnels(self) -> List[Dict[str, Any]]:
        return [{"name": "Mock_Tunnel_HQ", "interface": "wan1", "peertype": "any"}]

    async def close(self) -> None:
        await self.http.close()