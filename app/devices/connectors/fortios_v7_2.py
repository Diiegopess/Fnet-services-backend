# app/devices/connectors/fortios_v7_2.py

from typing import Any, Dict, List
from app.devices.connectors.base import DeviceConnector, VDOMConnector
from app.devices.connectors.client import FortiOSHttpClient
from app.devices.schemas import ConnectivityCheckResult


class FortiOSV72DeviceConnector(DeviceConnector):
    def __init__(self, host: str, port: int, token: str, verify_ssl: bool = False):
        self.http = FortiOSHttpClient(host=host, port=port, token=token, verify_ssl=verify_ssl)

    async def test_connectivity(self) -> ConnectivityCheckResult:
        try:
            status_data = await self.get_system_status()
            results = status_data.get("results", {})
            return ConnectivityCheckResult(
                is_reachable=True,
                status_code=200,
                version=results.get("version", "v7.2.x"),
                serial=results.get("serial", "Unknown"),
                message="Conexión exitosa contra FortiOS 7.2",
            )
        except Exception as e:
            return ConnectivityCheckResult(
                is_reachable=False, status_code=500, version=None, serial=None, message=str(e)
            )

    async def get_system_status(self) -> Dict[str, Any]:
        return await self.http.get("/api/v2/monitor/system/status")

    async def list_vdoms(self) -> List[str]:
        data = await self.http.get("/api/v2/cmdb/system/vdom")
        results = data.get("results", [])
        return [item.get("name") for item in results if "name" in item]

    async def get_ha_status(self) -> Dict[str, Any]:
        return await self.http.get("/api/v2/monitor/system/ha-peer")

    async def close(self) -> None:
        await self.http.close()


class FortiOSV72VDOMConnector(VDOMConnector):
    def __init__(self, host: str, port: int, token: str, vdom: str, verify_ssl: bool = False):
        super().__init__(vdom=vdom)
        self.http = FortiOSHttpClient(host=host, port=port, token=token, verify_ssl=verify_ssl)

    async def test_connectivity(self) -> ConnectivityCheckResult:
        try:
            await self.get_firewall_policies()
            return ConnectivityCheckResult(
                is_reachable=True, status_code=200, version=None, serial=None, message=f"VDOM {self.vdom} OK"
            )
        except Exception as e:
            return ConnectivityCheckResult(
                is_reachable=False, status_code=500, version=None, serial=None, message=str(e)
            )

    async def get_firewall_policies(self) -> List[Dict[str, Any]]:
        data = await self.http.get("/api/v2/cmdb/firewall/policy", params={"vdom": self.vdom})
        return data.get("results", [])

    async def get_interfaces(self) -> List[Dict[str, Any]]:
        data = await self.http.get("/api/v2/cmdb/system/interface", params={"vdom": self.vdom})
        return data.get("results", [])

    async def get_admin_settings(self) -> Dict[str, Any]:
        return await self.http.get("/api/v2/cmdb/system/admin", params={"vdom": self.vdom})

    async def get_ipsec_tunnels(self) -> List[Dict[str, Any]]:
        data = await self.http.get("/api/v2/cmdb/vpn.ipsec/phase1-interface", params={"vdom": self.vdom})
        return data.get("results", [])

    async def close(self) -> None:
        await self.http.close()