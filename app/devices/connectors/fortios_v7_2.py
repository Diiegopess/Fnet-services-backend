# app/devices/connectors/fortios_v7_2.py

import httpx
from app.devices.connectors.base import DeviceConnector, VDOMConnector
from app.devices.connectors.client import FortiOSHttpClient
from app.devices.schemas import ConnectivityCheckResult


class FortiOSV72DeviceConnector(DeviceConnector):

    def __init__(
        self, host: str, port: int, token: str, verify_ssl: bool = False
    ):
        self.http = FortiOSHttpClient(
            host=host, port=port, token=token, verify_ssl=verify_ssl
        )

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
        except httpx.HTTPStatusError as e:
            return ConnectivityCheckResult(
                is_reachable=False,
                status_code=e.response.status_code,
                version=None,
                serial=None,
                message=f"Error de API ({e.response.status_code}): Token o permisos inválidos",
            )
        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            return ConnectivityCheckResult(
                is_reachable=False,
                status_code=504,
                version=None,
                serial=None,
                message=f"Timeout/Error de conexión contra el puerto del dispositivo",
            )
        except Exception as e:
            return ConnectivityCheckResult(
                is_reachable=False,
                status_code=500,
                version=None,
                serial=None,
                message=f"Error inesperado: {str(e)}",
            )
        finally:
            # Asegurar cierre del socket al finalizar el test
            await self.close()