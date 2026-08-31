"""
Adaptador de Red: Sonda HTTP para FortiOS con soporte para entornos reales y mocks.
"""

import time
import httpx

from app.devices.connectors.base import IDeviceProber
from app.devices.schemas import ConnectivityCheckResult


class FortiOSHttpProber(IDeviceProber):
    """Implementación concreta de la sonda utilizando HTTP REST contra FortiOS."""

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds

    async def _execute_probe(self, url: str, headers: dict) -> httpx.Response:
        async with httpx.AsyncClient(verify=False, timeout=self.timeout_seconds) as client:
            return await client.get(url, headers=headers)

    async def probe(self, host: str, port: int, api_token: str) -> ConnectivityCheckResult:
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }

        # Detección inteligente de esquema: http para mocks/hosts locales, https por defecto
        is_mock_or_local = (
            "mock" in host.lower()
            or host in ("127.0.0.1", "localhost", "testserver")
            or port in (80, 8080)
        )
        scheme = "http" if is_mock_or_local else "https"
        url = f"{scheme}://{host}:{port}/api/v2/monitor/system/status"

        start_time = time.perf_counter()
        try:
            response = await self._execute_probe(url, headers)
            latency = round((time.perf_counter() - start_time) * 1000, 2)

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", {})

                return ConnectivityCheckResult(
                    is_reachable=True,
                    status_code=response.status_code,
                    serial_number=results.get("serial"),
                    detected_version=results.get("version"),
                    vdom_mode=results.get("vdom_mode"),
                    latency_ms=latency,
                    error_message=None,
                )

            return ConnectivityCheckResult(
                is_reachable=False,
                status_code=response.status_code,
                latency_ms=latency,
                error_message=f"FortiOS respondió con status {response.status_code}: {response.text[:200]}",
            )

        except httpx.ConnectTimeout:
            return ConnectivityCheckResult(
                is_reachable=False,
                error_message=f"Timeout de conexión tras {self.timeout_seconds}s contra {host}:{port}",
            )
        except httpx.ConnectError as e:
            return ConnectivityCheckResult(
                is_reachable=False,
                error_message=f"Error de red inalcanzable ({host}:{port}): {str(e)}",
            )
        except Exception as e:
            return ConnectivityCheckResult(
                is_reachable=False,
                error_message=f"Fallo inesperado al sondear {host}:{port}: {str(e)}",
            )