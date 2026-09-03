"""Adaptador de Red: Sonda HTTP para FortiOS con soporte para entornos reales y mocks."""

import ssl
import time
import httpx

from app.devices.connectors.base import IDeviceProber
from app.devices.schemas import ConnectivityCheckResult


class FortiOSHttpProber(IDeviceProber):
    """Implementación concreta de la sonda utilizando HTTP REST contra FortiOS."""

    def __init__(self, timeout_seconds: float = 15.0):
        self.timeout_seconds = timeout_seconds

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Crea un contexto SSL permisivo que tolera la renegociación mTLS del FortiGate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _clean_error_message(self, text: str | bytes | Exception) -> str:
        """Sanitiza mensajes de error y respuestas para evitar UnicodeDecodeError/ASCII crashes."""
        if isinstance(text, bytes):
            return text.decode("utf-8", errors="replace")
        
        if isinstance(text, Exception):
            try:
                text_str = str(text)
            except Exception:
                text_str = repr(text)
        else:
            text_str = str(text) if text is not None else ""

        return (
            text_str.encode("utf-8", errors="replace").decode("utf-8")
            if text_str
            else "Error desconocido"
        )

    async def _execute_probe(self, url: str, headers: dict, params: dict) -> httpx.Response:
        ssl_ctx = self._get_ssl_context()
        # Forzamos http1=True para evitar cierres de socket por negociación HTTP/2 en FortiOS.
        async with httpx.AsyncClient(
            verify=ssl_ctx,
            http1=True,
            timeout=httpx.Timeout(self.timeout_seconds, connect=12.0),
        ) as client:
            return await client.get(url, headers=headers, params=params)

    async def probe(
        self, host: str, port: int, api_token: str
    ) -> ConnectivityCheckResult:
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

        # IMPORTANTE: Se añade 'global': 1 para evitar que FortiOS cuelgue la petición si hay VDOMs
        params = {} if is_mock_or_local else {"global": 1}

        start_time = time.perf_counter()
        try:
            response = await self._execute_probe(url, headers, params)
            latency = round((time.perf_counter() - start_time) * 1000, 2)

            # Forzar decodificación UTF-8 explícita en la respuesta
            response.encoding = "utf-8"

            if response.status_code == 200:
                data = response.json()
                
                # Manejar respuestas con formato 'results' (estándar) o plana
                results = data.get("results", data) if isinstance(data, dict) else {}

                return ConnectivityCheckResult(
                    is_reachable=True,
                    status_code=response.status_code,
                    serial_number=results.get("serial"),
                    detected_version=results.get("version"),
                    vdom_mode=results.get("vdom_mode"),
                    latency_ms=latency,
                    error_message=None,
                )

            # Sanitización del cuerpo de la respuesta en caso de error HTTP
            body_preview = self._clean_error_message(response.content[:200])
            return ConnectivityCheckResult(
                is_reachable=False,
                status_code=response.status_code,
                latency_ms=latency,
                error_message=f"FortiOS respondió con status {response.status_code}: {body_preview}",
            )

        except httpx.ConnectTimeout:
            return ConnectivityCheckResult(
                is_reachable=False,
                error_message=f"Timeout de conexión tras {self.timeout_seconds}s contra {host}:{port}",
            )
        except httpx.ConnectError as e:
            clean_err = self._clean_error_message(e)
            return ConnectivityCheckResult(
                is_reachable=False,
                error_message=f"Error de red inalcanzable ({host}:{port}): {clean_err}",
            )
        except Exception as e:
            clean_err = self._clean_error_message(e)
            return ConnectivityCheckResult(
                is_reachable=False,
                error_message=f"Fallo inesperado al sondear {host}:{port}: {clean_err}",
            )