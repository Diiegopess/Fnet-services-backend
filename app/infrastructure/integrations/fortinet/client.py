import ssl
from typing import Any, Dict, Optional, Union
import httpx

from app.infrastructure.integrations.exceptions import IntegrationConnectionError, IntegrationHTTPError


class FortiOSRawHttpClient:
    """Cliente HTTP asíncrono optimizado para respaldos CLI y consultas de estado."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        is_local = "mock" in host.lower() or host in ("127.0.0.1", "localhost", "testserver")
        scheme = "http" if is_local else "https"
        self.base_url = f"{scheme}://{host}:{port}/api/v2"

    def _get_ssl_context(self) -> Union[ssl.SSLContext, bool]:
        if not self.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return True

    def _get_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def _safe_str(self, exc: Exception) -> str:
        try:
            msg = str(exc)
        except Exception:
            msg = repr(exc)
        return msg.encode("utf-8", errors="replace").decode("utf-8")

    async def get_raw_text(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> str:
        """Obtiene la respuesta HTTP directamente como Texto Plano (ideal para dumps de config)."""
        url = f"{self.base_url}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
        ssl_verify = self._get_ssl_context()

        async with httpx.AsyncClient(
            verify=ssl_verify,
            http1=True,
            timeout=httpx.Timeout(self.timeout, connect=12.0),
        ) as client:
            try:
                response = await client.get(
                    url, headers=self._get_headers(), params=params or {}
                )
                response.raise_for_status()
                response.encoding = "utf-8"
                return response.text
            except httpx.HTTPStatusError as exc:
                err_body = exc.response.content.decode("utf-8", errors="replace")
                raise IntegrationHTTPError(exc.response.status_code, err_body) from exc
            except (httpx.RequestError, Exception) as exc:
                raise IntegrationConnectionError(
                    f"Error de red descargando configuración ({url}): {self._safe_str(exc)}"
                ) from exc