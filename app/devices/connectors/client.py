# app/devices/connectors/client.py

import ssl
from typing import Any, Dict, Optional, Union
import httpx


class FortiOSHttpClient:
    """Cliente HTTP asíncrono para comunicarse con la REST API de FortiOS."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        verify_ssl: bool = False,
        timeout: float = 15.0,
    ):
        self.base_url = f"https://{host}:{port}/api/v2"
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _get_ssl_context(self) -> Union[ssl.SSLContext, bool]:
        """Genera un contexto SSL perdonable para renegociación TLS 1.3 / mTLS en FortiGate."""
        if not self.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return True

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _clean_bytes_error(self, content: bytes) -> str:
        """Decodifica el contenido en bytes a UTF-8 reemplazando caracteres inválidos."""
        if not content:
            return ""
        return content.decode("utf-8", errors="replace")

    def _safe_str(self, exc: Exception) -> str:
        """Convierte cualquier excepción a cadena de texto sin fallar por codificación ASCII."""
        try:
            msg = str(exc)
        except Exception:
            msg = repr(exc)
        return msg.encode("utf-8", errors="replace").decode("utf-8")

    async def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        skip_vdom: bool = False,
    ) -> Dict[str, Any]:
        """Realiza peticiones GET a la API de FortiOS."""
        url = (
            f"{self.base_url}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
        )
        req_params = dict(params or {})

        # Si se solicita omitir VDOM o la consulta es global
        if skip_vdom:
            req_params["global"] = 1

        ssl_verify = self._get_ssl_context()

        async with httpx.AsyncClient(
            verify=ssl_verify,
            http1=True,
            timeout=httpx.Timeout(self.timeout, connect=12.0),
        ) as client:
            try:
                response = await client.get(
                    url, headers=self._get_headers(), params=req_params
                )
                response.raise_for_status()

                response.encoding = "utf-8"
                return response.json()

            except httpx.HTTPStatusError as exc:
                error_msg = self._clean_bytes_error(exc.response.content)
                raise RuntimeError(
                    f"Error HTTP {exc.response.status_code} desde FortiGate: {error_msg}"
                ) from exc
            except httpx.RequestError as exc:
                err_text = self._safe_str(exc)
                raise RuntimeError(
                    f"Error de red con FortiGate ({url}): {err_text}"
                ) from exc
            except Exception as exc:
                err_text = self._safe_str(exc)
                raise RuntimeError(
                    f"Error inesperado al conectar con FortiGate ({url}): {err_text}"
                ) from exc

    async def post(
        self,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Realiza peticiones POST a la API de FortiOS."""
        url = (
            f"{self.base_url}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
        )
        req_params = dict(params or {})

        if "access_token" not in req_params:
            req_params["access_token"] = self.token

        ssl_verify = self._get_ssl_context()

        async with httpx.AsyncClient(
            verify=ssl_verify,
            http1=True,
            timeout=httpx.Timeout(self.timeout, connect=10.0),
        ) as client:
            try:
                response = await client.post(
                    url,
                    headers=self._get_headers(),
                    params=req_params,
                    json=json_data,
                )
                response.raise_for_status()
                response.encoding = "utf-8"
                return response.json()

            except httpx.HTTPStatusError as exc:
                error_msg = self._clean_bytes_error(exc.response.content)
                raise RuntimeError(
                    f"Error HTTP {exc.response.status_code} desde FortiGate: {error_msg}"
                ) from exc
            except httpx.RequestError as exc:
                err_text = self._safe_str(exc)
                raise RuntimeError(
                    f"Error de red con FortiGate ({url}): {err_text}"
                ) from exc
            except Exception as exc:
                err_text = self._safe_str(exc)
                raise RuntimeError(
                    f"Error inesperado al conectar con FortiGate ({url}): {err_text}"
                ) from exc