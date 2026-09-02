# app/devices/connectors/client.py

from typing import Any, Dict, Optional
import httpx


class FortiOSHttpClient:
    """Cliente HTTP asíncrono para comunicarse con la REST API de FortiOS."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        verify_ssl: bool = False,
        timeout: float = 10.0,
    ):
        self.base_url = f"https://{host}:{port}"
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/json",
                },
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        return self._client

    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        client = self._get_client()
        query_params = params or {}
        # Soportar token por URL en caso de que la versión no tome Bearer header
        if "access_token" not in query_params:
            query_params["access_token"] = self.token

        response = await client.get(endpoint, params=query_params)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()