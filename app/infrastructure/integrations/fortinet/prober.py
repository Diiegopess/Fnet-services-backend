# app/infrastructure/integrations/fortinet/prober.py

import time
import httpx
from app.infrastructure.integrations.fortinet.schemas import FortiGateConnectivityResult


class FortinetProber:
    """Sonda rápida de diagnóstico autosuficiente."""

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    async def probe(
        self, host: str, port: int, api_token: str
    ) -> FortiGateConnectivityResult:
        is_local = "mock" in host.lower() or host in ("127.0.0.1", "localhost", "testserver")
        scheme = "http" if is_local and port != 12443 else "https"
        url = f"{scheme}://{host}:{port}/api/v2/monitor/system/status"

        headers = {"Authorization": f"Bearer {api_token}"}
        
        # Inclusión de access_token para compatibilidad total con FortiOS
        params = {"access_token": api_token}
        if not is_local:
            params["global"] = 1

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                verify=False,
                http1=True,
                timeout=httpx.Timeout(self.timeout_seconds),
            ) as client:
                res = await client.get(url, headers=headers, params=params)
                latency = round((time.perf_counter() - start) * 1000, 2)

                if res.status_code == 200:
                    data = res.json().get("results", {}) if isinstance(res.json(), dict) else {}
                    return FortiGateConnectivityResult(
                        is_reachable=True,
                        status_code=200,
                        serial_number=data.get("serial", "Unknown"),
                        detected_version=data.get("version", "v7.2.x"),
                        latency_ms=latency,
                    )
                return FortiGateConnectivityResult(
                    is_reachable=False,
                    status_code=res.status_code,
                    latency_ms=latency,
                    error_message=f"HTTP Status {res.status_code}",
                )
        except Exception as e:
            return FortiGateConnectivityResult(
                is_reachable=False,
                status_code=500,
                error_message=str(e),
            )