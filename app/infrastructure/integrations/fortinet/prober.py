# app/infrastructure/integrations/fortinet/prober.py

import time
from typing import Any, Dict
import httpx
from app.infrastructure.integrations.fortinet.schemas import FortiGateConnectivityResult


class FortinetProber:
    """Sonda rápida de diagnóstico y detección topológica de FortiOS."""

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    async def probe(
        self, host: str, port: int, api_token: str
    ) -> FortiGateConnectivityResult:
        is_local = "mock" in host.lower() or host in ("127.0.0.1", "localhost", "testserver")
        scheme = "http" if is_local and port != 12443 else "https"
        base_url = f"{scheme}://{host}:{port}/api/v2"

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }
        params: Dict[str, Any] = {"access_token": api_token}

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                verify=False,
                http1=True,
                timeout=httpx.Timeout(self.timeout_seconds),
            ) as client:
                # 1. Consulta de estado y versión
                status_url = f"{base_url}/monitor/system/status"
                res = await client.get(status_url, headers=headers, params=params)
                latency = round((time.perf_counter() - start) * 1000, 2)

                if res.status_code == 200:
                    raw_body = res.json() if isinstance(res.json(), dict) else {}
                    results = raw_body.get("results", {}) if isinstance(raw_body.get("results"), dict) else raw_body

                    # Serial y versión (pueden venir en la raíz o en results según el firmware)
                    serial = (
                        results.get("serial")
                        or raw_body.get("serial")
                        or results.get("serial_number")
                        or "Unknown"
                    )

                    version = (
                        results.get("version")
                        or raw_body.get("version")
                        or "v7.2.x"
                    )

                    # 2. Detección por endpoint CMDB de VDOMs
                    is_multi_vdom = False
                    try:
                        vdom_cmdb_url = f"{base_url}/cmdb/system/vdom"
                        vdom_res = await client.get(vdom_cmdb_url, headers=headers, params=params)
                        if vdom_res.status_code == 200:
                            vdom_data = vdom_res.json().get("results", [])
                            # Si responde 200 y serializa lista de VDOMs, el chasis está particionado
                            if isinstance(vdom_data, list) and len(vdom_data) > 0:
                                is_multi_vdom = True
                                # Extraer serial de cabecera de la CMDB si vino omitido en status
                                if serial == "Unknown" and vdom_res.json().get("serial"):
                                    serial = vdom_res.json()["serial"]
                    except Exception:
                        is_multi_vdom = False

                    return FortiGateConnectivityResult(
                        is_reachable=True,
                        status_code=200,
                        serial_number=serial,
                        detected_version=version,
                        vdom_mode="multi-vdom" if is_multi_vdom else "standalone",
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