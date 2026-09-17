# app/infrastructure/integrations/fortinet/fetcher.py

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.infrastructure.integrations.fortinet.client import FortiOSRawHttpClient


class FortinetConfigFetcher:
    """Extractor desacoplado compatible con permisos de solo lectura (super_admin_readonly)."""

    def __init__(self, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    async def fetch_cli_dump(
        self,
        host: str,
        port: int,
        api_token: str,
        vdom: Optional[Union[str, uuid.UUID]] = None,
        platform: str = "fortigate",
    ) -> str:
        """Obtiene múltiples secciones del CMDB en JSON y las reconstruye en formato CLI Dump."""
        client = FortiOSRawHttpClient(
            host=host,
            port=port,
            token=api_token,
            verify_ssl=False,
            timeout=self.timeout_seconds,
        )

        vdom_str = str(vdom).strip() if vdom else None
        params: Dict[str, Any] = {"include_default": "1"}
        if vdom_str:
            params["vdom"] = vdom_str

        # Cargar los endpoints desde la carpeta definitions/ (fallback a default)
        def_path = Path(__file__).parent / "definitions" / f"{platform}_default.json"
        raw_defs = json.loads(def_path.read_text(encoding="utf-8")) if def_path.exists() else {"endpoints": []}
        endpoints = [(item["block_name"], item["path"]) for item in raw_defs.get("endpoints", [])]

        cli_blocks: List[str] = []

        for block_name, path in endpoints:
            try:
                raw_json = await client.get_raw_text(endpoint=path, params=params)
                res_data = json.loads(raw_json)
                data = res_data.get("results", {})

                cli_blocks.append(f"config {block_name}")

                # Si es un objeto único (ej. config system global)
                if isinstance(data, dict):
                    for key, val in data.items():
                        if val is not None and val != "":
                            cli_blocks.append(f'    set {key} "{val}"')

                # Si es una lista de objetos (ej. interfaces, administradores)
                elif isinstance(data, list):
                    for item in data:
                        entry_id = item.get("name") or item.get("id") or item.get("mkey", "")
                        if entry_id:
                            cli_blocks.append(f'    edit "{entry_id}"')
                            for k, v in item.items():
                                if v is not None and v != "" and k not in ("name", "id"):
                                    cli_blocks.append(f'        set {k} "{v}"')
                            cli_blocks.append("    next")

                cli_blocks.append("end")
            except Exception as e:
                print(f"DEBUG FETCHER WARNING (Endpoint {block_name}): {e}")
                continue

        return "\n".join(cli_blocks)