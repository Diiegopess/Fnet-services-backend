# app/infrastructure/integrations/fortinet/fetcher.py

import json
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
    ) -> str:
        """Obtiene múltiples secciones del CMDB en JSON y las reconstruye en formato CLI Dump."""
        client = FortiOSRawHttpClient(
            host=host,
            port=port,
            token=api_token,
            verify_ssl=False,
            timeout=self.timeout_seconds,
        )

        vdom_str: Optional[str] = None
        if vdom is not None:
            vdom_str = str(vdom).strip()

        params: Dict[str, Any] = {"include_default": "1"}
        if vdom_str:
            params["vdom"] = vdom_str

        # Endpoints ampliados para cubrir el catálogo completo de Hardening/CIS
        endpoints = [
            ("system global", "/cmdb/system/global"),
            ("system admin", "/cmdb/system/admin"),
            ("system interface", "/cmdb/system/interface"),
            ("system accprofile", "/cmdb/system/accprofile"),
            ("system password-policy", "/cmdb/system/password-policy"),
            ("system dns", "/cmdb/system/dns"),
            ("system ntp", "/cmdb/system/ntp"),
            ("system central-management", "/cmdb/system/central-management"),
            ("log syslogd setting", "/cmdb/log.syslogd/setting"),
            ("user setting", "/cmdb/user/setting"),
        ]

        cli_blocks: List[str] = []

        for block_name, path in endpoints:
            try:
                raw_json = await client.get_raw_text(endpoint=path, params=params)
                res_data = json.loads(raw_json)
                data = res_data.get("results", {})

                cli_blocks.append(f"config {block_name}")

                if isinstance(data, dict):
                    for key, val in data.items():
                        if val is not None and val != "":
                            cli_blocks.append(f'    set {key} "{val}"')

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
                # Si un endpoint no existe en esa versión de FortiOS, continúa silenciosamente
                continue

        return "\n".join(cli_blocks)