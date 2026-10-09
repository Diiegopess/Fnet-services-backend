# app/infrastructure/integrations/fortinet/fetcher.py

import json
import logging
from typing import Any, Dict, List, Optional, Union
import uuid

from app.infrastructure.integrations.fortinet.client import FortiOSRawHttpClient

logger = logging.getLogger(__name__)


class FortinetConfigFetcher:
    """Extractor agnóstico y desacoplado para consultas CMDB/REST en FortiOS."""

    def __init__(self, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    async def fetch_endpoints_data(
        self,
        host: str,
        port: int,
        api_token: str,
        endpoint_targets: Optional[Dict[str, Optional[str]]] = None,
        endpoints: Optional[List[str]] = None,
        default_vdom: Optional[Union[str, uuid.UUID]] = None,
    ) -> Dict[str, Any]:
        """
        Consulta endpoints REST de manera individual respetando el contexto VDOM asignado a cada uno.

        Args:
            host: IP o dominio del dispositivo.
            port: Puerto HTTPS de administración.
            api_token: Token de la API descifrado.
            endpoint_targets: Diccionario mapeando {endpoint: target_vdom}.
                              Ej: {'api/v2/cmdb/system/global': 'global', 'api/v2/cmdb/firewall/policy': 'CONTABLE'}
            endpoints: (Opcional por retrocompatibilidad) Lista simple de endpoints.
            default_vdom: (Opcional) VDOM por defecto si se usa la lista de endpoints simple.

        Returns:
            Dict[str, Any]: Diccionario {endpoint: parsed_json_response}.
        """
        client = FortiOSRawHttpClient(
            host=host,
            port=port,
            token=api_token,
            verify_ssl=False,
            timeout=self.timeout_seconds,
        )

        # 1. Normalizar el mapa de trabajo {endpoint: vdom_name}
        resolved_targets: Dict[str, Optional[str]] = {}

        if endpoint_targets:
            for ep, vdom_val in endpoint_targets.items():
                resolved_targets[ep.lstrip("/")] = str(vdom_val).strip() if vdom_val else None

        if endpoints:
            fallback_vdom = str(default_vdom).strip() if default_vdom else None
            for ep in endpoints:
                clean_ep = ep.lstrip("/")
                if clean_ep not in resolved_targets:
                    resolved_targets[clean_ep] = fallback_vdom

        retrieved_data: Dict[str, Any] = {}

        # 2. Ejecutar cada consulta de forma agnóstica
        for clean_endpoint, target_vdom in resolved_targets.items():
            params: Dict[str, Any] = {"include_default": "1"}
            if target_vdom:
                params["vdom"] = target_vdom

            try:
                raw_json = await client.get_raw_text(endpoint=clean_endpoint, params=params)
                res_data = json.loads(raw_json)
                retrieved_data[clean_endpoint] = res_data
            except Exception as e:
                logger.warning(
                    f"[FETCHER WARNING] Error consultando endpoint '{clean_endpoint}' "
                    f"en vdom='{target_vdom}': {e}"
                )
                retrieved_data[clean_endpoint] = {}

        return retrieved_data