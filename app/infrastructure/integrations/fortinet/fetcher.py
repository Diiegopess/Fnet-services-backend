# app/infrastructure/integrations/fortinet/fetcher.py

import json
from typing import Any, Dict, List, Optional, Union
import uuid

from app.infrastructure.integrations.fortinet.client import FortiOSRawHttpClient


class FortinetConfigFetcher:
    """Extractor desacoplado para FortiOS REST API compatible con permisos de solo lectura."""

    def __init__(self, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    async def fetch_endpoints_data(
        self,
        host: str,
        port: int,
        api_token: str,
        endpoints: List[str],
        vdom: Optional[Union[str, uuid.UUID]] = None,
    ) -> Dict[str, Any]:
        """Consulta una lista dinámica de endpoints REST y devuelve un mapa con sus respuestas JSON.
        
        Args:
            endpoints: Lista de rutas de la API, ej: ['api/v2/cmdb/system/global', 'api/v2/cmdb/log.disk/setting']
        Returns:
            Dict[str, Any]: Un diccionario donde la clave es el endpoint y el valor es la respuesta parseada.
        """
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

        # Mapeo: { "api/v2/cmdb/system/global": { "status": "success", "results": {...} } }
        retrieved_data: Dict[str, Any] = {}

        # Deduplicar la lista de endpoints requeridos
        unique_endpoints = list(set(endpoints))

        for endpoint in unique_endpoints:
            # Normalizar ruta eliminando la barra inicial si existe
            clean_endpoint = endpoint.lstrip("/")
            try:
                raw_json = await client.get_raw_text(endpoint=clean_endpoint, params=params)
                res_data = json.loads(raw_json)
                retrieved_data[clean_endpoint] = res_data
            except Exception as e:
                # Si un endpoint falla (ej. 404 por versión o licenciamiento), se inicializa vacío
                print(f"[FETCHER WARNING] Error al consultar endpoint '{clean_endpoint}': {e}")
                retrieved_data[clean_endpoint] = {}

        return retrieved_data