# app/services/hardening/engine/parser.py

import json
import re
from typing import Any, Dict


class FortiOSParser:
    """Parser adaptativo para transformar configuraciones de FortiOS (CLI o JSON REST API) en estructuras jerárquicas."""

    @staticmethod
    def parse_cli(raw_config: str) -> Dict[str, Any]:
        """Convierte dumps CLI o respuestas JSON de FortiOS en un diccionario estandarizado."""
        if not raw_config or not raw_config.strip():
            return {}

        # 1. Intentar parsear como respuesta JSON (proveniente de FortiOS REST API CMDB)
        try:
            json_data = json.loads(raw_config)
            if isinstance(json_data, dict):
                results = json_data.get("results", json_data)
                
                # Si 'results' es una lista de ítems (ej. config firewall policy)
                if isinstance(results, list):
                    table_dict = {}
                    for item in results:
                        name_key = item.get("name") or item.get("q_origin_key") or str(item.get("policyid", ""))
                        if name_key:
                            table_dict[str(name_key)] = item
                    return {"config system global": table_dict}

                # Si 'results' es un diccionario (ej. config system global)
                if isinstance(results, dict):
                    return {"config system global": results}
        except (json.JSONDecodeError, TypeError):
            pass  # No es JSON válido, se procesa como CLI Dump texto plano

        # 2. Parseo de CLI Dump texto plano tradicional
        parsed: Dict[str, Any] = {}
        current_config: str | None = None
        current_edit: str | None = None

        for line in raw_config.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            # Inicio de bloque 'config ...'
            if line.startswith("config "):
                current_config = line
                if current_config not in parsed:
                    parsed[current_config] = {}
                current_edit = None
                continue

            # Inicio de sub-item 'edit ...'
            if current_config and line.startswith("edit "):
                match = re.match(r"^edit\s+(.+)$", line)
                if match:
                    current_edit = match.group(1).strip('"\'')
                    if current_edit not in parsed[current_config]:
                        parsed[current_config][current_edit] = {}
                continue

            # Fin de sub-item 'next'
            if line == "next":
                current_edit = None
                continue

            # Fin de bloque 'end'
            if line == "end":
                current_config = None
                current_edit = None
                continue

            # Parámetros 'set key value'
            if current_config and line.startswith("set "):
                match = re.match(r"^set\s+([^\s]+)\s+(.+)$", line)
                if match:
                    key, val = match.groups()
                    val = val.strip('"\'')

                    if current_edit:
                        parsed[current_config][current_edit][key] = val
                    else:
                        parsed[current_config][key] = val

        return parsed