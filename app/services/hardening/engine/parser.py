import re
from typing import Any, Dict


class FortiOSParser:
    """Parser para transformar configuraciones CLI/JSON de FortiOS en diccionarios naveagables."""

    @staticmethod
    def parse_cli(raw_config: str) -> Dict[str, Any]:
        """Convierte una configuración en formato CLI de FortiOS (bloques config ... end) a un diccionario Python.

        Ejemplo de entrada:
            config system global
                set admintimeout 15
                set hostname "FG-CORE"
            end

        Retorna:
            {
                "config system global": {
                    "admintimeout": "15",
                    "hostname": "FG-CORE"
                }
            }
        """
        parsed: Dict[str, Any] = {}
        current_block: str | None = None

        for line in raw_config.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            # Detectar inicio de bloque (ej: "config system global")
            if line.startswith("config "):
                current_block = line
                if current_block not in parsed:
                    parsed[current_block] = {}
                continue

            # Detectar fin de bloque
            if line == "end" or line == "next":
                if line == "end":
                    current_block = None
                continue

            # Parsear asignaciones "set key value"
            if current_block and line.startswith("set "):
                match = re.match(r"^set\s+([^\s]+)\s+(.+)$", line)
                if match:
                    key, val = match.groups()
                    # Limpiar comillas si las hay
                    val = val.strip('"\'')
                    parsed[current_block][key] = val

        return parsed