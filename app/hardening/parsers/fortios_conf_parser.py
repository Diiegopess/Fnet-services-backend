import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BackupMetadata:
    """Información extraída de la cabecera del archivo de backup."""
    raw_header: Optional[str] = None
    model: Optional[str] = None
    version: Optional[str] = None
    build: Optional[str] = None
    opmode: Optional[str] = None
    vdom_enabled: bool = False


@dataclass
class ParsedBackupResult:
    """Resultado del parseo: metadatos informativos + dump compatible con el engine."""
    metadata: BackupMetadata
    cmdb_dump: Dict[str, Any] = field(default_factory=dict)


class FortiOSConfParser:
    """
    Parsea backups de FortiOS (.conf) de forma agnóstica de versión
    y genera la estructura compatible con DeclarativeRuleEngine.
    """

    # Mapea las rutas CLI a los endpoints CMDB que evalúan tus benchmarks
    CLI_TO_CMDB_MAP = {
        ("system", "dns"): "api/v2/cmdb/system/dns",
        ("system", "zone"): "api/v2/cmdb/system/zone",
        ("system", "global"): "api/v2/cmdb/system/global",
        ("system", "interface"): "api/v2/cmdb/system/interface",
        ("system", "admin", "setting"): "api/v2/cmdb/system.admin/setting",
        ("firewall", "policy"): "api/v2/cmdb/firewall/policy",
        ("firewall", "address"): "api/v2/cmdb/firewall/address",
        ("log", "syslogd", "setting"): "api/v2/cmdb/log.syslogd/setting",
        ("log", "fortianalyzer", "setting"): "api/v2/cmdb/log.fortianalyzer/setting",
    }

    def parse(self, raw_text: str) -> ParsedBackupResult:
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        
        # 1. Extraer metadatos de la cabecera (#config-version=...)
        metadata = self._extract_header_metadata(lines)

        # 2. Filtrar comentarios
        config_lines = [line for line in lines if not line.startswith("#")]

        # 3. Construir árbol jerárquico CLI
        parsed_tree: Dict[str, Any] = {}
        self._parse_block(config_lines, 0, parsed_tree)

        # 4. Normalizar al dump que espera el DeclarativeRuleEngine
        cmdb_dump = self._normalize_to_cmdb_dump(parsed_tree)

        return ParsedBackupResult(metadata=metadata, cmdb_dump=cmdb_dump)

    def _extract_header_metadata(self, lines: List[str]) -> BackupMetadata:
        metadata = BackupMetadata()
        for line in lines[:10]:
            if line.startswith("#config-version="):
                metadata.raw_header = line
                # Formato típico: #config-version=FG100E-7.4.1-FW-build2463:opmode=0:vdom=0:user=admin
                clean = line.replace("#config-version=", "")
                parts = clean.split(":")
                fw_info = parts[0] if len(parts) > 0 else ""

                # Extraer modelo y versión
                fw_match = re.match(r"([A-Za-z0-9_-]+?)-(\d+\.\d+\.\d+)-FW-build(\d+)", fw_info)
                if fw_match:
                    metadata.model = fw_match.group(1)
                    metadata.version = fw_match.group(2)
                    metadata.build = fw_match.group(3)
                else:
                    metadata.version = fw_info

                for segment in parts[1:]:
                    if segment.startswith("vdom="):
                        metadata.vdom_enabled = segment.split("=")[1].strip() != "0"
                    elif segment.startswith("opmode="):
                        metadata.opmode = segment.split("=")[1].strip()
                break
        return metadata

    def _parse_block(self, lines: List[str], index: int, current_scope: Dict[str, Any]) -> int:
        while index < len(lines):
            line = lines[index]

            if line.startswith("config "):
                section_name = line.split(" ", 1)[1].strip()
                new_scope: Dict[str, Any] = {}
                index = self._parse_block(lines, index + 1, new_scope)
                current_scope[section_name] = new_scope

            elif line.startswith("edit "):
                # Instancia de una colección (ej: edit "port1")
                edit_id = line.split(" ", 1)[1].strip().strip('"')
                item_scope: Dict[str, Any] = {"name": edit_id}
                index = self._parse_block(lines, index + 1, item_scope)
                current_scope[edit_id] = item_scope

            elif line.startswith("set "):
                parts = line.split(" ", 2)
                if len(parts) >= 3:
                    key = parts[1]
                    raw_val = parts[2].strip()

                    # Tokenizar respetando comillas
                    values = [
                        v.strip().strip('"')
                        for v in re.findall(r'(?:[^\s"]+|"[^"]*")+|(?:"[^"]*"|[^\s"]+)', raw_val)
                    ]
                    current_scope[key] = values[0] if len(values) == 1 else values
                index += 1

            elif line in ("end", "next"):
                return index + 1
            else:
                index += 1

        return index

    def _normalize_to_cmdb_dump(self, parsed_tree: Dict[str, Any]) -> Dict[str, Any]:
        cmdb_dump: Dict[str, Any] = {}

        for cli_path, endpoint in self.CLI_TO_CMDB_MAP.items():
            curr = parsed_tree
            found = True
            for part in cli_path:
                if isinstance(curr, dict) and part in curr:
                    curr = curr[part]
                else:
                    found = False
                    break

            if found and isinstance(curr, dict):
                # Determinar si es una lista o un registro único
                sample_child = next(iter(curr.values()), None)
                if isinstance(sample_child, dict) and "name" in sample_child:
                    cmdb_dump[endpoint] = {"results": list(curr.values())}
                else:
                    cmdb_dump[endpoint] = {"results": curr}

        return cmdb_dump