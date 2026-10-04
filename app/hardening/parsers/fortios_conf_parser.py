import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BackupMetadata:
    model: str = "FortiGate"
    version: str = "7.4.x"
    build: Optional[str] = None
    vdom_enabled: bool = False


@dataclass
class ParsedBackupResult:
    metadata: BackupMetadata
    cmdb_dump: Dict[str, Any] = field(default_factory=dict)


class FortiOSConfParser:
    """Parsea el archivo .conf y arma la estructura raw_dump requerida por el motor."""

    def parse(self, raw_text: str) -> ParsedBackupResult:
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        metadata = self._extract_metadata(lines)

        cmdb_dump: Dict[str, Any] = {}

        # 1. Extraer 'config system global' -> api/v2/cmdb/system/global
        global_cfg = self._extract_flat_section(lines, "config system global")
        if global_cfg:
            cmdb_dump["api/v2/cmdb/system/global"] = {
                "http_method": "GET",
                "status": "success",
                "results": global_cfg,
            }

        # 2. Extraer 'config system interface' -> api/v2/cmdb/system/interface
        interfaces = self._extract_table_section(lines, "config system interface")
        if interfaces:
            cmdb_dump["api/v2/cmdb/system/interface"] = {
                "http_method": "GET",
                "status": "success",
                "results": interfaces,
            }

        # 3. Extraer 'config system accprofile' -> api/v2/cmdb/system/accprofile
        accprofiles = self._extract_table_section(lines, "config system accprofile")
        if accprofiles:
            cmdb_dump["api/v2/cmdb/system/accprofile"] = {
                "http_method": "GET",
                "status": "success",
                "results": accprofiles,
            }

        return ParsedBackupResult(metadata=metadata, cmdb_dump=cmdb_dump)

    def _extract_metadata(self, lines: List[str]) -> BackupMetadata:
        meta = BackupMetadata()
        for line in lines[:15]:
            if line.startswith("#config-version="):
                match = re.search(r"#config-version=([A-Za-z0-9_-]+)-(\d+\.\d+\.\d+)", line)
                if match:
                    meta.model = match.group(1)
                    meta.version = match.group(2)
                b_match = re.search(r"build(\d+)", line)
                if b_match:
                    meta.build = b_match.group(1)
                meta.vdom_enabled = "vdom=1" in line
                break
        return meta

    def _extract_flat_section(self, lines: List[str], section_header: str) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        inside = False
        for line in lines:
            if line == section_header:
                inside = True
                continue
            if inside:
                if line == "end":
                    break
                if line.startswith("set "):
                    parts = line.split(" ", 2)
                    if len(parts) >= 3:
                        key = parts[1].strip()
                        raw_val = parts[2].strip().strip('"').strip("'")
                        data[key] = int(raw_val) if raw_val.isdigit() else raw_val
        return data

    def _extract_table_section(self, lines: List[str], section_header: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        inside = False
        current_item: Optional[Dict[str, Any]] = None

        for line in lines:
            if line == section_header:
                inside = True
                continue
            if inside:
                if line == "end" and current_item is None:
                    break
                if line.startswith("edit "):
                    item_name = line[5:].strip().strip('"').strip("'")
                    current_item = {"name": item_name}
                elif line.startswith("set ") and current_item is not None:
                    parts = line.split(" ", 2)
                    if len(parts) >= 3:
                        key = parts[1].strip()
                        raw_val = parts[2].strip().strip('"').strip("'")
                        current_item[key] = int(raw_val) if raw_val.isdigit() else raw_val
                elif line == "next" and current_item is not None:
                    items.append(current_item)
                    current_item = None
        return items