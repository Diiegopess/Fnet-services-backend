"""
Micro-servidor Mock para emular la API REST de FortiOS.
Utilizado exclusivamente para tests de integración y entorno de desarrollo local.
"""

from typing import Optional, Dict, Any
from fastapi import FastAPI, Header, HTTPException, Query, status

app = FastAPI(title="FortiOS Mock API", version="7.2.4")

VALID_TOKENS = {
    "test-token-123",
    "fortigate-secret-token",
    "valid-token",
    "token-fgt-60f",
    "token-fgt-100e",
    "token-fgt-200f",
}

# Catálogo de FortiGates Mock preconfigurados
MOCK_DEVICES: Dict[str, Dict[str, Any]] = {
    "test": {
        "hostname": "FW-Mock-Test",
        "serial": "FG100E-MOCK-TEST",  # Coincide exactamente con el test de integración
        "version": "v7.2.4",
        "build": 1396,
        "mode": "standalone",
        "vdoms": ["root"],
    },
    "fgt-60f-hq": {
        "hostname": "FW-HQ-60F",
        "serial": "FGT60FTK21001234",
        "version": "v7.2.5",
        "build": 1512,
        "mode": "standalone",
        "vdoms": ["root"],
    },
    "fgt-100e-corp": {
        "hostname": "FW-CORP-100E",
        "serial": "FG100ETK19005678",
        "version": "v7.2.4",
        "build": 1396,
        "mode": "vdom",
        "vdoms": ["root", "CLIENT-CORP-A", "CLIENT-GUEST-B", "DMZ-SERVICES"],
    },
    "fgt-200f-dc": {
        "hostname": "FW-DATACENTER-200F",
        "serial": "FG200FTK22009999",
        "version": "v7.4.1",
        "build": 2460,
        "mode": "vdom",
        "vdoms": ["root", "PROD-PAYMENTS", "STAGING", "INTERNAL-LAN"],
    },
}


def _validate_token(authorization: Optional[str], access_token: Optional[str]) -> None:
    """Valida el token tanto por Header Bearer como por Query Param ?access_token="""
    token = None

    if access_token:
        token = access_token.strip()
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "").strip()

    if not token or (token not in VALID_TOKENS and not token.startswith("valid") and not token.startswith("test")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid FortiOS REST API token",
        )


def _resolve_device(
    device_id: Optional[str],
    mode: Optional[str],
    x_mock_mode: Optional[str],
    x_device_id: Optional[str],
) -> Dict[str, Any]:
    """Resuelve qué perfil de FortiGate devolver según los parámetros de la solicitud."""
    # 1. Si se especificó un ID de dispositivo conocido
    target_id = (device_id or x_device_id or "").lower()
    if target_id in MOCK_DEVICES:
        return MOCK_DEVICES[target_id]

    # 2. Si viene parametrizado modo vdom o standalone
    is_vdom = (mode == "vdom") or (x_mock_mode == "vdom")
    if is_vdom:
        return MOCK_DEVICES["fgt-100e-corp"]

    # 3. Dispositivo por defecto para los tests de pytest
    return MOCK_DEVICES["test"]


@app.get("/api/v2/monitor/system/status")
async def get_system_status(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    x_mock_mode: Optional[str] = Header(None, alias="X-Mock-Mode"),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
):
    _validate_token(authorization, access_token)
    device = _resolve_device(device_id, mode, x_mock_mode, x_device_id)

    return {
        "http_method": "GET",
        "status": "success",
        "version": device["version"],
        "build": device["build"],
        "results": {
            "hostname": device["hostname"],
            "serial": device["serial"],
            "version": device["version"],
            "build": device["build"],
            "mode": device["mode"],
            "vdom": "root",
            "status": "ok",
        },
    }


@app.get("/api/v2/cmdb/system/vdom")
async def list_vdoms(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),
    x_mock_mode: Optional[str] = Header(None, alias="X-Mock-Mode"),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
):
    _validate_token(authorization, access_token)
    device = _resolve_device(device_id, mode, x_mock_mode, x_device_id)

    vdom_list = [{"name": vdom_name, "comments": f"VDOM {vdom_name}"} for vdom_name in device["vdoms"]]

    return {
        "http_method": "GET",
        "status": "success",
        "version": device["version"],
        "build": device["build"],
        "results": vdom_list,
    }