"""
Micro-servidor Mock para emular la API REST de FortiOS.
Utilizado exclusivamente para tests de integración y entorno de desarrollo local.
"""

from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Query, status

app = FastAPI(title="FortiOS Mock API", version="7.2.4")

VALID_TOKENS = {"test-token-123", "fortigate-secret-token", "valid-token"}


def _validate_token(authorization: Optional[str], access_token: Optional[str]) -> None:
    """Valida el token tanto por Header Bearer como por Query Param ?access_token="""
    token = None

    if access_token:
        token = access_token.strip()
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "").strip()

    if not token or (token not in VALID_TOKENS and not token.startswith("valid")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid FortiOS REST API token",
        )


@app.get("/api/v2/monitor/system/status")
async def get_system_status(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),  # Permite pasar ?mode=vdom o ?mode=standalone
    x_mock_mode: Optional[str] = Header(None, alias="X-Mock-Mode"),  # O por Header
):
    _validate_token(authorization, access_token)

    # Evaluación si es VDOM o Standalone según query params o headers
    is_vdom_mode = (mode == "vdom") or (x_mock_mode == "vdom")

    if is_vdom_mode:
        serial_number = "FG100E-MOCK-VDOM"
        hostname = "FW-Mock-VDOM"
        system_mode = "vdom"
    else:
        serial_number = "FG100E-MOCK-STANDALONE"
        hostname = "FW-Mock-Standalone"
        system_mode = "standalone"

    # Estructura JSON Oficial que espera el conector de FortiGate
    return {
        "http_method": "GET",
        "status": "success",
        "version": "v7.2.4",
        "build": 1396,
        "results": {
            "hostname": hostname,
            "serial": serial_number,
            "version": "v7.2.4",
            "build": 1396,
            "mode": system_mode,
            "vdom": "root",
            "status": "ok",
        },
    }


@app.get("/api/v2/cmdb/system/vdom")
async def list_vdoms(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Query(None),
):
    _validate_token(authorization, access_token)

    return {
        "http_method": "GET",
        "status": "success",
        "version": "v7.2.4",
        "build": 1396,
        "results": [
            {"name": "root", "comments": "Root management VDOM"},
            {"name": "CLIENT-CORP-A", "comments": "Production Corporate Traffic"},
            {"name": "CLIENT-GUEST-B", "comments": "Guest WiFi"},
        ],
    }