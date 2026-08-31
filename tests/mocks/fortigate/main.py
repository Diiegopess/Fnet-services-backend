"""
Micro-servidor Mock para emular la API REST de FortiOS.
Utilizado exclusivamente para tests de integración y entorno de desarrollo local.
"""

from fastapi import FastAPI, Header, HTTPException, status

app = FastAPI(title="FortiOS Mock API", version="7.2.4")

VALID_TOKENS = {"test-token-123", "fortigate-secret-token", "valid-token"}


@app.get("/api/v2/monitor/system/status")
async def get_system_status(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer token",
        )

    token = authorization.replace("Bearer ", "").strip()
    if token not in VALID_TOKENS and not token.startswith("valid"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid FortiOS REST API token",
        )

    return {
        "http_method": "GET",
        "status": "success",
        "version": "v7.2.4",
        "results": {
            "serial": "FG100ETK19001234",
            "version": "7.2.4",
            "build": 1396,
            "vdom_mode": "split-vdom",
            "hostname": "FW-LAB-MOCK-01",
        },
    }


@app.get("/api/v2/cmdb/system/vdom")
async def list_vdoms(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer token",
        )

    return {
        "http_method": "GET",
        "status": "success",
        "results": [
            {"name": "root", "comments": "Root management VDOM"},
            {"name": "CLIENT-CORP-A", "comments": "Production Corporate Traffic"},
            {"name": "CLIENT-GUEST-B", "comments": "Guest WiFi"},
        ],
    }