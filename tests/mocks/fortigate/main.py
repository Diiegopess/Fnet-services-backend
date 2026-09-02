"""
Micro-servidor Mock para emular la API REST de FortiOS.
Utilizado exclusivamente para tests de integración y entorno de desarrollo local.
"""

from fastapi import FastAPI, Header, HTTPException, status

app = FastAPI(title="FortiOS Mock API", version="7.2.4")

VALID_TOKENS = {"test-token-123", "fortigate-secret-token", "valid-token"}


@app.get("/api/v2/monitor/system/status")
async def get_system_status(authorization: str = Header(None)):
    print(f"DEBUG MOCK -> Header recibido: '{authorization}'", flush=True)

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer token",
        )

    token = authorization.replace("Bearer ", "").strip()
    print(f"DEBUG MOCK -> Token extraido: '{token}' | Es valido: {token in VALID_TOKENS}", flush=True)

    if token not in VALID_TOKENS and not token.startswith("valid"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid FortiOS REST API token",
        )
    # ...


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