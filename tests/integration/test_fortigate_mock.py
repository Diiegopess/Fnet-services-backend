# tests/integration/test_fortigate_mock.py

import os
import pytest
from app.devices.connectors.factory import FortiConnectorFactory

MOCK_HOST = os.getenv("FORTIGATE_MOCK_HOST", "localhost")
MOCK_PORT = int(os.getenv("FORTIGATE_MOCK_PORT", "8443"))
VALID_TOKEN = "test-token-123"


@pytest.mark.asyncio
async def test_connector_connectivity_check():
    """Prueba la sonda de conectividad contra el contenedor Mock."""
    connector = FortiConnectorFactory.get_device_connector(
        host=MOCK_HOST,
        port=MOCK_PORT,
        api_token=VALID_TOKEN,
        version="7.2",
        verify_ssl=False,
    )

    try:
        result = await connector.test_connectivity()

        assert result.is_reachable is True
        assert result.status_code == 200
        assert result.serial == "FG100E-MOCK-TEST"  # Ahora coinciden perfectamente
        assert result.version == "v7.2.4"
    finally:
        await connector.close()


@pytest.mark.asyncio
async def test_connector_list_vdoms():
    """Prueba la lectura de VDOMs expuestos por el conector contra el mock."""
    connector = FortiConnectorFactory.get_device_connector(
        host=MOCK_HOST,
        port=MOCK_PORT,
        api_token=VALID_TOKEN,
        version="7.2",
        verify_ssl=False,
    )

    try:
        vdoms = await connector.list_vdoms()

        assert isinstance(vdoms, list)
        assert len(vdoms) >= 1
        assert "root" in vdoms
    finally:
        await connector.close()


@pytest.mark.asyncio
async def test_connector_invalid_token_handling():
    """Prueba que el conector maneje respuestas 401 Unauthorized de forma segura."""
    connector = FortiConnectorFactory.get_device_connector(
        host=MOCK_HOST,
        port=MOCK_PORT,
        api_token="token-invalido-xyz",
        version="7.2",
        verify_ssl=False,
    )

    try:
        result = await connector.test_connectivity()

        assert result.is_reachable is False
        assert result.status_code in [401, 500] or "Unauthorized" in (result.error_message or "")
    finally:
        await connector.close()