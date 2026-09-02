# app/devices/connectors/factory.py

from app.devices.connectors.base import DeviceConnector, VDOMConnector
from app.devices.connectors.fortios_v6_4 import FortiOSV64DeviceConnector, FortiOSV64VDOMConnector
from app.devices.connectors.fortios_v7_0 import FortiOSV70DeviceConnector, FortiOSV70VDOMConnector
from app.devices.connectors.fortios_v7_2 import FortiOSV72DeviceConnector, FortiOSV72VDOMConnector
from app.devices.connectors.fortios_v7_4 import FortiOSV74DeviceConnector, FortiOSV74VDOMConnector
from app.devices.connectors.fortios_mock import FortiOSMockDeviceConnector, FortiOSMockVDOMConnector


class FortiConnectorFactory:
    """Resuelve la implementación correcta del conector según la versión del firmware o entorno."""

    @staticmethod
    def get_device_connector(
        host: str,
        port: int,
        api_token: str,
        version: str = "7.2",
        verify_ssl: bool = False,
    ) -> DeviceConnector:
        version_str = str(version).lower().strip()

        if version_str == "mock":
            return FortiOSMockDeviceConnector(host=host, port=port, token=api_token)
        elif version_str.startswith("6.4"):
            return FortiOSV64DeviceConnector(host=host, port=port, token=api_token, verify_ssl=verify_ssl)
        elif version_str.startswith("7.0"):
            return FortiOSV70DeviceConnector(host=host, port=port, token=api_token, verify_ssl=verify_ssl)
        elif version_str.startswith("7.4"):
            return FortiOSV74DeviceConnector(host=host, port=port, token=api_token, verify_ssl=verify_ssl)

        # Default a FortiOS 7.2
        return FortiOSV72DeviceConnector(host=host, port=port, token=api_token, verify_ssl=verify_ssl)

    @staticmethod
    def get_vdom_connector(
        host: str,
        port: int,
        api_token: str,
        vdom_name: str,
        version: str = "7.2",
        verify_ssl: bool = False,
    ) -> VDOMConnector:
        version_str = str(version).lower().strip()

        if version_str == "mock":
            return FortiOSMockVDOMConnector(vdom=vdom_name, host=host, port=port, token=api_token)
        elif version_str.startswith("6.4"):
            return FortiOSV64VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name, verify_ssl=verify_ssl)
        elif version_str.startswith("7.0"):
            return FortiOSV70VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name, verify_ssl=verify_ssl)
        elif version_str.startswith("7.4"):
            return FortiOSV74VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name, verify_ssl=verify_ssl)

        # Default a FortiOS 7.2
        return FortiOSV72VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name, verify_ssl=verify_ssl)