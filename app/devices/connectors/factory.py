"""
Fábrica para instanciar conectores tipados según versión de FortiOS.
"""

from app.devices.connectors.base import DeviceConnector, VDOMConnector
from app.devices.connectors.fortios_v7_2 import FortiOSV72DeviceConnector, FortiOSV72VDOMConnector
from app.devices.connectors.fortios_v7_0 import FortiOSV70DeviceConnector, FortiOSV70VDOMConnector
from app.devices.connectors.fortios_v7_4 import FortiOSV74DeviceConnector, FortiOSV74VDOMConnector


class FortiConnectorFactory:
    """Resuelve la implementación correcta del conector según la versión del firmware."""

    @staticmethod
    def get_device_connector(
        host: str, 
        port: int, 
        api_token: str, 
        version: str = "7.2"
    ) -> DeviceConnector:
        if version.startswith("7.0"):
            return FortiOSV70DeviceConnector(host=host, port=port, token=api_token)
        elif version.startswith("7.4"):
            return FortiOSV74DeviceConnector(host=host, port=port, token=api_token)
        # Default a 7.2
        return FortiOSV72DeviceConnector(host=host, port=port, token=api_token)

    @staticmethod
    def get_vdom_connector(
        host: str, 
        port: int, 
        api_token: str, 
        vdom_name: str, 
        version: str = "7.2"
    ) -> VDOMConnector:
        if version.startswith("7.0"):
            return FortiOSV70VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name)
        elif version.startswith("7.4"):
            return FortiOSV74VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name)
        # Default a 7.2
        return FortiOSV72VDOMConnector(host=host, port=port, token=api_token, vdom=vdom_name)