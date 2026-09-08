# app/integrations/api.py

from app.infrastructure.integrations.fortigate.api import FortiGateAPI
# from app.integrations.fortianalyzer.api import FortiAnalyzerAPI  # Futuro
# from app.integrations.cisco.api import CiscoAPI                  # Futuro


class IntegrationsAPI:
    """
    FACHADA PRINCIPAL del módulo de Integraciones.
    Agrupa las sub-fachadas especializadas por tipo de dispositivo/proveedor.
    """

    def __init__(self):
        self._fortigate = FortiGateAPI()
        # self._fortianalyzer = FortiAnalyzerAPI()
        # self._cisco = CiscoAPI()

    @property
    def fortigate(self) -> FortiGateAPI:
        """Acceso a las operaciones específicas de FortiGate."""
        return self._fortigate

    # @property
    # def fortianalyzer(self) -> FortiAnalyzerAPI:
    #     return self._fortianalyzer