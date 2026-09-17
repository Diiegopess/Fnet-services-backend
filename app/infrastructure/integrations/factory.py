# app/infrastructure/integrations/factory.py

from app.infrastructure.integrations.fortinet.client import FortiOSRawHttpClient
from app.infrastructure.integrations.fortinet.prober import FortinetProber


class FortinetFactory:
    """Factoría unificada para clientes y sondeadores de Fortinet."""

    @staticmethod
    def get_raw_client(
        host: str,
        port: int,
        api_token: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> FortiOSRawHttpClient:
        """Instancia el cliente HTTP síncrono/asíncrono de bajo nivel."""
        return FortiOSRawHttpClient(
            host=host,
            port=port,
            token=api_token,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    @staticmethod
    def get_prober(timeout_seconds: float = 5.0) -> FortinetProber:
        """Instancia el verificador de conectividad."""
        return FortinetProber(timeout_seconds=timeout_seconds)