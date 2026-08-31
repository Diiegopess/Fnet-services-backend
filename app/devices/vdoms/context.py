"""
Módulo de Contexto de Ejecución para VDOMs.
"""

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class VDOMContext:
    """Contenedor inmutable con el contexto completo y validado de un VDOM."""
    vdom_id: uuid.UUID
    vdom_name: str
    is_root: bool
    device_id: uuid.UUID
    device_name: str
    device_host: str
    device_port: int
    client_id: uuid.UUID