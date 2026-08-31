"""
Catálogo Centralizado de Permisos del Sistema (RBAC).
"""

from enum import Enum


class PermissionEnum(str, Enum):
    # --- USUARIOS ---
    USERS_READ = "users:read"
    USERS_CREATE = "users:create"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"
    USERS_ASSIGN_ROLE = "users:assign_role"

    # --- AUDITORÍA ---
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # --- CLIENTES / ORGANIZACIONES ---
    CLIENTS_READ = "clients:read"
    CLIENTS_CREATE = "clients:create"
    CLIENTS_UPDATE = "clients:update"
    CLIENTS_DELETE = "clients:delete"
    CLIENTS_ASSIGN_TECHNICIAN = "clients:assign_technician"

    # --- DISPOSITIVOS (HARDWARE / CHASIS) ---
    DEVICES_READ = "devices:read"
    DEVICES_CREATE = "devices:create"
    DEVICES_UPDATE = "devices:update"
    DEVICES_DELETE = "devices:delete"
    DEVICES_TEST_CONNECTION = "devices:test_connection"

    # --- VDOMS (PARTICIONES LÓGICAS) ---
    VDOMS_READ = "vdoms:read"
    VDOMS_CREATE = "vdoms:create"
    VDOMS_UPDATE = "vdoms:update"
    VDOMS_DELETE = "vdoms:delete"
    VDOMS_SYNC = "vdoms:sync"