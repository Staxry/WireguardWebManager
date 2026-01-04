"""
WireGuard Web Management Interface - Основной пакет
"""

__version__ = '2.0'

# Экспортируем основные компоненты для удобного импорта
from .admin_config import (
    load_admin_config, verify_password, is_session_expired,
    record_failed_login, is_ip_blocked, clear_login_attempts,
    change_admin_password, change_admin_username
)

from .audit_log import (
    log_action, AuditActions, get_audit_logs, get_audit_stats
)

from .rate_limiter import (
    rate_limit, get_rate_limit_status, get_blocked_ips_info
)

from .database import (
    init_database, ClientDB, TrafficDB, SettingsDB
)

from .api import (
    api_bp, init_api
)

__all__ = [
    # Admin config
    'load_admin_config', 'verify_password', 'is_session_expired',
    'record_failed_login', 'is_ip_blocked', 'clear_login_attempts',
    'change_admin_password', 'change_admin_username',
    # Audit log
    'log_action', 'AuditActions', 'get_audit_logs', 'get_audit_stats',
    # Rate limiter
    'rate_limit', 'get_rate_limit_status', 'get_blocked_ips_info',
    # Database
    'init_database', 'ClientDB', 'TrafficDB', 'SettingsDB',
    # API
    'api_bp', 'init_api',
]

