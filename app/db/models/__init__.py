"""Explicit imports of every model module — Alembic's `--autogenerate`
(see `alembic/env.py`) and any other whole-metadata introspection only see
a model that has actually been imported somewhere. A new model module not
listed here is invisible to migrations."""

from app.db.models.api_token import ApiToken
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditChainState, AuditLogEntry
from app.db.models.company import Company
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.totp_recovery_code import TotpRecoveryCode
from app.db.models.user import User
from app.db.models.user_session import UserSession
from app.db.models.webauthn_credential import WebAuthnCredential

__all__ = [
    "ApiToken",
    "AppSettings",
    "AuditChainState",
    "AuditLogEntry",
    "Company",
    "CompanySnapshot",
    "Honeypot",
    "HoneypotEvent",
    "TotpRecoveryCode",
    "User",
    "UserSession",
    "WebAuthnCredential",
]
