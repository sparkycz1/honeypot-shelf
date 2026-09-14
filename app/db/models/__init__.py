"""Explicit imports of every model module — Alembic's `--autogenerate`
(see `alembic/env.py`) and any other whole-metadata introspection only see
a model that has actually been imported somewhere. A new model module not
listed here is invisible to migrations."""

from app.db.models.api_token import ApiToken
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditChainState, AuditLogEntry
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_company import honeypot_companies
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.honeypot_service import HoneypotService
from app.db.models.honeypot_tag import Tag
from app.db.models.honeypot_update_run import HoneypotUpdateRun
from app.db.models.initialize_run import InitializeRun
from app.db.models.notification_log import NotificationChannel, NotificationKind, NotificationLog
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.notification_rule_state import NotificationRuleState
from app.db.models.pending_honeypot import PendingHoneypot
from app.db.models.saved_honeypot_view import SavedHoneypotView
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.scheduled_task_run import ScheduledTaskRun
from app.db.models.ssh_identity import SSHIdentity
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
    "CompanyMembership",
    "CompanySnapshot",
    "Honeypot",
    "HoneypotEvent",
    "honeypot_companies",
    "HoneypotMonitoringSample",
    "HoneypotPackage",
    "HoneypotReachabilitySample",
    "HoneypotService",
    "HoneypotUpdateRun",
    "InitializeRun",
    "NotificationChannel",
    "NotificationKind",
    "NotificationLog",
    "NotificationRule",
    "NotificationRuleState",
    "NotificationScope",
    "PendingHoneypot",
    "SSHIdentity",
    "SavedHoneypotView",
    "ScheduledTask",
    "ScheduledTaskRun",
    "Tag",
    "TotpRecoveryCode",
    "User",
    "UserSession",
    "WebAuthnCredential",
]
