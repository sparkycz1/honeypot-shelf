"""How a notification is delivered — see `app.db.models.notification_log`
and `app.db.models.notification_rule`.

Its own module, with no model imports, so `notification_rule` can use it at
class-definition time without importing `notification_log` (no import
cycle between the models).
"""

import enum


class NotificationChannel(enum.StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    # Push services and team chats — see app.services.push_channels.
    NTFY = "ntfy"
    GOTIFY = "gotify"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    PUSHOVER = "pushover"
    MATTERMOST = "mattermost"
    SLACK = "slack"
    TEAMS = "teams"
