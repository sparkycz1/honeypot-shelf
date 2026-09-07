"""Pydantic schemas for scheduled-task forms."""

from __future__ import annotations

import uuid
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.db.models.scheduled_task import ScheduleTargetType
from app.scheduling.actions import get_action
from app.scheduling.cron import validate_cron_expression


class ScheduledTaskCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=100)
    action_params: dict[str, str] = Field(default_factory=dict)
    target_type: ScheduleTargetType
    target_honeypot_id: uuid.UUID | None = None
    # Not user-submitted — resolved by the route from `target_honeypot_id`'s
    # own company (HONEYPOT) or an explicit company choice (ALL_HONEYPOTS)
    # and validated against the current user's scope there. See
    # `app.db.models.scheduled_task.ScheduledTask`'s module docstring.
    owner_company_id: uuid.UUID | None = None
    cron_expression: str = Field(min_length=1, max_length=100)
    is_enabled: bool = True

    @field_validator("action")
    @classmethod
    def _validate_action(cls, value: str) -> str:
        if get_action(value) is None:
            raise ValueError(f'Unknown action "{value}".')
        return value

    @field_validator("cron_expression")
    @classmethod
    def _validate_cron(cls, value: str) -> str:
        stripped = value.strip()
        validate_cron_expression(stripped)
        return stripped

    @model_validator(mode="after")
    def _validate_target(self) -> Self:
        if self.target_type == ScheduleTargetType.HONEYPOT:
            if self.target_honeypot_id is None:
                raise ValueError("Pick a honeypot for a honeypot-targeted schedule.")
        else:  # ALL_HONEYPOTS — no specific honeypot id applies.
            self.target_honeypot_id = None
        if self.owner_company_id is None:
            raise ValueError("Pick a company for this schedule.")
        return self
