"""POST /api/ingest/{honeypot_id}/events — the OpenCanary event-ingestion
endpoint. See app/web/routes/ingest.py."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent

pytestmark = pytest.mark.asyncio


async def _make_honeypot(db_session_factory) -> Honeypot:
    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        honeypot = Honeypot(company_id=company.id, name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_ingest_event_with_shared_token_is_accepted(anonymous_client, db_session_factory):
    honeypot = await _make_honeypot(db_session_factory)
    response = await anonymous_client.post(
        f"/api/ingest/{honeypot.id}/events",
        headers={"Authorization": "Bearer test-only-ingest-token-not-for-real-use-0000000"},
        json={
            "logtype": "SSH_LOGIN_ATTEMPT",
            "local_time": "2026-01-01 12:00:00.000000",
            "src_host": "203.0.113.7",
            "src_port": 51422,
            "dst_port": 22222,
            "logdata": {"USERNAME": "root", "PASSWORD": "toor"},
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "accepted"

    async with db_session_factory() as db:
        result = await db.execute(select(HoneypotEvent))
        events = result.scalars().all()
        assert len(events) == 1
        assert events[0].event_type == "SSH_LOGIN_ATTEMPT"
        assert events[0].src_ip == "203.0.113.7"
        assert events[0].company_id == honeypot.company_id

        refreshed = await db.get(Honeypot, honeypot.id)
        assert refreshed.last_seen_at is not None


async def test_ingest_event_with_wrong_token_is_rejected(anonymous_client, db_session_factory):
    honeypot = await _make_honeypot(db_session_factory)
    response = await anonymous_client.post(
        f"/api/ingest/{honeypot.id}/events",
        headers={"Authorization": "Bearer not-the-right-token"},
        json={"logtype": "PORTSCAN"},
    )
    assert response.status_code == 401


async def test_ingest_event_for_unknown_honeypot_is_404(anonymous_client):
    response = await anonymous_client.post(
        f"/api/ingest/{uuid.uuid4()}/events",
        headers={"Authorization": "Bearer test-only-ingest-token-not-for-real-use-0000000"},
        json={"logtype": "PORTSCAN"},
    )
    assert response.status_code == 404


async def test_ingest_requires_a_bearer_token(anonymous_client, db_session_factory):
    honeypot = await _make_honeypot(db_session_factory)
    response = await anonymous_client.post(
        f"/api/ingest/{honeypot.id}/events", json={"logtype": "PORTSCAN"}
    )
    assert response.status_code == 401
