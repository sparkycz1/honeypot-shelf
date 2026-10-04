"""The removed services pop-up's address still leads somewhere useful."""

from __future__ import annotations

import uuid
from typing import Any

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from tests.conftest import create_company


async def test_old_services_link_redirects_to_monitoring(
    client: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        honeypot_id = honeypot.id

    response = await client.get(f"/honeypots/{honeypot_id}/services", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/honeypots/{honeypot_id}/monitoring"

    missing = await client.get(f"/honeypots/{uuid.uuid4()}/services", follow_redirects=False)
    assert missing.status_code == 404
