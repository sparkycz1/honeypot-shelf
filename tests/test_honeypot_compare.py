"""Two honeypots side by side (`app.services.honeypot_compare`): facts,
packages and services that differ, from what is already stored. Ported
from debcontrol."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from httpx2 import AsyncClient

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.honeypot_service import HoneypotService
from app.db.models.user import User
from app.services import honeypot_compare
from app.ssh.packages import PackageSource
from tests.conftest import create_company


def test_items_diff() -> None:
    diff = honeypot_compare.diff_items(
        {"openssh-server": "1:9.2", "curl": "7.88", "only-a": "1"},
        {"openssh-server": "1:9.6", "curl": "7.88", "only-b": "2"},
    )
    assert diff.only_a == [("only-a", "1")] and diff.only_b == [("only-b", "2")]
    assert diff.different == [("openssh-server", "1:9.2", "1:9.6")]
    assert (diff.same, diff.differences) == (1, 3)


async def _seed(db_session_factory: Any, company_id: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    ids = []
    for name, kernel, ssh_version, address, unit_state in (
        ("hp-a", "6.6.31", "1:9.2", "192.0.2.10/24", "active"),
        ("hp-b", "6.6.51", "1:9.6", "192.0.2.11/24", "failed"),
    ):
        now = datetime.now(UTC)
        async with db_session_factory() as db:
            honeypot = Honeypot(
                companies=[await db.get(Company, company_id)],
                name=name,
                kernel_version=kernel,
                os_version="Debian GNU/Linux 12",
                network_interfaces=[{"interface": "eth0", "address": address}],
                packages_updated_at=now,
                services_updated_at=now,
            )
            db.add(honeypot)
            await db.flush()
            db.add_all(
                [
                    HoneypotPackage(
                        honeypot_id=honeypot.id,
                        source=PackageSource.APT,
                        name="openssh-server",
                        version=ssh_version,
                    ),
                    HoneypotPackage(
                        honeypot_id=honeypot.id,
                        source=PackageSource.APT,
                        name="curl",
                        version="7.88",
                    ),
                    HoneypotService(
                        honeypot_id=honeypot.id,
                        unit="opencanary.service",
                        load_state="loaded",
                        active_state=unit_state,
                        sub_state="running" if unit_state == "active" else "failed",
                        description="OpenCanary",
                    ),
                ]
            )
            await db.commit()
            ids.append(honeypot.id)
    return ids[0], ids[1]


async def test_compare_page_bulk_button_and_api(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    a, b = await _seed(db_session_factory, company.id)
    listing = await client.get("/honeypots")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', listing.text)
    assert csrf is not None

    picked = await client.post(
        "/honeypots/bulk/compare",
        data={"csrf_token": csrf.group(1), "honeypot_ids": [str(b), str(a)]},
        follow_redirects=False,
    )
    one = await client.post(
        "/honeypots/bulk/compare",
        data={"csrf_token": csrf.group(1), "honeypot_ids": [str(a)]},
        follow_redirects=False,
    )
    page = await client.get(f"/honeypots/compare?a={a}&b={b}")

    assert 'formaction="/honeypots/bulk/compare"' in listing.text
    assert picked.headers["location"] == f"/honeypots/compare?a={a}&b={b}"
    assert one.headers["location"] == "/honeypots?compare_error=1"
    assert page.status_code == 200
    assert "6.6.31" in page.text and "6.6.51" in page.text
    assert "1:9.2" in page.text and "1:9.6" in page.text
    assert "active (running)" in page.text and "failed (failed)" in page.text
    assert f'href="/honeypots/compare?a={b}&amp;b={a}"' in page.text

    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    api = (
        await client.get(
            f"/api/v1/honeypots/compare?a={a}&b={b}",
            headers={"Authorization": f"Bearer {raw}"},
        )
    ).json()
    facts = {row["field"]: row for row in api["facts"]}
    assert facts["kernel_version"]["differs"] and not facts["os_version"]["differs"]
    assert facts["addresses"]["only_a"] == ["eth0 192.0.2.10/24"]
    assert api["packages"]["different"] == [{"name": "openssh-server", "a": "1:9.2", "b": "1:9.6"}]
    assert api["packages"]["same"] == 1


async def test_compare_needs_write_access_to_both(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    mine = await create_company(db_session_factory, name="Mine")
    theirs = await create_company(db_session_factory, name="Theirs")
    a, b = await _seed(db_session_factory, mine.id)
    other, _ = await _seed(db_session_factory, theirs.id)

    await login_as(client, username="rw", company_id=mine.id, access_level=AccessLevel.READ_WRITE)
    assert (await client.get(f"/honeypots/compare?a={a}&b={b}")).status_code == 200
    assert (await client.get(f"/honeypots/compare?a={a}&b={other}")).status_code == 404
    assert (await client.get(f"/honeypots/compare?a={a}&b={a}")).status_code == 404

    await login_as(client, username="ro", company_id=mine.id, access_level=AccessLevel.READ)
    assert (await client.get(f"/honeypots/compare?a={a}&b={b}")).status_code == 403
