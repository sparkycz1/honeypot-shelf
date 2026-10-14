"""Hardware inventory and warranties (`app.ssh.hardware`,
`app.services.hardware_inventory`): read from DMI or a Raspberry Pi's
device tree, recorded by people with write access, listed per company,
and a warranty that ends soon announced once per rule. Ported from
debcontrol, plus the Pi."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import User
from app.services import hardware_inventory
from app.ssh.facts import _SECTION_MARKERS, parse_facts_output
from app.ssh.hardware import parse_hardware
from app.tasks import jobs
from tests.conftest import _create_user, create_company


def test_a_raspberry_pi_is_read_from_its_device_tree() -> None:
    pi = parse_hardware(
        "vendor=\nmodel=\nserial=\n"
        "dt_model=Raspberry Pi 4 Model B Rev 1.4\ndt_serial=00000000a1b2c3d4\nvirt="
    )
    assert pi == {
        "vendor": "Raspberry Pi",
        "model": "Raspberry Pi 4 Model B Rev 1.4",
        "serial": "a1b2c3d4",
        "is_physical": True,
    }


def test_a_pc_is_read_from_dmi_and_placeholders_are_unknown() -> None:
    pc = parse_hardware(
        "vendor=Dell Inc.\nmodel=OptiPlex 7070\nserial=To Be Filled By O.E.M.\n"
        "dt_model=\ndt_serial=\nvirt=none"
    )
    vm = parse_hardware("vendor=QEMU\nmodel=Standard PC (Q35 + ICH9, 2009)\nserial=\nvirt=kvm")
    assert pc == {
        "vendor": "Dell Inc.",
        "model": "OptiPlex 7070",
        "serial": None,
        "is_physical": True,
    }
    assert vm["is_physical"] is False
    assert parse_hardware("") == {
        "vendor": None,
        "model": None,
        "serial": None,
        "is_physical": None,
    }


def test_the_facts_carry_the_hardware_section() -> None:
    hardware = (
        "vendor=\nmodel=\nserial=\n"
        "dt_model=Raspberry Pi 5 Model B Rev 1.0\ndt_serial=12ab\nvirt=none"
    )
    raw = "".join(
        f"==={name}===\n{hardware if name == 'HARDWARE' else ''}\n"
        for name in _SECTION_MARKERS
    )
    facts = parse_facts_output(raw)
    assert facts["hardware"]["model"] == "Raspberry Pi 5 Model B Rev 1.0"
    assert facts["hardware"]["serial"] == "12ab"


def test_dates_are_checked() -> None:
    assert hardware_inventory.parse_date("2027-03-31", "x") == date(2027, 3, 31)
    assert hardware_inventory.parse_date("  ", "x") is None
    for bad, code in (("31.3.2027", "date"), ("1850-01-01", "year")):
        try:
            hardware_inventory.parse_date(bad, "x")
        except hardware_inventory.AssetError as exc:
            assert exc.code == code
        else:
            raise AssertionError(bad)


async def _honeypot(
    db_session_factory: Any, company_id: uuid.UUID, name: str, **fields: Any
) -> uuid.UUID:
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company_id)], name=name, **fields)
        db.add(honeypot)
        await db.commit()
        return honeypot.id


def _csrf(text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', text)
    assert match is not None
    return match.group(1)


async def test_recording_a_warranty_and_the_inventory(
    client: AsyncClient, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    pi = await _honeypot(
        db_session_factory, company.id, "pi", hw_vendor="Raspberry Pi", hw_model="Raspberry Pi 4"
    )
    vm = await _honeypot(db_session_factory, company.id, "vm", is_physical=False)
    soon = (datetime.now(UTC).date() + timedelta(days=20)).isoformat()

    page = await client.get(f"/honeypots/{pi}")
    bad = await client.post(
        f"/honeypots/{pi}/asset",
        data={"csrf_token": _csrf(page.text), "purchase_date": "2027-01-01",
              "warranty_until": "2026-01-01"},
        follow_redirects=False,
    )
    saved = await client.post(
        f"/honeypots/{pi}/asset",
        data={"csrf_token": _csrf(page.text), "purchase_date": "2025-01-10",
              "warranty_until": soon, "asset_serial": "SN-1", "asset_note": "Rack 2"},
        follow_redirects=False,
    )
    vm_page = await client.get(f"/honeypots/{vm}")
    after = await client.get(f"/honeypots/{pi}")
    inventory = await client.get("/honeypots/hardware")

    assert 'id="hardware"' in page.text and 'id="hardware"' not in vm_page.text
    assert bad.headers["location"].endswith("asset_error=order#hardware")
    assert saved.status_code == 303
    assert "SN-1" in after.text and "20 days left" in after.text
    assert "Raspberry Pi Raspberry Pi 4" in inventory.text and ">vm<" not in inventory.text
    async with db_session_factory() as db:
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert "honeypot.asset.update" in actions


async def test_read_only_and_other_companies(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    mine = await create_company(db_session_factory, name="Mine")
    theirs = await create_company(db_session_factory, name="Theirs")
    own = await _honeypot(db_session_factory, mine.id, "own-pi", hw_model="Pi")
    await _honeypot(db_session_factory, theirs.id, "their-pi", hw_model="Pi")
    await login_as(client, company_id=mine.id, access_level=AccessLevel.READ)

    inventory = await client.get("/honeypots/hardware")
    page = await client.get(f"/honeypots/{own}")
    refused = await client.post(
        f"/honeypots/{own}/asset", data={"csrf_token": _csrf(page.text), "asset_note": "x"}
    )

    assert "own-pi" in inventory.text and "their-pi" not in inventory.text
    assert 'action="/honeypots/' + str(own) + '/asset"' not in page.text
    assert refused.status_code == 403


async def test_api(client: AsyncClient, login_as: Any, db_session_factory: Any) -> None:
    company = await create_company(db_session_factory)
    pi = await _honeypot(db_session_factory, company.id, "api-pi", hw_serial="FW-1")
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw}"}

    put = await client.put(
        f"/api/v1/honeypots/{pi}/asset",
        headers=headers,
        json={"warranty_until": "2030-06-30", "note": "spare"},
    )
    bad = await client.put(
        f"/api/v1/honeypots/{pi}/asset",
        headers=headers,
        json={"purchase_date": "2030-01-01", "warranty_until": "2029-01-01"},
    )
    listing = await client.get("/api/v1/hardware-inventory", headers=headers)
    one = await client.get(f"/api/v1/honeypots/{pi}", headers=headers)

    assert put.status_code == 200 and put.json()["serial"] == "FW-1"
    assert bad.status_code == 422
    assert listing.json()[0]["honeypot_name"] == "api-pi"
    assert listing.json()[0]["warranty_until"] == "2030-06-30"
    assert one.json()["hardware"]["note"] == "spare"


async def test_a_warranty_that_ends_soon_is_announced_once_per_rule(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    posted: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook",
        lambda url, payload: posted.append((url.rsplit("/", 1)[-1], payload["details"])),
    )
    company = await create_company(db_session_factory)
    today = datetime.now(UTC).date()
    pi = await _honeypot(
        db_session_factory, company.id, "pi", warranty_until=today + timedelta(days=30)
    )
    owners = {
        "writer": (await _create_user(
            db_session_factory, username="w", company_id=company.id,
            access_level=AccessLevel.READ_WRITE,
        ))[0],
        "reader": (await _create_user(
            db_session_factory, username="r", company_id=company.id,
            access_level=AccessLevel.READ,
        ))[0],
        "short": (await _create_user(
            db_session_factory, username="s", company_id=company.id,
            access_level=AccessLevel.READ_WRITE,
        ))[0],
    }
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, pi)
        for name, owner in owners.items():
            db.add(
                NotificationRule(
                    user_id=owner.id,
                    name=name,
                    scope=NotificationScope.HONEYPOT,
                    honeypots=[honeypot],
                    delivery_channel=NotificationChannel.WEBHOOK,
                    webhook_url=f"https://hooks.example.com/{name}",
                    notify_on_alert=False,
                    notify_on_unavailable=False,
                    notify_on_recovered=False,
                    notify_on_warranty_ending=True,
                    warranty_notice_days=7 if name == "short" else 60,
                )
            )
        await db.commit()

    first = await jobs._announce_warranties()
    again = await jobs._announce_warranties()
    # A renewed warranty is a new end date: announced again when its time comes.
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, pi)
        assert honeypot is not None
        honeypot.warranty_until = today + timedelta(days=3)
        await db.commit()
    renewed = await jobs._announce_warranties()

    assert (first, again) == (1, 0)
    # The reader may not maintain the honeypot; "short" waits for 7 days.
    assert posted[0][0] == "writer" and "in 30 day(s)" in posted[0][1]
    assert renewed == 2
    assert sorted(name for name, _ in posted[1:]) == ["short", "writer"]
