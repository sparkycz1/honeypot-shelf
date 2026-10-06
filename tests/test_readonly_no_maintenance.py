"""A read-only account watches a honeypot — state, activity, monitoring —
and does not see what maintaining it is about: installed packages and
pending updates. An account with write access sees both. Checked on the
pages and in the REST API."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, date, datetime
from typing import Any

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.ssh.packages import PackageSource
from tests.conftest import create_company


async def _seed(db_session_factory: Any) -> tuple[uuid.UUID, uuid.UUID]:
    """One honeypot with a pending update, an installed package and an
    update run. Returns (honeypot id, company id)."""
    company = await create_company(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="hp-watch",
            ip_address="10.6.6.6",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
            is_reachable=True,
            updates_checked_at=now,
            packages_updated_at=now,
            upgradable_count=3,
            security_upgradable_count=1,
            reboot_required=True,
            apt_upgradable_packages=[
                {"name": "secretpkg", "current_version": "1", "new_version": "2"}
            ],
            apt_held_packages=["heldpkg"],
        )
        db.add(honeypot)
        await db.flush()
        db.add(
            HoneypotPackage(
                honeypot_id=honeypot.id, source=PackageSource.APT, name="secretpkg", version="1"
            )
        )
        db.add(
            HoneypotUpdateRun(
                honeypot_id=honeypot.id,
                strategy=UpgradeStrategy.FULL_UPGRADE,
                status=UpdateRunStatus.SUCCEEDED,
                finished_at=now,
            )
        )
        db.add(
            CompanySnapshot(
                company_id=company.id,
                snapshot_date=date.today(),
                honeypot_count=1,
                honeypots_online=1,
                honeypots_reachable=1,
                event_count=0,
                needs_updates=1,
                needs_security_updates=1,
                needs_reboot=1,
            )
        )
        await db.commit()
        return honeypot.id, company.id


async def _token(db_session_factory: Any, user: Any) -> dict[str, str]:
    async with db_session_factory() as db:
        _token_row, raw = await create_api_token(
            db, await db.get(type(user), user.id), name="scope", expires_at=None
        )
        await db.commit()
    return {"Authorization": f"Bearer {raw}"}


async def test_read_only_pages_show_no_packages_or_updates(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _seed(db_session_factory)
    await login_as(client, company_id=company_id, access_level=AccessLevel.READ)
    base = f"/honeypots/{honeypot_id}"

    overview = await client.get(base)
    listing = await client.get("/honeypots")
    dashboard = await client.get("/dashboard")
    history = await client.get(f"{base}/history")
    inventory = await client.get("/honeypots/inventory.csv")

    assert overview.status_code == 200
    assert "packages-modal" not in overview.text
    assert "packages-summary-panel" not in overview.text
    assert listing.status_code == 200 and "hp-watch" in listing.text
    assert "package-search" not in listing.text
    assert "3 updates" not in listing.text and "badge-warn" not in listing.text
    assert dashboard.status_code == 200
    assert "Honeypots with pending updates" not in dashboard.text
    assert history.status_code == 200 and "System update" not in history.text
    row = next(csv.DictReader(io.StringIO(inventory.text)))
    assert row["name"] == "hp-watch" and row["status"] == "online"
    assert row["upgradable"] == "" and row["security_upgradable"] == ""
    assert row["reboot_required"] == "" and row["updates_checked_at"] == ""

    for path in (
        f"{base}/packages",
        f"{base}/packages-summary-panel",
        f"{base}/update-availability-panel",
        f"{base}/updates",
        "/honeypots/package-search?q=secret",
    ):
        response = await client.get(path)
        assert response.status_code == 403, path
        assert "secretpkg" not in response.text


async def test_read_write_pages_still_show_them(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _seed(db_session_factory)
    await login_as(client, company_id=company_id, access_level=AccessLevel.READ_WRITE)
    base = f"/honeypots/{honeypot_id}"

    overview = await client.get(base)
    packages = await client.get(f"{base}/packages")
    search = await client.get("/honeypots/package-search?q=secret")
    history = await client.get(f"{base}/history")
    inventory = await client.get("/honeypots/inventory.csv")

    assert "packages-modal" in overview.text
    assert packages.status_code == 200 and "secretpkg" in packages.text
    assert search.status_code == 200 and "hp-watch" in search.text
    assert "System update" in history.text
    assert next(csv.DictReader(io.StringIO(inventory.text)))["upgradable"] == "3"


async def test_api_hides_maintenance_data_from_a_read_only_account(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _seed(db_session_factory)
    reader = await login_as(
        client, company_id=company_id, access_level=AccessLevel.READ, api_access_enabled=True
    )
    headers = await _token(db_session_factory, reader)
    base = f"/api/v1/honeypots/{honeypot_id}"

    one = (await client.get(base, headers=headers)).json()
    many = (await client.get("/api/v1/honeypots", headers=headers)).json()
    search = await client.get("/api/v1/honeypots/package-search?q=secret", headers=headers)
    timeline = (await client.get(f"{base}/timeline", headers=headers)).json()
    trends = (await client.get("/api/v1/dashboard/trends", headers=headers)).json()

    assert one["name"] == "hp-watch" and one["is_reachable"] is True
    for key in (
        "upgradable_count",
        "security_upgradable_count",
        "apt_upgradable_packages",
        "apt_held_packages",
        "reboot_required",
        "updates_checked_at",
        "packages_updated_at",
    ):
        assert key in one and one[key] is None, key
        assert many[0][key] is None, key
    assert search.json()["results"] == []
    assert "update_run" not in {event["kind"] for event in timeline["events"]}
    snapshot = trends["snapshots"][0]
    assert snapshot["honeypots_online"] == 1
    assert snapshot["needs_updates"] is None and snapshot["needs_reboot"] is None
    for path in (f"{base}/packages", f"{base}/packages/held", f"{base}/update-runs"):
        assert (await client.get(path, headers=headers)).status_code == 403, path


async def test_api_shows_maintenance_data_to_a_read_write_account(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _seed(db_session_factory)
    writer = await login_as(
        client,
        company_id=company_id,
        access_level=AccessLevel.READ_WRITE,
        api_access_enabled=True,
    )
    headers = await _token(db_session_factory, writer)
    base = f"/api/v1/honeypots/{honeypot_id}"

    one = (await client.get(base, headers=headers)).json()
    packages = await client.get(f"{base}/packages", headers=headers)
    runs = await client.get(f"{base}/update-runs", headers=headers)
    trends = (await client.get("/api/v1/dashboard/trends", headers=headers)).json()
    timeline = (await client.get(f"{base}/timeline", headers=headers)).json()

    assert one["upgradable_count"] == 3 and one["apt_held_packages"] == ["heldpkg"]
    assert [p["name"] for p in packages.json()] == ["secretpkg"]
    assert runs.status_code == 200 and len(runs.json()["runs"]) == 1
    assert trends["snapshots"][0]["needs_updates"] == 1
    assert "update_run" in {event["kind"] for event in timeline["events"]}


async def test_reboot_needed_is_not_sent_to_a_read_only_rule_owner(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    """A pending reboot is about updates; a failed service is monitoring."""
    from app.db.models.notification_log import NotificationChannel, NotificationKind
    from app.db.models.notification_rule import NotificationRule, NotificationScope
    from app.tasks import jobs
    from tests.conftest import _create_user

    honeypot_id, company_id = await _seed(db_session_factory)
    owners = {}
    for name, level in (("reader", AccessLevel.READ), ("writer", AccessLevel.READ_WRITE)):
        owners[name] = (
            await _create_user(
                db_session_factory, username=name, company_id=company_id, access_level=level
            )
        )[0]
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
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
                    notify_on_reboot_required=True,
                    notify_on_service_failed=True,
                )
            )
        await db.commit()
    posted: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook",
        lambda url, payload: posted.append((payload["kind"], url.rsplit("/", 1)[-1])),
    )

    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        await jobs._announce_health(
            db,
            honeypot,
            kind=NotificationKind.REBOOT_REQUIRED,
            rule_column=NotificationRule.notify_on_reboot_required,
            current=["reboot"],
        )
        await jobs._announce_health(
            db,
            honeypot,
            kind=NotificationKind.SERVICE_FAILED,
            rule_column=NotificationRule.notify_on_service_failed,
            current=["nginx.service"],
        )

    assert sorted(posted) == [
        ("reboot_required", "writer"),
        ("service_failed", "reader"),
        ("service_failed", "writer"),
    ]
