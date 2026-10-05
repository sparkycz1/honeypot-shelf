"""A honeypot's History tab and notes (`app.services.honeypot_timeline`,
`app.services.honeypot_notes`), the inventory CSV, bulk tags on the
honeypot list and saved views of the Logs tab
(`app.services.saved_log_views`)."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_note import HoneypotNote
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.saved_log_view import SavedLogView
from app.db.models.user import User
from app.services import honeypot_timeline
from app.services.saved_log_views import build_log_query_string
from tests.conftest import ADMIN_USERNAME, create_company


async def _make_honeypot(
    db_session_factory: Any, *, name: str = "hp-one", company_name: str = "Acme Corp"
) -> tuple[uuid.UUID, uuid.UUID]:
    """Returns (honeypot id, company id)."""
    company = await create_company(db_session_factory, name=company_name)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name=name,
            ip_address="10.7.7.7",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
            os_version="Debian GNU/Linux 12",
            cpu_cores=4,
            is_reachable=True,
        )
        db.add(honeypot)
        await db.commit()
        return honeypot.id, company.id


async def _csrf(client: Any, url: str) -> dict[str, str]:
    await client.get(url)
    return {"csrf_token": client.cookies.get("csrftoken")}


async def _admin_token(db_session_factory: Any) -> dict[str, str]:
    async with db_session_factory() as db:
        admin = (await db.execute(select(User).where(User.username == ADMIN_USERNAME))).scalar_one()
        _token, raw = await create_api_token(db, admin, name="history", expires_at=None)
        await db.commit()
    return {"Authorization": f"Bearer {raw}"}


# --- timeline ----------------------------------------------------------------


async def test_timeline_merges_notes_runs_outages_and_actions(db_session_factory: Any) -> None:
    honeypot_id, _company_id = await _make_honeypot(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add(HoneypotNote(honeypot_id=honeypot_id, author="alice", body="Moved to the DMZ"))
        db.add(
            HoneypotUpdateRun(
                honeypot_id=honeypot_id,
                strategy=UpgradeStrategy.SECURITY,
                status=UpdateRunStatus.FAILED,
                error="apt exited with status 100.",
                finished_at=now - timedelta(hours=2),
            )
        )
        for minutes, reachable in ((50, True), (40, False), (30, False), (20, True)):
            db.add(
                HoneypotReachabilitySample(
                    honeypot_id=honeypot_id,
                    checked_at=now - timedelta(minutes=minutes),
                    reachable=reachable,
                )
            )
        for action in ("honeypot.power", "honeypot.logs.view", "honeypot.note.add"):
            db.add(
                AuditLogEntry(
                    actor="bob",
                    action=action,
                    summary=f"did {action}",
                    target_type="honeypot",
                    target_id=str(honeypot_id),
                )
            )
        await db.commit()
        honeypot = await db.get(Honeypot, honeypot_id)

        full = await honeypot_timeline.load_timeline(db, honeypot, days=7, include_audit=True)
        without_audit = await honeypot_timeline.load_timeline(
            db, honeypot, days=7, include_audit=False
        )
        only_notes = await honeypot_timeline.load_timeline(
            db, honeypot, days=7, include_audit=True, kinds={"note"}
        )

    kinds = [event.kind for event in full.events]
    assert kinds.count("note") == 1
    assert kinds.count("update_run") == 1
    # Down once, back once: the two unchanged samples in between are not events.
    assert kinds.count("reachability") == 2
    # The look-up and the note's own audit entry are left out.
    assert [e.data["action"] for e in full.events if e.kind == "audit"] == ["honeypot.power"]
    assert full.events == sorted(full.events, key=lambda e: e.at, reverse=True)
    run = next(e for e in full.events if e.kind == "update_run")
    assert run.outcome == "error" and run.data["strategy"] == "security"
    assert "audit" not in {event.kind for event in without_audit.events}
    assert {event.kind for event in only_notes.events} == {"note"}
    assert honeypot_timeline.normalize_days("12") == honeypot_timeline.DEFAULT_RANGE_DAYS


# --- History tab and notes ---------------------------------------------------


async def test_history_tab_adds_and_deletes_a_note(client: Any, db_session_factory: Any) -> None:
    honeypot_id, _company_id = await _make_honeypot(db_session_factory)
    base = f"/honeypots/{honeypot_id}"
    csrf = await _csrf(client, f"{base}/history")

    empty = await client.post(f"{base}/notes", data={**csrf, "body": "   "}, follow_redirects=False)
    added = await client.post(
        f"{base}/notes",
        data={**csrf, "body": "<b>Replaced the SD card</b>"},
        follow_redirects=False,
    )
    page = await client.get(f"{base}/history")
    async with db_session_factory() as db:
        note = (await db.execute(select(HoneypotNote))).scalar_one()
    deleted = await client.post(
        f"{base}/notes/{note.id}/delete", data=csrf, follow_redirects=False
    )
    missing = await client.post(
        f"{base}/notes/{uuid.uuid4()}/delete", data=csrf, follow_redirects=False
    )

    assert empty.status_code == 303 and empty.headers["location"].endswith("note_error=1")
    assert added.status_code == 303
    assert "&lt;b&gt;Replaced the SD card&lt;/b&gt;" in page.text
    assert note.author == ADMIN_USERNAME
    assert deleted.status_code == 303 and missing.status_code == 404
    async with db_session_factory() as db:
        assert (await db.execute(select(HoneypotNote))).scalar_one_or_none() is None
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert actions.count("honeypot.note.add") == 1
    assert actions.count("honeypot.note.delete") == 1


async def test_read_only_account_sees_history_but_cannot_write_notes(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _make_honeypot(db_session_factory)
    other_id, _other_company = await _make_honeypot(
        db_session_factory, name="hp-other", company_name="Other"
    )
    async with db_session_factory() as db:
        db.add(HoneypotNote(honeypot_id=honeypot_id, author="alice", body="Visible note"))
        db.add(
            AuditLogEntry(
                actor="bob",
                action="honeypot.power",
                summary="Secret admin action",
                target_type="honeypot",
                target_id=str(honeypot_id),
            )
        )
        await db.commit()
    await login_as(client, company_id=company_id, access_level=AccessLevel.READ)

    page = await client.get(f"/honeypots/{honeypot_id}/history")
    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    refused = await client.post(
        f"/honeypots/{honeypot_id}/notes", data={**csrf, "body": "nope"}, follow_redirects=False
    )
    foreign = await client.get(f"/honeypots/{other_id}/history")

    assert page.status_code == 200
    assert "Visible note" in page.text
    assert "Secret admin action" not in page.text
    assert 'name="body"' not in page.text
    assert refused.status_code == 403
    assert foreign.status_code == 404


async def test_api_timeline_and_notes(client: Any, db_session_factory: Any) -> None:
    honeypot_id, _company_id = await _make_honeypot(db_session_factory)
    headers = await _admin_token(db_session_factory)
    base = f"/api/v1/honeypots/{honeypot_id}"

    created = await client.post(f"{base}/notes", json={"body": "From the API"}, headers=headers)
    blank = await client.post(f"{base}/notes", json={"body": "   "}, headers=headers)
    timeline = await client.get(f"{base}/timeline?days=7&kind=note", headers=headers)
    removed = await client.delete(f"{base}/notes/{created.json()['id']}", headers=headers)
    again = await client.delete(f"{base}/notes/{created.json()['id']}", headers=headers)

    assert created.status_code == 201 and created.json()["author"] == ADMIN_USERNAME
    assert blank.status_code == 422
    body = timeline.json()
    assert body["days"] == 7 and body["includes_audit"] is True
    assert [event["detail"] for event in body["events"]] == ["From the API"]
    assert removed.status_code == 204 and again.status_code == 404


# --- inventory CSV and bulk tags --------------------------------------------


async def test_inventory_csv_follows_the_filter_and_is_audited(
    client: Any, db_session_factory: Any
) -> None:
    await _make_honeypot(db_session_factory, name="=cmd-honey")
    await _make_honeypot(db_session_factory, name="plain-honey", company_name="Other")

    everything = await client.get("/honeypots/inventory.csv")
    filtered = await client.get("/honeypots/inventory.csv?q=plain")

    assert everything.status_code == 200
    assert everything.headers["content-type"].startswith("text/csv")
    assert "honeypot-shelf-inventory-" in everything.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(everything.text)))
    assert len(rows) == 2
    # A name starting with "=" must not be read as a formula by a spreadsheet.
    assert not any(row["name"].startswith("=") for row in rows)
    plain = next(row for row in rows if row["name"] == "plain-honey")
    assert plain["companies"] == "Other" and plain["status"] == "online"
    assert plain["cpu_cores"] == "4" and plain["host_key_pinned"] == "True"
    assert [row["name"] for row in csv.DictReader(io.StringIO(filtered.text))] == ["plain-honey"]
    async with db_session_factory() as db:
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert actions.count("honeypot.inventory_export") == 2


async def test_bulk_tags_are_added_and_removed(client: Any, db_session_factory: Any) -> None:
    first, _ = await _make_honeypot(db_session_factory, name="hp-a")
    second, _ = await _make_honeypot(db_session_factory, name="hp-b", company_name="Other")
    csrf = await _csrf(client, "/honeypots")
    ids = [str(first), str(second)]

    nothing = await client.post(
        "/honeypots/bulk/tags/add", data={**csrf, "honeypot_ids": ids, "tags": " "},
        follow_redirects=False,
    )
    added = await client.post(
        "/honeypots/bulk/tags/add", data={**csrf, "honeypot_ids": ids, "tags": "dmz, lab"},
        follow_redirects=False,
    )
    removed = await client.post(
        "/honeypots/bulk/tags/remove", data={**csrf, "honeypot_ids": [str(first)], "tags": "lab"},
        follow_redirects=False,
    )

    assert "bulk_error=" in nothing.headers["location"]
    assert added.headers["location"] == "/honeypots" and removed.status_code == 303
    async with db_session_factory() as db:
        tags = {
            honeypot.name: sorted(tag.name for tag in honeypot.tags)
            for honeypot in (await db.execute(select(Honeypot))).scalars().all()
        }
    assert tags == {"hp-a": ["dmz"], "hp-b": ["dmz", "lab"]}


async def test_bulk_tags_skip_honeypots_the_account_cannot_write(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    mine, company_id = await _make_honeypot(db_session_factory, name="hp-mine")
    foreign, _ = await _make_honeypot(db_session_factory, name="hp-foreign", company_name="Other")
    await login_as(client, company_id=company_id, access_level=AccessLevel.READ_WRITE)
    csrf = await _csrf(client, "/honeypots")

    await client.post(
        "/honeypots/bulk/tags/add",
        data={**csrf, "honeypot_ids": [str(mine), str(foreign)], "tags": "prod"},
        follow_redirects=False,
    )

    async with db_session_factory() as db:
        tags = {
            honeypot.name: [tag.name for tag in honeypot.tags]
            for honeypot in (await db.execute(select(Honeypot))).scalars().all()
        }
    assert tags == {"hp-mine": ["prod"], "hp-foreign": []}


# --- saved log views ---------------------------------------------------------


def test_log_view_keeps_only_known_filters() -> None:
    query = build_log_query_string(
        {
            "source": "journal",
            "priority": "err",
            "unit": "opencanary.service",
            "lines": "500",
            "hide_own": "on",
            "search": "sshd",
            "evil": "x",
        }
    )

    assert query == (
        "source=journal&priority=err&unit=opencanary.service&hide_own=1&search=sshd&lines=500"
    )
    assert build_log_query_string({"source": "nope", "lines": "many", "priority": "loud"}) == ""
    # OpenCanary's own log is wherever that honeypot keeps it: no path.
    assert build_log_query_string({"source": "honeypot", "path": "/srv/canary/x.log"}) == (
        "source=honeypot"
    )


async def test_log_views_are_saved_per_account_and_work_on_any_honeypot(
    client: Any, db_session_factory: Any
) -> None:
    first, _ = await _make_honeypot(db_session_factory, name="hp-a")
    second, _ = await _make_honeypot(db_session_factory, name="hp-b", company_name="Other")
    async with db_session_factory() as db:
        admin = (await db.execute(select(User).where(User.username == ADMIN_USERNAME))).scalar_one()
        db.add(SavedLogView(user_id=admin.id, name="existing", query_string="source=journal"))
        await db.commit()
    csrf = await _csrf(client, "/honeypots")
    data = {**csrf, "source": "journal", "priority": "err", "search": "sshd"}

    saved = await client.post(
        f"/honeypots/{first}/logs/views", data={**data, "name": "errors"}, follow_redirects=False
    )
    duplicate = await client.post(
        f"/honeypots/{first}/logs/views", data={**data, "name": "errors"}, follow_redirects=False
    )

    assert saved.status_code == 303
    assert saved.headers["location"] == (
        f"/honeypots/{first}/logs?source=journal&priority=err&search=sshd"
    )
    assert duplicate.headers["location"].endswith("view_error=duplicate_name")
    async with db_session_factory() as db:
        views = {
            view.name: view
            for view in (await db.execute(select(SavedLogView))).scalars().all()
        }
    assert views["errors"].query_string == "source=journal&priority=err&search=sshd"

    removed = await client.post(
        f"/honeypots/{second}/logs/views/{views['existing'].id}/delete",
        data=csrf,
        follow_redirects=False,
    )
    assert removed.headers["location"] == f"/honeypots/{second}/logs"
    async with db_session_factory() as db:
        names = list((await db.execute(select(SavedLogView.name))).scalars().all())
    assert names == ["errors"]


async def test_api_saved_log_views(client: Any, db_session_factory: Any) -> None:
    headers = await _admin_token(db_session_factory)
    payload = {"name": "auth", "source": "file", "path": "/var/log/auth.log", "lines": 500}

    created = await client.post("/api/v1/account/saved-log-views", json=payload, headers=headers)
    duplicate = await client.post("/api/v1/account/saved-log-views", json=payload, headers=headers)
    listed = await client.get("/api/v1/account/saved-log-views", headers=headers)
    view_id = created.json()["id"]
    removed = await client.delete(f"/api/v1/account/saved-log-views/{view_id}", headers=headers)
    again = await client.delete(f"/api/v1/account/saved-log-views/{view_id}", headers=headers)

    assert created.status_code == 201
    assert created.json()["query_string"] == "source=file&path=%2Fvar%2Flog%2Fauth.log&lines=500"
    assert duplicate.status_code == 409
    assert [view["name"] for view in listed.json()] == ["auth"]
    assert removed.status_code == 204 and again.status_code == 404
