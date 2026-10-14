"""Update batches (`app.services.update_batches`, `/batches`): the list of
recent batches, a batch's own page with its counts, the way back to the
batch from one honeypot's run, "Run again where it failed", the watchdog
that closes runs a stopped worker left "running", and the REST twins."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.user import User
from app.tasks import jobs
from tests.conftest import create_company


def _csrf_from(response: Any) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def _honeypot(db_session_factory: Any, name: str, company_id: uuid.UUID) -> uuid.UUID:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company_id)],
            name=name,
            host_key_fingerprint="SHA256:test",
        )
        db.add(honeypot)
        await db.commit()
        return honeypot.id


async def _batch(
    db_session_factory: Any,
    company_id: uuid.UUID,
    statuses: dict[str, UpdateRunStatus],
    *,
    minutes_ago: int = 5,
    rolling: bool = False,
) -> tuple[uuid.UUID, dict[str, tuple[uuid.UUID, uuid.UUID]]]:
    """One batch with a run per named honeypot. Returns the batch id and
    {honeypot name: (honeypot id, run id)}."""
    batch_id = uuid.uuid4()
    runs: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    created = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    for position, (name, run_status) in enumerate(statuses.items()):
        honeypot_id = await _honeypot(db_session_factory, name, company_id)
        async with db_session_factory() as db:
            run = HoneypotUpdateRun(
                honeypot_id=honeypot_id,
                strategy=UpgradeStrategy.FULL_UPGRADE,
                status=run_status,
                batch_id=batch_id,
                created_at=created,
                rollout_position=position if rolling else None,
                error=(
                    "apt exited with status 100." if run_status == UpdateRunStatus.FAILED else None
                ),
            )
            db.add(run)
            await db.commit()
            runs[name] = (honeypot_id, run.id)
    return batch_id, runs


async def test_run_page_leads_back_to_its_batch(
    client: AsyncClient, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    batch_id, runs = await _batch(
        db_session_factory,
        company.id,
        {
            "web-b": UpdateRunStatus.RUNNING,
            "web-a": UpdateRunStatus.SUCCEEDED,
            "web-c": UpdateRunStatus.FAILED,
        },
    )
    honeypot_id, run_id = runs["web-b"]

    page = await client.get(f"/honeypots/{honeypot_id}/updates/{run_id}")

    assert page.status_code == 200
    assert f'href="/batches/{batch_id}"' in page.text
    assert "Back to the batch (3 honeypots)" in page.text
    # Every honeypot of the batch is one click away, in name order.
    strip = page.text[page.text.index('class="batch-strip"') :]
    positions = [strip.index(f"/honeypots/{runs[name][0]}/updates/") for name in runs]
    assert positions[1] < positions[0] < positions[2]
    assert 'aria-current="page"' in page.text


async def test_a_run_outside_a_batch_has_no_batch_links(
    client: AsyncClient, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    _batch_id, runs = await _batch(
        db_session_factory, company.id, {"solo": UpdateRunStatus.SUCCEEDED}
    )
    honeypot_id, run_id = runs["solo"]

    page = await client.get(f"/honeypots/{honeypot_id}/updates/{run_id}")

    assert page.status_code == 200
    assert "Back to the batch" not in page.text
    assert 'class="batch-strip"' not in page.text


async def test_batch_page_counts_and_recent_batches(
    client: AsyncClient, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    older, _ = await _batch(
        db_session_factory,
        company.id,
        {"old-1": UpdateRunStatus.SUCCEEDED, "old-2": UpdateRunStatus.SUCCEEDED},
        minutes_ago=600,
    )
    newer, _runs = await _batch(
        db_session_factory,
        company.id,
        {"new-1": UpdateRunStatus.SUCCEEDED, "new-2": UpdateRunStatus.FAILED},
    )

    listing = await client.get("/batches")
    assert listing.status_code == 200
    assert listing.text.index(f"/batches/{newer}") < listing.text.index(f"/batches/{older}")
    assert "1 failed" in listing.text

    page = await client.get(f"/batches/{newer}")
    assert page.status_code == 200
    assert "1 done" in page.text and "1 failed" in page.text and "of 2" in page.text
    assert "apt exited with status 100." in page.text
    # Finished with a failure: it can be run again.
    assert f'action="/batches/{newer}/retry"' in page.text


async def test_old_batch_address_redirects(client: AsyncClient, db_session_factory: Any) -> None:
    company = await create_company(db_session_factory)
    batch_id, _ = await _batch(
        db_session_factory,
        company.id,
        {"a": UpdateRunStatus.SUCCEEDED, "b": UpdateRunStatus.SUCCEEDED},
    )
    moved = await client.get(f"/companies/batches/{batch_id}", follow_redirects=False)
    assert moved.status_code == 308
    assert moved.headers["location"] == f"/batches/{batch_id}"
    missing = await client.get(f"/companies/batches/{uuid.uuid4()}", follow_redirects=False)
    assert missing.status_code == 404


async def test_read_write_user_reaches_the_batch_but_not_another_companys(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    """The batch pages used to sit behind the superadmin-only /companies
    router: a READ_WRITE user starting a bulk update was sent to a 403."""
    mine = await create_company(db_session_factory, name="Mine")
    theirs = await create_company(db_session_factory, name="Theirs")
    own_batch, _ = await _batch(
        db_session_factory,
        mine.id,
        {"m1": UpdateRunStatus.SUCCEEDED, "m2": UpdateRunStatus.FAILED},
    )
    other_batch, _ = await _batch(
        db_session_factory,
        theirs.id,
        {"t1": UpdateRunStatus.SUCCEEDED, "t2": UpdateRunStatus.FAILED},
    )
    await login_as(client, company_id=mine.id, access_level=AccessLevel.READ_WRITE)

    assert (await client.get(f"/batches/{own_batch}")).status_code == 200
    assert (await client.get(f"/batches/{other_batch}")).status_code == 404
    listing = await client.get("/batches")
    assert str(own_batch) in listing.text and str(other_batch) not in listing.text


async def test_read_only_user_has_no_batch_pages(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    batch_id, _ = await _batch(
        db_session_factory,
        company.id,
        {"r1": UpdateRunStatus.SUCCEEDED, "r2": UpdateRunStatus.SUCCEEDED},
    )
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    assert (await client.get("/batches")).status_code == 403
    assert (await client.get(f"/batches/{batch_id}")).status_code == 403


async def test_retry_starts_a_new_batch_on_the_failed_honeypots(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    company = await create_company(db_session_factory)
    batch_id, runs = await _batch(
        db_session_factory,
        company.id,
        {
            "r-ok": UpdateRunStatus.SUCCEEDED,
            "r-bad": UpdateRunStatus.FAILED,
            "r-stopped": UpdateRunStatus.FAILED,
        },
        rolling=True,
    )
    page = await client.get(f"/batches/{batch_id}")

    response = await client.post(
        f"/batches/{batch_id}/retry",
        data={"csrf_token": _csrf_from(page)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    new_batch = uuid.UUID(response.headers["location"].removeprefix("/batches/"))
    async with db_session_factory() as db:
        new_runs = (
            (
                await db.execute(
                    select(HoneypotUpdateRun).where(HoneypotUpdateRun.batch_id == new_batch)
                )
            )
            .scalars()
            .all()
        )
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert {run.honeypot_id for run in new_runs} == {runs["r-bad"][0], runs["r-stopped"][0]}
    # The first batch was rolling, so the retry is too.
    assert all(run.rollout_position is not None for run in new_runs)
    assert "update_batch.retry" in actions


async def test_retry_refused_while_running_or_without_failures(
    client: AsyncClient, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    running, _ = await _batch(
        db_session_factory,
        company.id,
        {"x1": UpdateRunStatus.RUNNING, "x2": UpdateRunStatus.FAILED},
    )
    clean, _ = await _batch(
        db_session_factory,
        company.id,
        {"y1": UpdateRunStatus.SUCCEEDED, "y2": UpdateRunStatus.SUCCEEDED},
    )
    page = await client.get(f"/batches/{clean}")
    assert "/retry" not in page.text
    token = _csrf_from(await client.get("/batches/" + str(running)))
    for batch_id in (running, clean):
        response = await client.post(f"/batches/{batch_id}/retry", data={"csrf_token": token})
        assert response.status_code == 409


async def test_api_lists_and_retries_batches(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    batch_id, _ = await _batch(
        db_session_factory,
        company.id,
        {"api-1": UpdateRunStatus.SUCCEEDED, "api-2": UpdateRunStatus.FAILED},
    )
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw_token}"}

    listing = await client.get("/api/v1/companies/batches", headers=headers)
    assert listing.status_code == 200
    [entry] = listing.json()["batches"]
    assert entry["batch_id"] == str(batch_id)
    assert (entry["total"], entry["succeeded"], entry["failed"]) == (2, 1, 1)

    detail = await client.get(f"/api/v1/companies/batches/{batch_id}", headers=headers)
    assert detail.status_code == 200
    assert [run["status"] for run in detail.json()["runs"]] == ["succeeded", "failed"]

    retried = await client.post(f"/api/v1/companies/batches/{batch_id}/retry", headers=headers)
    assert retried.status_code == 200
    assert retried.json()["batch_id"] != str(batch_id)


async def _run(
    db_session_factory: Any,
    honeypot_id: uuid.UUID,
    *,
    started_hours_ago: float,
    run_status: UpdateRunStatus = UpdateRunStatus.RUNNING,
    rollout_position: int | None = None,
) -> uuid.UUID:
    async with db_session_factory() as db:
        run = HoneypotUpdateRun(
            honeypot_id=honeypot_id,
            strategy=UpgradeStrategy.FULL_UPGRADE,
            status=run_status,
            started_at=datetime.now(UTC) - timedelta(hours=started_hours_ago),
            rollout_position=rollout_position,
            batch_id=uuid.uuid4(),
        )
        db.add(run)
        await db.commit()
        return run.id


async def test_abandoned_runs_are_closed_and_fresh_ones_left_alone(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    honeypot_id = await _honeypot(db_session_factory, "stuck", company.id)
    stale = await _run(db_session_factory, honeypot_id, started_hours_ago=30)
    rolling = await _run(db_session_factory, honeypot_id, started_hours_ago=30, rollout_position=0)
    fresh = await _run(db_session_factory, honeypot_id, started_hours_ago=0.1)
    done = await _run(
        db_session_factory, honeypot_id, started_hours_ago=30, run_status=UpdateRunStatus.SUCCEEDED
    )
    released: list[str] = []
    monkeypatch.setattr(jobs.finish_update_run, "delay", lambda run_id: released.append(run_id))

    closed = await jobs._fail_stale_update_runs()
    again = await jobs._fail_stale_update_runs()

    async with db_session_factory() as db:
        all_runs = (await db.execute(select(HoneypotUpdateRun))).scalars().all()
        by_id = {run.id: run for run in all_runs}
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert (closed, again) == (2, 0)
    for run_id in (stale, rolling):
        assert by_id[run_id].status == UpdateRunStatus.FAILED
        assert by_id[run_id].error == jobs.STALE_RUN_ERROR
        assert by_id[run_id].finished_at is not None
    assert by_id[fresh].status == UpdateRunStatus.RUNNING
    assert by_id[done].status == UpdateRunStatus.SUCCEEDED
    # Only the rolling batch has anything waiting on it.
    assert released == [str(rolling)]
    assert actions.count("honeypot_update_runs.reap") == 1
