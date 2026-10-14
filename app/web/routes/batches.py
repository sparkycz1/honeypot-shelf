"""Update batches (`/batches`) — the runs one "run update" on several
honeypots started together: the list of recent batches, one batch's page
(with its live-updating status fragment) and "Run again where it failed".
See `app.services.update_batches`; the REST twin lives in
`app/web/routes/api_v1.py` (`/api/v1/companies/batches...`). Ported from
debcontrol's `/machine-groups/batches`.

Open to any account that may write at all (`require_write`), each batch
narrowed to the honeypots that account may write — the same rule as a
honeypot's own Updates tab. These pages used to live under `/companies`,
which is superadmin-only, so a `READ_WRITE` user starting an update on
several honeypots from the honeypot list landed on a 403; the old address
still redirects here (`app/web/routes/companies.py`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_write
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.honeypot_update_run import HoneypotUpdateRun
from app.db.models.user import User
from app.db.session import get_db
from app.services import update_batches
from app.web.templating import templates

router = APIRouter(prefix="/batches", dependencies=[Depends(require_write)])


@router.get("")
async def update_batch_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The newest update batches with how each stands — the way back to a
    batch after leaving its page."""
    return templates.TemplateResponse(
        request,
        "batches/list.html",
        {"batches": await update_batches.recent_batches(db, current_user)},
    )


def _batch_context(
    batch_id: uuid.UUID, runs: list[HoneypotUpdateRun], csrf_token: str, **extra: object
) -> dict[str, object]:
    counts = update_batches.count_runs(runs)
    return {
        "runs": runs,
        "batch_id": batch_id,
        "counts": counts,
        "has_pending": counts.unfinished > 0,
        # "Run again on the failed ones", once nothing is running any more.
        # Every run listed is already on a honeypot this account may write.
        "can_retry": counts.failed > 0 and counts.unfinished == 0,
        "csrf_token": csrf_token,
        **extra,
    }


@router.get("/{batch_id}")
async def update_batch_detail(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skipped: int = 0,
) -> Response:
    runs = await update_batches.visible_batch_runs(db, current_user, batch_id)
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "batches/detail.html",
        _batch_context(batch_id, runs, csrf_token, skipped=skipped),
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{batch_id}/status")
async def update_batch_status(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    runs = await update_batches.visible_batch_runs(db, current_user, batch_id)
    csrf_token, _new_cookie = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/update_batch_status.html",
        _batch_context(batch_id, runs, csrf_token),
    )


@router.post("/{batch_id}/retry", dependencies=[Depends(verify_csrf)])
async def retry_update_batch(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Run the batch again on the honeypots where it failed."""
    try:
        new_batch_id, skipped = await update_batches.retry_failed(db, current_user, batch_id)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found."
        ) from exc
    except update_batches.BatchNotFinishedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="The batch is still running."
        ) from exc
    except update_batches.NothingFailedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="No run of this batch failed."
        ) from exc
    await log_event(
        db,
        request=request,
        action="update_batch.retry",
        summary="Ran an update batch again on the honeypots where it failed",
        details={
            "batch_id": str(new_batch_id),
            "retry_of_batch_id": str(batch_id),
            "skipped": skipped,
        },
    )
    # Built from the id `trigger_updates` generated, never from the request.
    redirect_url = f"/batches/{new_batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
