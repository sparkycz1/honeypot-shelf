"""The manufacturer picker next to a MAC address field (the honeypot
Config tab and Initialize): find a manufacturer in the downloaded list,
and make up an address of theirs. Two htmx fragments, nothing stored —
the address only becomes anything once the form around it is submitted.

For accounts that can change a honeypot at all (`require_write`); the
list itself is the same for everyone and names no honeypot or company.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_write
from app.db.session import get_db
from app.services import mac_vendors
from app.web.templating import templates

router = APIRouter(prefix="/mac-vendors", dependencies=[Depends(require_write)])


@router.get("/search")
async def search(request: Request, q: str = "", db: AsyncSession = Depends(get_db)) -> Response:
    query = q.strip()[:100]
    return templates.TemplateResponse(
        request,
        "partials/_mac_vendor_results.html",
        {"query": query, "vendors": await mac_vendors.search_vendors(db, query)},
    )


@router.get("/generate")
async def generate(
    request: Request, vendor: str = "", db: AsyncSession = Depends(get_db)
) -> Response:
    """A fresh address of `vendor`, as the MAC address field itself —
    swapped in place of the one on the page. Asking again draws another."""
    vendor = vendor.strip()[:255]
    address = await mac_vendors.generate_address(db, vendor)
    return templates.TemplateResponse(
        request,
        "partials/_mac_address_field.html",
        {
            "mac_address": address or "",
            "mac_vendor": vendor if address else "",
            "mac_vendor_unknown": address is None,
        },
    )
