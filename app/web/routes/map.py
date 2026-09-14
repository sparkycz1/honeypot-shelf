"""The Map page — where honeypot alerts are coming from, geographically.
Company-scoped exactly like the Dashboard (`app.web.routes.dashboard`):
every user sees the sum across every company they have access to, a
superadmin sees every company. Reads only the geo columns
`app.tasks.jobs._poll_honeypot_canary_log` already resolved and stored on
`HoneypotEvent` at ingestion time (see `app.services.geoip`'s module
docstring for why) — this route does no GeoIP lookups of its own.

**Deliberately only ever plots a public source IP** — `src_latitude`/
`src_longitude`/`src_country_code` are `None` for any event whose `src_ip`
was private/reserved/malformed, or wasn't resolved at all (GeoIP not
configured, or ingested before it was) — see `app.services.geoip`. Those
rows are simply excluded here, not shown as "unknown location" dots; a
company's own internal scanning/testing traffic hitting its own honeypot
from inside its LAN has no real-world location to plot.

**No literal coastlines** — this SVG world "map" is a plain Plate Carrée
graticule (latitude/longitude grid lines), not a political map: building
or vendoring an actual coastline outline was out of scope for a first cut
(see `app.services.geoip_display`'s projection docstring). Dots still land
at the geographically correct position; there's just no landmass silhouette
drawn under them yet.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.auth.scope import visible_company_ids
from app.db.models.company import Company
from app.db.models.geoip_database import SINGLETON_ID as GEOIP_SINGLETON_ID
from app.db.models.geoip_database import GeoipDatabase
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services.geoip_display import country_flag, dot_radius, project
from app.web.templating import templates

router = APIRouter()

_TOP_COUNTRIES_LIMIT = 20
_MAP_WIDTH = 760
_MAP_HEIGHT = 380


@dataclass(frozen=True)
class MapDot:
    x: float
    y: float
    radius: float
    label: str


@router.get("/map")
async def map_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> object:
    company_ids = visible_company_ids(user)
    # `None` for a superadmin means "every company" (see
    # `visible_company_ids`'s own docstring) - including a honeypot
    # attached to zero companies, same as the Dashboard's own
    # `honeypot_query` - so this filter is only ever added at all for a
    # non-superadmin.
    scope_filters = (
        [HoneypotEvent.honeypot.has(Honeypot.companies.any(Company.id.in_(company_ids)))]
        if company_ids is not None
        else []
    )

    location_rows = (
        await db.execute(
            select(
                HoneypotEvent.src_country_code,
                HoneypotEvent.src_country_name,
                HoneypotEvent.src_city_name,
                HoneypotEvent.src_latitude,
                HoneypotEvent.src_longitude,
                func.count().label("event_count"),
            )
            .where(
                *scope_filters,
                HoneypotEvent.src_latitude.is_not(None),
                HoneypotEvent.src_longitude.is_not(None),
            )
            .group_by(
                HoneypotEvent.src_country_code,
                HoneypotEvent.src_country_name,
                HoneypotEvent.src_city_name,
                HoneypotEvent.src_latitude,
                HoneypotEvent.src_longitude,
            )
        )
    ).all()

    country_rows = (
        await db.execute(
            select(
                HoneypotEvent.src_country_code,
                HoneypotEvent.src_country_name,
                func.count().label("event_count"),
            )
            .where(*scope_filters, HoneypotEvent.src_country_code.is_not(None))
            .group_by(HoneypotEvent.src_country_code, HoneypotEvent.src_country_name)
            .order_by(func.count().desc())
            .limit(_TOP_COUNTRIES_LIMIT)
        )
    ).all()

    max_count = max((row.event_count for row in location_rows), default=0)
    dots = [
        MapDot(
            *project(row.src_latitude, row.src_longitude, _MAP_WIDTH, _MAP_HEIGHT),
            radius=dot_radius(row.event_count, max_count),
            label=(
                f"{row.src_city_name + ', ' if row.src_city_name else ''}"
                f"{row.src_country_name or row.src_country_code}: {row.event_count}"
            ),
        )
        for row in location_rows
    ]

    top_countries = [
        {
            "code": row.src_country_code,
            "name": row.src_country_name or row.src_country_code,
            "flag": country_flag(row.src_country_code),
            "count": row.event_count,
        }
        for row in country_rows
    ]

    geoip_status = await db.get(GeoipDatabase, GEOIP_SINGLETON_ID)
    geoip_ready = geoip_status is not None and geoip_status.mmdb_data is not None

    total_events_result = await db.execute(
        select(func.count()).select_from(HoneypotEvent).where(*scope_filters)
    )
    total_events = total_events_result.scalar_one()
    located_events = sum(row.event_count for row in location_rows)

    return templates.TemplateResponse(
        request,
        "map/index.html",
        {
            "dots": dots,
            "top_countries": top_countries,
            "map_width": _MAP_WIDTH,
            "map_height": _MAP_HEIGHT,
            "geoip_ready": geoip_ready,
            "total_events": total_events,
            "located_events": located_events,
            "is_superadmin": user.is_superadmin,
        },
    )
