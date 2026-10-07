"""Changing a honeypot's MAC address: the address itself, the boot-time
unit that applies it, the downloaded manufacturer list it can be picked
from, and the three places it is offered (Config tab, Initialize,
Settings)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.access_level import AccessLevel
from app.db.models.app_settings import AppSettings
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.mac_vendor import MacVendor
from app.services import mac_vendors
from app.ssh import mac_address as mac
from app.ssh.exec import CommandResult
from app.ssh.initialize import build_initialize_command
from app.ssh.platform_detect import DetectedPlatform
from tests.conftest import create_company

_LIST = (
    "000000\tOfficially Xerox\n"
    "00000C\tCisco Systems, Inc\n"
    "000142\tCisco Systems, Inc\n"
    "001B63\tApple, Inc.\n"
    "00:0C:29  VMware, Inc.\n"
    "01005E\tIANA multicast\n"
    "# a comment\n"
    "\n"
    "not a prefix line at all\n" + "".join(f"AA00{i:02X}\tFiller Maker {i}\n" for i in range(12))
)


# --- The address ---------------------------------------------------------


@pytest.mark.parametrize(
    "typed",
    ["00:1B:63:84:45:E6", "00-1b-63-84-45-e6", "001b.6384.45e6", " 001B638445E6 "],
)
def test_a_mac_address_is_accepted_in_the_usual_spellings(typed: str) -> None:
    assert mac.normalize_mac(typed) == "00:1b:63:84:45:e6"


@pytest.mark.parametrize(
    "typed",
    [
        "",
        "00:1b:63:84:45",  # five bytes
        "00:1b:63:84:45:e6:01",
        "zz:1b:63:84:45:e6",
        "00:00:00:00:00:00",
        "01:00:5e:00:00:01",  # multicast
        "00:1b:63:84:45:e6; reboot",
    ],
)
def test_what_cannot_be_an_interface_address_is_refused(typed: str) -> None:
    with pytest.raises(mac.InvalidMacAddressError):
        mac.normalize_mac(typed)


# --- The unit on the honeypot --------------------------------------------


def test_setting_an_address_writes_a_unit_that_acts_before_the_network() -> None:
    command = mac.build_set_command("00:1b:63:84:45:e6")
    assert f"cat > {mac.UNIT_PATH} <<HONEYPOTSHELF_MAC_UNIT" in command
    assert "Before=network-pre.target" in command
    assert "link set dev $mac_iface address 00:1b:63:84:45:e6" in command
    assert "# honeypotshelf-mac: 00:1b:63:84:45:e6" in command
    assert f"systemctl enable {mac.UNIT_NAME}" in command
    # Never changes the running interface.
    assert "ip link set" not in command.replace("$mac_ip link set", "")
    # A read-only root would lose the unit at the very boot it is for.
    assert "!= overlay ] || exit 4" in command
    # Root when already root, sudo otherwise; the script never stays behind.
    assert "sudo -n bash /tmp/.honeypotshelf-mac.sh" in command
    assert command.rstrip().endswith("exit $status")


def test_only_a_normalized_address_ever_reaches_the_script() -> None:
    with pytest.raises(mac.InvalidMacAddressError):
        mac.unit_install_lines("00:1B:63:84:45:E6'; reboot #")


def test_returning_to_the_hardware_address_removes_the_unit() -> None:
    command = mac.build_reset_command()
    assert f"systemctl disable {mac.UNIT_NAME}" in command
    assert f"rm -f {mac.UNIT_PATH}" in command


def test_status_tells_a_pending_change_from_one_in_effect() -> None:
    pending = mac.parse_status(
        "IFACE=eth0\nCURRENT=b8:27:eb:12:34:56\nCONFIGURED=00:1b:63:84:45:e6\nROOTFS=ext4\n"
    )
    assert pending.interface == "eth0" and pending.pending and not pending.readonly_root
    applied = mac.parse_status(
        "IFACE=eth0\nCURRENT=00:1b:63:84:45:e6\nCONFIGURED=00:1b:63:84:45:e6\nROOTFS=overlay\n"
    )
    assert not applied.pending and applied.readonly_root
    untouched = mac.parse_status("IFACE=eth0\nCURRENT=b8:27:eb:12:34:56\nCONFIGURED=\nROOTFS=ext4")
    assert untouched.configured is None and not untouched.pending


@pytest.mark.asyncio
async def test_a_refusal_is_explained(monkeypatch: Any) -> None:
    async def _refuse(*_args: Any, **_kwargs: Any) -> CommandResult:
        return CommandResult(exit_status=4, output="")

    monkeypatch.setattr(mac, "run_command", _refuse)
    with pytest.raises(mac.MacAddressError, match="read-only"):
        await mac.set_mac_address(Honeypot(name="hp"), None, "00:1b:63:84:45:e6", 10)


def test_initialize_sets_the_address_last_before_the_reboot() -> None:
    platform = DetectedPlatform(
        distro="debian", codename="trixie", label="Debian 13 (trixie)", has_raspi_config=False
    )
    without = build_initialize_command(device_name="hp1", service_user="pi", platform=platform)
    assert mac.UNIT_NAME not in without

    script = build_initialize_command(
        device_name="hp1", service_user="pi", platform=platform, mac_address="00:1b:63:84:45:e6"
    )
    assert "address 00:1b:63:84:45:e6" in script
    # After the SSH port move, before the reboot that applies it.
    assert script.index("systemctl restart ssh") < script.index(mac.UNIT_PATH)
    assert script.index(mac.UNIT_PATH) < script.index("(sleep 2; reboot)")


# --- The manufacturer list -----------------------------------------------


def test_the_list_format_is_one_prefix_and_name_per_line() -> None:
    vendors = mac_vendors.parse_vendor_list(_LIST)
    assert vendors["000000"] == "Officially Xerox"
    assert vendors["00000C"] == vendors["000142"] == "Cisco Systems, Inc"
    assert vendors["000C29"] == "VMware, Inc."  # separators and spaces are fine
    assert len(vendors) == 18  # comment, blank and junk lines skipped


async def _load_list(db_session_factory: Any, monkeypatch: Any, text: str = _LIST) -> int:
    async def _download(_url: str) -> str:
        return text

    monkeypatch.setattr(mac_vendors, "_download", _download)
    async with db_session_factory() as db:
        settings = await db.get(AppSettings, 1)
        if settings is None:
            settings = AppSettings(id=1)
            db.add(settings)
        settings.mac_vendor_list_url = "https://lists.example.com/mac.txt"
        await db.commit()
        return await mac_vendors.refresh_vendor_list(db, settings)


@pytest.mark.asyncio
async def test_downloading_replaces_the_stored_list(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    assert await _load_list(db_session_factory, monkeypatch) == 18
    assert await _load_list(db_session_factory, monkeypatch, _LIST + "ABCDEF\tNew Maker\n") == 19
    async with db_session_factory() as db:
        settings = await db.get(AppSettings, 1)
        assert settings is not None
        assert settings.mac_vendor_list_updated_at is not None
        assert settings.mac_vendor_list_error is None
        assert await mac_vendors.vendor_of(db, "ab:cd:ef:00:00:01") == "New Maker"


@pytest.mark.asyncio
async def test_a_page_that_is_not_a_list_replaces_nothing(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    await _load_list(db_session_factory, monkeypatch)
    with pytest.raises(mac_vendors.MacVendorListError, match="did not return a list"):
        await _load_list(db_session_factory, monkeypatch, "<html>404 Not Found</html>")
    async with db_session_factory() as db:
        assert await mac_vendors.vendor_count(db) == 18
        settings = await db.get(AppSettings, 1)
        assert settings is not None and "did not return a list" in settings.mac_vendor_list_error


def test_the_list_is_fetched_again_once_its_interval_has_passed() -> None:
    now = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    settings = AppSettings(mac_vendor_refresh_interval_hours=24)
    assert not mac_vendors.is_due(settings, now=now)  # no address: nothing to fetch
    settings.mac_vendor_list_url = "https://lists.example.com/mac.txt"
    assert mac_vendors.is_due(settings, now=now)  # never tried
    settings.mac_vendor_list_attempted_at = now - timedelta(hours=23)
    assert not mac_vendors.is_due(settings, now=now)
    settings.mac_vendor_list_attempted_at = now - timedelta(hours=25)
    assert mac_vendors.is_due(settings, now=now)


@pytest.mark.asyncio
async def test_an_address_is_drawn_from_the_picked_manufacturer(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    await _load_list(db_session_factory, monkeypatch)
    async with db_session_factory() as db:
        found = await mac_vendors.search_vendors(db, "cisco")
        assert found == [("Cisco Systems, Inc", 2)]
        # Nothing typed yet: the drop-down opens with the biggest manufacturers.
        opened = await mac_vendors.search_vendors(db, "")
        assert opened[0] == ("Cisco Systems, Inc", 2) and len(opened) == 17

        drawn = {await mac_vendors.generate_address(db, "Cisco Systems, Inc") for _ in range(20)}
        assert len(drawn) > 1
        for address in drawn:
            assert address is not None and address[:8] in {"00:00:0c", "00:01:42"}
            assert mac.normalize_mac(address) == address

        # A multicast prefix in the list is never handed out.
        assert await mac_vendors.generate_address(db, "IANA multicast") is None
        assert await mac_vendors.generate_address(db, "Nobody Ltd") is None


@pytest.mark.asyncio
async def test_a_private_address_is_not_fetched_from(monkeypatch: Any) -> None:
    for url in ("http://127.0.0.1/list.txt", "http://10.0.0.5/list.txt", "ftp://example.com/l"):
        with pytest.raises(mac_vendors.MacVendorListError, match="public http"):
            mac_vendors.validate_list_url(url)


# --- Pages ---------------------------------------------------------------


async def _honeypot(db_session_factory: Any, company_id: uuid.UUID | None = None) -> uuid.UUID:
    if company_id is None:
        company_id = (await create_company(db_session_factory)).id
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company_id)],
            name="hp-mac",
            ip_address="10.4.4.4",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        return honeypot.id


_STATE = {
    "ok": True,
    "interface": "eth0",
    "current": "b8:27:eb:12:34:56",
    "configured": "00:1b:63:84:45:e6",
    "pending": True,
    "readonly_root": False,
}
_TASK = "app.tasks.jobs.honeypot_mac_address"


@pytest.mark.asyncio
async def test_config_tab_shows_and_sets_the_address(
    client: Any, db_session_factory: Any, celery_calls: Any, monkeypatch: Any
) -> None:
    await _load_list(db_session_factory, monkeypatch)
    honeypot_id = await _honeypot(db_session_factory)
    celery_calls.result_for[_TASK] = _STATE

    tab = (await client.get(f"/honeypots/{honeypot_id}/config")).text
    assert f'hx-get="/honeypots/{honeypot_id}/config/mac"' in tab

    panel = (await client.get(f"/honeypots/{honeypot_id}/config/mac")).text
    assert "b8:27:eb:12:34:56" in panel and "eth0" in panel
    assert "after a reboot" in panel
    assert "Apple, Inc." in panel  # the configured address's manufacturer
    assert 'form="mac-vendor-search"' in panel and 'id="mac-vendor-search"' in panel
    # The manufacturer picker is a drop-down with a search box.
    assert 'role="combobox"' in panel and "data-combo-list hidden" in panel
    assert "focus from:#mac_vendor_q" in panel

    csrf = client.cookies.get("csrftoken")
    refused = await client.post(
        f"/honeypots/{honeypot_id}/config/mac",
        data={"csrf_token": csrf, "mac_address": "01:00:5e:00:00:01"},
    )
    assert "multicast" in refused.text
    assert not [c for c in celery_calls if c[0] == _TASK and c[2].get("mac")]

    saved = await client.post(
        f"/honeypots/{honeypot_id}/config/mac",
        data={"csrf_token": csrf, "mac_address": "00-1B-63-84-45-E6", "mac_vendor": "Apple, Inc."},
    )
    assert "uses the new address from its next reboot" in saved.text
    assert f'href="/honeypots/{honeypot_id}/power/reboot"' in saved.text
    sets = [c for c in celery_calls if c[0] == _TASK and c[2].get("mac")]
    assert sets[-1][2] == {"mac": "00:1b:63:84:45:e6", "vendor": "Apple, Inc."}

    reset = await client.post(
        f"/honeypots/{honeypot_id}/config/mac/reset", data={"csrf_token": csrf}
    )
    assert "hardware address again" in reset.text
    assert [c for c in celery_calls if c[0] == _TASK and c[2].get("reset")]


@pytest.mark.asyncio
async def test_a_typed_address_is_not_credited_to_the_manufacturer_picked_before(
    client: Any, db_session_factory: Any, celery_calls: Any, monkeypatch: Any
) -> None:
    await _load_list(db_session_factory, monkeypatch)
    honeypot_id = await _honeypot(db_session_factory)
    celery_calls.result_for[_TASK] = _STATE
    await client.get(f"/honeypots/{honeypot_id}/config/mac")  # sets the CSRF cookie
    await client.post(
        f"/honeypots/{honeypot_id}/config/mac",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "mac_address": "00:00:0c:11:22:33",
            "mac_vendor": "Apple, Inc.",
        },
    )
    sets = [c for c in celery_calls if c[0] == _TASK and c[2].get("mac")]
    assert sets[-1][2] == {"mac": "00:00:0c:11:22:33", "vendor": None}


@pytest.mark.asyncio
async def test_an_account_that_only_reads_the_honeypot_cannot_touch_its_address(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    """Writes one company, only reads the honeypot's."""
    from app.db.models.company_membership import CompanyMembership

    own = await create_company(db_session_factory, name="Own")
    other = await create_company(db_session_factory, name="Other")
    honeypot_id = await _honeypot(db_session_factory, other.id)
    user = await login_as(client, company_id=own.id, access_level=AccessLevel.READ_WRITE)
    async with db_session_factory() as db:
        db.add(
            CompanyMembership(user_id=user.id, company_id=other.id, access_level=AccessLevel.READ)
        )
        await db.commit()

    assert (await client.get(f"/honeypots/{honeypot_id}/config/mac")).status_code == 403
    page = await client.get("/honeypots")
    blocked = await client.post(
        f"/honeypots/{honeypot_id}/config/mac",
        data={
            "csrf_token": page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0],
            "mac_address": "00:1b:63:84:45:e6",
        },
    )
    assert blocked.status_code == 403
    assert not [c for c in celery_calls if c[0] == _TASK]


@pytest.mark.asyncio
async def test_picker_finds_a_manufacturer_and_draws_an_address(
    client: Any, db_session_factory: Any, monkeypatch: Any
) -> None:
    await _load_list(db_session_factory, monkeypatch)
    results = (await client.get("/mac-vendors/search", params={"q": "cisco"})).text
    assert "Cisco Systems, Inc" in results and "2 prefixes" in results
    assert 'hx-get="/mac-vendors/generate"' in results
    assert 'role="option" data-combo-value="Cisco Systems, Inc"' in results
    assert "No manufacturer" in (await client.get("/mac-vendors/search?q=zzzz")).text

    field = (
        await client.get("/mac-vendors/generate", params={"vendor": "Cisco Systems, Inc"})
    ).text
    value = field.split('name="mac_address"', 1)[1].split('value="', 1)[1].split('"', 1)[0]
    assert value[:8] in {"00:00:0c", "00:01:42"}
    assert 'name="mac_vendor" value="Cisco Systems, Inc"' in field
    assert "Draw another" in field


@pytest.mark.asyncio
async def test_without_a_list_the_address_can_still_be_typed(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    honeypot_id = await _honeypot(db_session_factory)
    celery_calls.result_for[_TASK] = {**_STATE, "configured": None, "pending": False}
    panel = (await client.get(f"/honeypots/{honeypot_id}/config/mac")).text
    assert 'name="mac_address"' in panel
    assert "can only be typed in" in panel
    assert 'id="mac_vendor_q"' not in panel

    initialize = (await client.get("/initialize")).text
    assert 'name="mac_address"' in initialize and "can only be typed in" in initialize


@pytest.mark.asyncio
async def test_initialize_refuses_a_bad_address_and_keeps_a_good_one(client: Any) -> None:
    from app.web.routes.initialize import PENDING_RUNS

    form = {
        "csrf_token": client.cookies.get("csrftoken") or "",
        "ip_address": "10.5.5.5",
        "device_name": "hp-new",
        "username": "root",
    }
    page = await client.get("/initialize")
    form["csrf_token"] = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]

    bad = await client.post("/initialize", data={**form, "mac_address": "not-a-mac"})
    assert "six bytes" in bad.text

    good = await client.post("/initialize", data={**form, "mac_address": "00-1B-63-84-45-E6"})
    assert good.status_code == 303
    run = PENDING_RUNS[good.headers["location"].rsplit("/", 1)[1]]
    assert run.mac_address == "00:1b:63:84:45:e6"

    none = await client.post("/initialize", data=form)
    assert PENDING_RUNS[none.headers["location"].rsplit("/", 1)[1]].mac_address is None


@pytest.mark.asyncio
async def test_settings_hold_the_list_address_and_interval(
    client: Any, db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr(mac_vendors, "validate_webhook_url", lambda _url: None)

    async def _download(_url: str) -> str:
        return _LIST

    monkeypatch.setattr(mac_vendors, "_download", _download)

    page = (await client.get("/settings", params={"tab": "integrations"})).text
    assert 'id="mac-vendors"' in page and "Last downloaded:" in page
    assert 'name="mac_vendor_list_url"' in page and 'value=""' in page  # nothing by default
    assert "/settings/mac-vendors/refresh" not in page  # nothing to download yet
    csrf = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]

    too_often = await client.post(
        "/settings/mac-vendors",
        data={
            "csrf_token": csrf,
            "mac_vendor_list_url": "https://lists.example.com/mac.txt",
            "mac_vendor_refresh_interval_hours": "0",
        },
    )
    assert "between 1 and 8760" in too_often.text

    saved = await client.post(
        "/settings/mac-vendors",
        data={
            "csrf_token": csrf,
            "mac_vendor_list_url": "https://lists.example.com/mac.txt",
            "mac_vendor_refresh_interval_hours": "24",
        },
    )
    assert saved.status_code == 303
    downloaded = await client.post("/settings/mac-vendors/refresh", data={"csrf_token": csrf})
    assert downloaded.status_code == 303

    async with db_session_factory() as db:
        settings = (await db.execute(select(AppSettings))).scalar_one()
        assert settings.mac_vendor_list_url == "https://lists.example.com/mac.txt"
        assert settings.mac_vendor_refresh_interval_hours == 24
        assert (await db.execute(select(MacVendor))).scalars().first() is not None
    page = (await client.get("/settings", params={"tab": "integrations"})).text
    assert "18 prefixes" in page


@pytest.mark.asyncio
async def test_the_hourly_job_downloads_only_when_due(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    from app.tasks import jobs

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    assert await jobs._refresh_mac_vendor_list(only_if_due=True) == {"ok": True, "skipped": True}

    await _load_list(db_session_factory, monkeypatch)  # sets an address, downloads once
    assert await jobs._refresh_mac_vendor_list(only_if_due=True) == {"ok": True, "skipped": True}
    assert await jobs._refresh_mac_vendor_list(only_if_due=False) == {"ok": True, "count": 18}
