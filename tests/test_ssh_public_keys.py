"""Superadmin personal SSH public keys — parsing/validation
(`app.auth.ssh_keys`), the idempotent-append shell builder
(`app.ssh.authorized_keys`), and the account-page routes that tie them
together (`app/web/routes/auth.py`'s `/account/ssh-keys*`)."""

from __future__ import annotations

import pytest

from app.auth.ssh_keys import InvalidSshPublicKeyError, parse_ssh_public_keys
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.user import AccessLevel
from app.ssh.authorized_keys import build_authorized_keys_append_command
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio

_KEY_A = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJnUyBtmK6VX3dwD/W4wtBOuCSSvlrE6vilNRvPhSlwj alice@laptop"
)
_KEY_B = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7dQ3c3FcIpTozZFtzE/dD2ZWBs92ke0dTUvhJoKq2W bob@laptop"
)


# --- parse_ssh_public_keys -------------------------------------------------


def test_parse_ssh_public_keys_accepts_a_single_valid_key():
    assert parse_ssh_public_keys(_KEY_A) == [_KEY_A]


def test_parse_ssh_public_keys_accepts_multiple_keys_one_per_line():
    raw = f"{_KEY_A}\n{_KEY_B}\n"
    assert parse_ssh_public_keys(raw) == [_KEY_A, _KEY_B]


def test_parse_ssh_public_keys_drops_blank_lines_and_comments():
    raw = f"\n# my laptop\n{_KEY_A}\n\n#another comment\n{_KEY_B}\n"
    assert parse_ssh_public_keys(raw) == [_KEY_A, _KEY_B]


def test_parse_ssh_public_keys_empty_input_returns_empty_list():
    assert parse_ssh_public_keys("") == []
    assert parse_ssh_public_keys("   \n  \n") == []


def test_parse_ssh_public_keys_rejects_malformed_input():
    with pytest.raises(InvalidSshPublicKeyError):
        parse_ssh_public_keys("not a key")


def test_parse_ssh_public_keys_never_partially_accepts():
    """A typo in the second of two keys must reject the whole batch, not
    silently save only the first one."""
    with pytest.raises(InvalidSshPublicKeyError):
        parse_ssh_public_keys(f"{_KEY_A}\nnot a key")


# --- build_authorized_keys_append_command ----------------------------------


def test_build_authorized_keys_append_command_is_idempotent_per_key():
    command = build_authorized_keys_append_command("pi", [_KEY_A, _KEY_B])
    assert command.count("grep -qxF") == 2
    assert _KEY_A in command
    assert _KEY_B in command
    assert "getent passwd" in command
    assert "chmod 600" in command
    assert "chown -R" in command


def test_build_authorized_keys_append_command_quotes_the_username():
    command = build_authorized_keys_append_command("pi; rm -rf /", [_KEY_A])
    assert "'pi; rm -rf /'" in command


def test_build_authorized_keys_append_command_with_no_keys_still_prepares_the_dir():
    command = build_authorized_keys_append_command("pi", [])
    assert "grep -qxF" not in command
    assert "install -d" in command


# --- /account/ssh-keys and /account/ssh-keys/push --------------------------


async def test_account_page_hides_ssh_keys_section_for_a_company_user(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ_WRITE)
    response = await client.get("/account")
    assert response.status_code == 200
    assert 'name="ssh_public_keys"' not in response.text


async def test_update_own_ssh_keys_saves_valid_keys(client):
    form = await client.get("/account")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/account/ssh-keys",
        data={"ssh_public_keys": f"{_KEY_A}\n{_KEY_B}", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303

    page = await client.get("/account")
    assert _KEY_A in page.text
    assert _KEY_B in page.text


async def test_update_own_ssh_keys_rejects_malformed_input(client):
    form = await client.get("/account")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/account/ssh-keys",
        data={"ssh_public_keys": "definitely not a key", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Not a valid SSH public key" in response.text


async def test_push_own_ssh_keys_requires_superadmin(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ_WRITE)
    form = await client.get("/account")
    csrf_token = _csrf_from(form)

    response = await client.post("/account/ssh-keys/push", data={"csrf_token": csrf_token})
    assert response.status_code == 403


async def test_push_own_ssh_keys_dispatches_to_every_pinned_honeypot(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        db.add(
            Honeypot(
                companies=[await db.get(Company, company.id)],
                name="acme-honey1",
                host_key_fingerprint="SHA256:fakefingerprint",
            )
        )
        # Never pinned yet — must not be included in the push.
        db.add(Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey2"))
        await db.commit()

    form = await client.get("/account")
    csrf_token = _csrf_from(form)

    response = await client.post("/account/ssh-keys/push", data={"csrf_token": csrf_token})
    assert response.status_code == 200
    assert "Pushed to 1/1" in response.text
    assert "app.tasks.jobs.push_superadmin_ssh_keys" in celery_calls.names


async def test_push_own_ssh_keys_with_no_pinned_honeypots_shows_an_error(client):
    form = await client.get("/account")
    csrf_token = _csrf_from(form)

    response = await client.post("/account/ssh-keys/push", data={"csrf_token": csrf_token})
    assert response.status_code == 200
    assert "No honeypots have a pinned host key yet." in response.text


def _csrf_from(response) -> str:
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)
