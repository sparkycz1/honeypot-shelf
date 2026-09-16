"""`scripts/setup.py`'s `_vpn_overlay_running` — regression guard for a
real bug found live: checking `docker ps` (running containers only)
meant a merely-*stopped* VPN sidecar (crashed, or just not yet connected
right after the operator first configured it) silently dropped
`docker-compose.vpn.yml` from every subsequent `up -d` — with no error,
just "not running" the next time Settings -> VPN tried to reach it.
`docker ps -a` (existing, running or not) is what actually answers "is
this part of the deployment" — the same fix scripts/upgrade.sh needed
for the identical check."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from scripts.setup import _vpn_overlay_running


def test_vpn_overlay_running_checks_all_containers_not_just_running_ones():
    fake_result = MagicMock(stdout="honeypotshelf-vpn-1\n")
    with patch("scripts.setup.subprocess.run", return_value=fake_result) as mock_run:
        assert _vpn_overlay_running("/usr/bin/docker") is True

    args = mock_run.call_args[0][0]
    assert args[:3] == ["/usr/bin/docker", "ps", "-a"]


def test_vpn_overlay_running_false_when_no_container_found():
    fake_result = MagicMock(stdout="")
    with patch("scripts.setup.subprocess.run", return_value=fake_result):
        assert _vpn_overlay_running("/usr/bin/docker") is False
