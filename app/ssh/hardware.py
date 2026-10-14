"""What a honeypot's hardware says it is: vendor, model, serial number and
whether it is a virtual machine (the facts' HARDWARE section; see
`app.services.hardware_inventory`). Ported from debcontrol, plus the
Raspberry Pi, which has no DMI/SMBIOS firmware tables: its model and
serial number come from the device tree (`/proc/device-tree/model`,
`/proc/device-tree/serial-number`, or `/proc/cpuinfo`'s `Serial`)."""

from __future__ import annotations

from typing import TypedDict

# Firmware fields vendors leave unfilled.
_PLACEHOLDERS = frozenset(
    {
        "",
        "0",
        "none",
        "n/a",
        "na",
        "default string",
        "not specified",
        "not applicable",
        "system product name",
        "system manufacturer",
        "system serial number",
        "to be filled by o.e.m.",
        "o.e.m.",
        "unknown",
        "123456789",
    }
)

_KEYS = ("vendor", "model", "serial", "dt_model", "dt_serial")

# The facts' HARDWARE section — one `key=value` line each, empty when the
# source does not exist. DMI vendor and model are world-readable, the DMI
# serial needs root (`dmidecode`, already in the onboarding sudoers rule).
# `2>/dev/null` goes before the `<` so a missing file says nothing.
HARDWARE_COMMAND = (
    "echo ===HARDWARE===; "
    'echo "vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"; '
    'echo "model=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"; '
    'echo "serial=$( (sudo -n dmidecode -s system-serial-number 2>/dev/null '
    '|| cat /sys/class/dmi/id/product_serial 2>/dev/null) | head -n 1)"; '
    "echo \"dt_model=$(tr -d '\\000' 2>/dev/null < /proc/device-tree/model)\"; "
    "echo \"dt_serial=$( (tr -d '\\000' 2>/dev/null < /proc/device-tree/serial-number "
    "|| awk -F': *' '/^Serial/ {print $2}' /proc/cpuinfo 2>/dev/null) | head -n 1)\"; "
    'echo "virt=$(systemd-detect-virt 2>/dev/null)"'
)


class Hardware(TypedDict):
    vendor: str | None
    model: str | None
    serial: str | None
    # True on bare metal (a Pi included), False in a VM or container, None
    # when it could not be told.
    is_physical: bool | None


def clean_firmware_value(value: str) -> str | None:
    text = " ".join(value.split())[:128]
    return None if text.lower() in _PLACEHOLDERS else text


def parse_hardware(section: str) -> Hardware:
    """The HARDWARE section's `key=value` lines: DMI first, the device
    tree where DMI says nothing (a Raspberry Pi)."""
    found: dict[str, str | None] = dict.fromkeys(_KEYS)
    virt = ""
    for line in section.splitlines():
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator:
            continue
        if key == "virt":
            # `systemd-detect-virt` says "none" for bare metal — a value
            # here, not an unfilled field.
            virt = value.strip().lower()
        elif key in found:
            found[key] = clean_firmware_value(value)
    vendor, model, serial = found["vendor"], found["model"], found["serial"]
    dt_model = found["dt_model"]
    if dt_model and not model:
        model = dt_model
        if not vendor and dt_model.lower().startswith("raspberry pi"):
            vendor = "Raspberry Pi"
    if not serial and found["dt_serial"]:
        # A Pi's serial is a 64-bit number printed with leading zeros.
        serial = found["dt_serial"].lstrip("0") or None
    is_physical = (virt == "none") if virt else (True if dt_model else None)
    return Hardware(vendor=vendor, model=model, serial=serial, is_physical=is_physical)
