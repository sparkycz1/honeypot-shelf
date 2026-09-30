"""What a non-superadmin user may do within a `Company` — see
`app.db.models.user` and `app.db.models.company_membership`.

Its own module, with no model imports, so `company_membership` can use it
at class-definition time without importing `user` (no import cycle
between the models).
"""

import enum


class AccessLevel(enum.StrEnum):
    """What a non-superadmin user may do within their own `Company` — see
    the module docstring. `READ_WRITE` always implies everything `READ`
    grants; there is no third tier."""

    READ = "read"
    READ_WRITE = "read_write"
