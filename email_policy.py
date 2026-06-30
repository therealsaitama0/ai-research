"""Email normalization policy to prevent account takeover via aliases.

This module provides canonical email transformation:
  - Case-folding on both local and domain parts
  - Gmail dot-removal (user@gmail.com == u.ser@gmail.com)
  - Gmail plus-tag stripping (user@gmail.com == user+tag@gmail.com)
"""

from __future__ import annotations

_accounts: dict[str, dict] = {}
_user_ids: dict[str, str] = {}


def canonicalize_email(email: str) -> str:
    if not email or "@" not in email:
        return email.lower()
    local, domain = email.lower().split("@", 1)
    domain = domain.lower()
    if domain == "gmail.com":
        local = local.replace(".", "")
        local = local.split("+")[0]
    return f"{local}@{domain}"


def get_user_id_for_canonical(canonical: str) -> str | None:
    return _user_ids.get(canonical)


def seed_account(canonical: str, user_id: str) -> None:
    _user_ids[canonical] = user_id
    _accounts[canonical] = {"user_id": user_id, "canonical_email": canonical}
