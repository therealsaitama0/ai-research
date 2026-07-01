"""
Fix for Issue #206 — Mass Assignment in Microservice → Privilege Escalation Chain

Vulnerability
-------------
A microservice endpoint that blindly binds an incoming JSON/form payload to an
ORM model (e.g. ``User(**request.json)`` or ``user.update(**payload)``) lets an
attacker inject fields the client should never control. In a distributed
microservice topology this becomes a *chain*:

    1. Public "profile update" service accepts ``{"name": "...",
       "is_admin": true, "role": "superuser", "tenant_id": 42, ...}``.
    2. The user record propagates (event bus / DB replica) to the auth service.
    3. The auth service trusts the ``is_admin`` / ``role`` field it sees on the
       shared user object — attacker now has admin on every downstream service.

Root cause: no server-side allow-list of writable fields; trust boundary is
placed at the ORM instead of at the HTTP edge; sensitive fields (``role``,
``is_admin``, ``permissions``, ``tenant_id``, ``password_hash``, ``id``, audit
timestamps) are not segregated from user-editable ones.

Fix strategy
------------
1. **Explicit per-role allow-list** of writable fields. Deny by default.
2. **Strip / reject** any key not in the allow-list (log + audit the attempt).
3. **Type-check** each accepted field so an attacker cannot smuggle a dict /
   list into a scalar column (SQL/NoSQL injection pivot).
4. **Never trust the client** for privilege fields — only a dedicated
   admin-scoped endpoint (with its own allow-list + authorization check) may
   mutate ``role`` / ``is_admin`` / ``permissions`` / ``tenant_id``.
5. **Immutable fields** (``id``, ``created_at``, ``password_hash``) are always
   rejected regardless of caller.
6. Return a stable error contract so downstream services do not silently
   accept partial writes.

The module below is dependency-free and framework-agnostic so it can be reused
by any microservice (Flask, FastAPI, Django, aiohttp, gRPC gateway, ...).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

logger = logging.getLogger("security.mass_assignment")

# ---------------------------------------------------------------------------
# 1. Field classification — the single source of truth per model
# ---------------------------------------------------------------------------

# Fields the server MUST always control. Rejecting them (instead of silently
# dropping) surfaces attacks in logs and blocks confused-deputy chains.
IMMUTABLE_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "uuid",
        "pk",
        "created_at",
        "updated_at",
        "deleted_at",
        "password_hash",
        "password_salt",
        "mfa_secret",
        "api_key",
        "api_secret",
        "email_verified_at",
        "last_login_at",
        "failed_login_count",
        "audit_log",
    }
)

# Fields that require a privileged caller. Presented in a normal user payload
# they are the privilege-escalation vector.
PRIVILEGED_FIELDS: frozenset[str] = frozenset(
    {
        "role",
        "roles",
        "is_admin",
        "is_superuser",
        "is_staff",
        "permissions",
        "scopes",
        "tenant_id",
        "org_id",
        "organization_id",
        "owner_id",
        "account_type",
        "plan",
        "billing_tier",
        "feature_flags",
        "quota",
    }
)

# Case-insensitive lookup — attackers commonly try ``IsAdmin``, ``ROLE`` etc.
_IMMUTABLE_CI = frozenset(f.lower() for f in IMMUTABLE_FIELDS)
_PRIVILEGED_CI = frozenset(f.lower() for f in PRIVILEGED_FIELDS)

# Keys that hint at nested-object injection (``role[$ne]``, ``__proto__``,
# ``constructor.prototype`` etc.) used in Mongo / prototype-pollution chains.
_SUSPICIOUS_KEY_RE = re.compile(
    r"(^__|\.|\$|\[|prototype|constructor|__proto__|toString|valueOf)",
    re.IGNORECASE,
)


class MassAssignmentError(ValueError):
    """Raised when the payload attempts to write a forbidden field."""

    def __init__(self, message: str, offending: Iterable[str]):
        super().__init__(message)
        self.offending: tuple[str, ...] = tuple(sorted(set(offending)))


@dataclass(frozen=True)
class FieldPolicy:
    """Declarative allow-list for a single (model, actor-role) pair.

    ``allowed`` is the ONLY set of keys accepted from the client. Anything else
    — including unknown keys — is rejected. This is the "deny by default"
    posture required to stop mass-assignment.
    """

    model: str
    actor_role: str
    allowed: frozenset[str]
    # Optional per-field validators. Missing → default type check (scalar only).
    validators: Mapping[str, Callable[[Any], Any]] = field(default_factory=dict)
    # If True, unknown keys raise; if False, they are silently dropped (still
    # logged). Default True — fail closed.
    strict: bool = True

    def __post_init__(self) -> None:  # pragma: no cover - trivial
        overlap = self.allowed & IMMUTABLE_FIELDS
        if overlap:
            raise ValueError(
                f"Policy for {self.model}/{self.actor_role} allow-lists "
                f"immutable fields: {sorted(overlap)}"
            )


# ---------------------------------------------------------------------------
# 2. Core sanitizer
# ---------------------------------------------------------------------------

_SCALAR_TYPES: tuple[type, ...] = (str, int, float, bool, type(None))


def _default_scalar_validator(value: Any) -> Any:
    """Reject dicts/lists in scalar slots to block NoSQL operator injection
    (e.g. Mongo ``{"$ne": null}``) and prototype-pollution payloads."""
    if not isinstance(value, _SCALAR_TYPES):
        raise MassAssignmentError(
            f"Non-scalar value of type {type(value).__name__} not allowed",
            offending=[],
        )
    # Guard against overly long strings used to DoS validators / DBs.
    if isinstance(value, str) and len(value) > 4096:
        raise MassAssignmentError("String value exceeds maximum length", offending=[])
    return value


def sanitize_payload(
    payload: Mapping[str, Any] | None,
    policy: FieldPolicy,
    *,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Return a NEW dict containing only fields the caller may write.

    Raises :class:`MassAssignmentError` when the payload attempts to touch
    immutable/privileged fields, or (under ``strict=True``) unknown fields.
    All rejections are logged with the actor and offending keys so that a WAF
    or SIEM can correlate the attempt across microservice hops.
    """
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise MassAssignmentError(
            "Payload must be a JSON object", offending=[type(payload).__name__]
        )

    clean: dict[str, Any] = {}
    forbidden: list[str] = []
    unknown: list[str] = []
    suspicious: list[str] = []

    for raw_key, value in payload.items():
        if not isinstance(raw_key, str):
            suspicious.append(repr(raw_key))
            continue

        key = raw_key.strip()
        key_ci = key.lower()

        if _SUSPICIOUS_KEY_RE.search(key):
            suspicious.append(key)
            continue

        if key_ci in _IMMUTABLE_CI:
            # Immutable server-owned fields: never accepted, from anyone.
            forbidden.append(key)
            continue

        if key_ci in _PRIVILEGED_CI and key not in policy.allowed:
            # Privileged fields: only accepted when the policy explicitly
            # allow-lists them (i.e. the caller is an admin actor).
            forbidden.append(key)
            continue

        if key not in policy.allowed:
            unknown.append(key)
            continue

        validator = policy.validators.get(key, _default_scalar_validator)
        try:
            clean[key] = validator(value)
        except MassAssignmentError as exc:
            exc.offending = (key,)
            raise
        except Exception as exc:  # noqa: BLE001 - convert to security error
            raise MassAssignmentError(
                f"Invalid value for field {key!r}: {exc}", offending=[key]
            ) from exc

    if forbidden or suspicious:
        logger.warning(
            "mass_assignment_attempt model=%s actor=%s role=%s forbidden=%s suspicious=%s",
            policy.model,
            actor_id,
            policy.actor_role,
            forbidden,
            suspicious,
        )
        raise MassAssignmentError(
            "Payload contains fields the caller is not allowed to set",
            offending=[*forbidden, *suspicious],
        )

    if unknown:
        if policy.strict:
            logger.info(
                "mass_assignment_unknown_fields model=%s actor=%s unknown=%s",
                policy.model,
                actor_id,
                unknown,
            )
            raise MassAssignmentError(
                "Payload contains unknown fields", offending=unknown
            )
        logger.debug("dropped unknown fields %s for %s", unknown, policy.model)

    return clean


# ---------------------------------------------------------------------------
# 3. Example wiring — the "before" (vulnerable) vs "after" (patched) handler
# ---------------------------------------------------------------------------

USER_SELF_POLICY = FieldPolicy(
    model="User",
    actor_role="user",
    allowed=frozenset({"name", "display_name", "avatar_url", "locale", "timezone"}),
)

USER_ADMIN_POLICY = FieldPolicy(
    model="User",
    actor_role="admin",
    allowed=frozenset(
        {
            "name",
            "display_name",
            "avatar_url",
            "locale",
            "timezone",
            "role",
            "is_admin",
            "permissions",
            "tenant_id",
        }
    ),
)


def update_user_vulnerable(user: Any, payload: Mapping[str, Any]) -> Any:
    """DO NOT USE — kept only for the regression tests below."""
    for key, value in payload.items():  # pragma: no cover - deliberately unsafe
        setattr(user, key, value)
    return user


def update_user_secure(
    user: Any,
    payload: Mapping[str, Any],
    *,
    actor_id: str,
    actor_is_admin: bool,
) -> Any:
    """Hardened replacement. Callers pass the *authenticated* actor context;
    the payload itself never decides which policy applies."""
    policy = USER_ADMIN_POLICY if actor_is_admin else USER_SELF_POLICY
    clean = sanitize_payload(payload, policy, actor_id=actor_id)
    for key, value in clean.items():
        setattr(user, key, value)
    return user


# ---------------------------------------------------------------------------
# 4. Self-tests — run ``python fixes/mass_assignment_privesc_fix.py``
# ---------------------------------------------------------------------------

def _run_self_tests() -> None:
    class _User:
        def __init__(self) -> None:
            self.name = "alice"
            self.is_admin = False
            self.role = "user"
            self.tenant_id = 1
            self.id = 100
            self.password_hash = "hash"

    # 1. Happy path: only allowed fields land on the model.
    u = _User()
    update_user_secure(
        u, {"name": "Alice", "locale": "en"}, actor_id="u1", actor_is_admin=False
    )
    assert u.name == "Alice" and u.locale == "en"
    assert u.is_admin is False and u.role == "user"

    # 2. Classic mass-assignment privesc — must raise, must NOT mutate.
    u = _User()
    for evil in (
        {"name": "x", "is_admin": True},
        {"name": "x", "role": "superuser"},
        {"name": "x", "permissions": ["*"]},
        {"name": "x", "tenant_id": 999},
        {"name": "x", "IsAdmin": True},          # case variation
        {"name": "x", "ROLE": "admin"},          # case variation
    ):
        try:
            update_user_secure(u, evil, actor_id="u1", actor_is_admin=False)
        except MassAssignmentError as exc:
            assert exc.offending, "must report offending keys"
        else:  # pragma: no cover
            raise AssertionError(f"privesc payload accepted: {evil}")
        assert u.is_admin is False and u.role == "user" and u.tenant_id == 1

    # 3. Immutable fields — even admins cannot rewrite them via the API.
    for evil in (
        {"id": 1},
        {"password_hash": "pwn"},
        {"created_at": "1970-01-01"},
    ):
        try:
            update_user_secure(u, evil, actor_id="admin", actor_is_admin=True)
        except MassAssignmentError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"immutable field accepted: {evil}")

    # 4. NoSQL operator / prototype pollution smuggling — rejected.
    for evil in (
        {"name": {"$ne": None}},
        {"__proto__": {"is_admin": True}},
        {"constructor.prototype.is_admin": True},
        {"role.$set": "admin"},
    ):
        try:
            update_user_secure(u, evil, actor_id="u1", actor_is_admin=False)
        except MassAssignmentError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"suspicious key accepted: {evil}")

    # 5. Unknown fields fail closed under strict policies.
    try:
        update_user_secure(
            u, {"name": "ok", "unknown_field": 1}, actor_id="u1", actor_is_admin=False
        )
    except MassAssignmentError as exc:
        assert "unknown_field" in exc.offending
    else:  # pragma: no cover
        raise AssertionError("unknown field silently accepted")

    # 6. Admin policy accepts privileged fields for admin callers only.
    admin_target = _User()
    update_user_secure(
        admin_target,
        {"role": "moderator", "is_admin": True},
        actor_id="root",
        actor_is_admin=True,
    )
    assert admin_target.role == "moderator" and admin_target.is_admin is True

    # 7. Non-mapping payloads rejected.
    try:
        sanitize_payload([("name", "x")], USER_SELF_POLICY)  # type: ignore[arg-type]
    except MassAssignmentError:
        pass
    else:  # pragma: no cover
        raise AssertionError("list payload accepted")

    # 8. Oversized string rejected (DoS / stored-XSS pivot guard).
    try:
        update_user_secure(
            _User(),
            {"name": "A" * 5000},
            actor_id="u1",
            actor_is_admin=False,
        )
    except MassAssignmentError:
        pass
    else:  # pragma: no cover
        raise AssertionError("oversized string accepted")

    print("mass_assignment_privesc_fix: all 8 self-tests passed")


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.WARNING)
    _run_self_tests()
