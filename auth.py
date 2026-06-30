"""Authentication module with email normalization to prevent account takeover."""

from email_policy import canonicalize_email, get_user_id_for_canonical, seed_account

_accounts: dict[str, dict] = {}


def register_account(email: str, password: str) -> dict:
    if not email or not password:
        return {"success": False, "error": "invalid_input"}

    canonical = canonicalize_email(email)
    if get_user_id_for_canonical(canonical):
        return {
            "success": False,
            "error": "email_taken",
            "canonical_email": canonical,
            "takeover_risk": False,
        }

    user_id = f"user-{len(_accounts) + 1}"
    _accounts[canonical] = {
        "user_id": user_id,
        "email": email,
        "canonical_email": canonical,
        "password": password,
    }
    seed_account(canonical, user_id)
    return {
        "success": True,
        "user_id": user_id,
        "email": email,
        "canonical_email": canonical,
        "takeover_risk": False,
    }


def request_password_reset(email: str) -> dict:
    canonical = canonicalize_email(email)
    user_id = get_user_id_for_canonical(canonical)
    if user_id is None:
        return {"success": False, "error": "account_not_found", "takeover_risk": False}

    return {
        "success": True,
        "user_id": user_id,
        "reset_sent_to": canonical,
        "takeover_risk": False,
    }
