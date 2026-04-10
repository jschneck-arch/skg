from __future__ import annotations

from collections.abc import Iterable

from skg_domain_ad.mappings import load_password_description_keywords


def is_machine_account_principal(name: str) -> bool:
    text = str(name or "").strip()
    if not text:
        return False
    local = text.split("@", 1)[0]
    return local.endswith("$")


def description_has_password_hint(
    description: str,
    *,
    keywords: Iterable[str] | None = None,
) -> bool:
    text = str(description or "").lower()
    if not text:
        return False

    active_keywords = keywords if keywords is not None else load_password_description_keywords()
    for keyword in active_keywords:
        normalized = str(keyword or "").strip().lower()
        if normalized and normalized in text:
            return True
    return False
