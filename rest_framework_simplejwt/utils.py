from calendar import timegm
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, TypeVar

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.utils.crypto import salted_hmac
from django.utils.functional import lazy

if TYPE_CHECKING:
    from .models import TokenUser

    AuthUser = TypeVar("AuthUser", AbstractBaseUser, TokenUser)


def _get_token_auth_hash(user: "AuthUser", secret=None) -> str:
    key_salt = "rest_framework_simplejwt.utils.get_token_auth_hash"
    return salted_hmac(key_salt, user.password, secret=secret).hexdigest()


def get_token_auth_hash(user: "AuthUser") -> str:
    """
    Return an HMAC of the given user password field.
    """
    if hasattr(user, "get_session_auth_hash"):
        return user.get_session_auth_hash()
    return _get_token_auth_hash(user)


def get_fallback_token_auth_hash(user: "AuthUser") -> str:
    """
    Yields a sequence of fallback HMACs of the given user password field.
    """
    if hasattr(user, "get_session_auth_fallback_hash"):
        yield from user.get_session_auth_fallback_hash()

    fallback_keys = getattr(settings, "SECRET_KEY_FALLBACKS", [])
    yield from (
        _get_token_auth_hash(user, fallback_secret) for fallback_secret in fallback_keys
    )


def make_utc(dt: datetime) -> datetime:
    if settings.USE_TZ and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)

    return dt


def aware_utcnow() -> datetime:
    dt = datetime.now(tz=timezone.utc)
    if not settings.USE_TZ:
        dt = dt.replace(tzinfo=None)

    return dt


def datetime_to_epoch(dt: datetime) -> int:
    return timegm(dt.utctimetuple())


def datetime_from_epoch(ts: float) -> datetime:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if not settings.USE_TZ:
        dt = dt.replace(tzinfo=None)

    return dt


def format_lazy(s: str, *args, **kwargs) -> str:
    return s.format(*args, **kwargs)


format_lazy: Callable = lazy(format_lazy, str)
