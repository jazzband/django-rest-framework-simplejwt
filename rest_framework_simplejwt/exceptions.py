from typing import TYPE_CHECKING, Any, Optional

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, status

if TYPE_CHECKING:
    from rest_framework.exceptions import _Detail

    # DetailDictMixin is used with drf APIExceptions
    BASE_AuthenticationFailed = exceptions.APIException
else:
    _Detail = Any
    BASE_AuthenticationFailed = object


class TokenError(Exception):
    pass


class TokenBackendError(Exception):
    pass


class DetailDictMixin(BASE_AuthenticationFailed):
    def __init__(
        self,
        detail: Optional[_Detail] = None,
        code: Optional[str] = None,
    ) -> None:
        """
        Builds a detail dictionary for the error to give more information to API
        users.
        """
        detail_dict = {"detail": self.default_detail, "code": self.default_code}

        if isinstance(detail, dict):
            detail_dict.update(detail)
        elif detail is not None:
            detail_dict["detail"] = detail

        if code is not None:
            detail_dict["code"] = code

        super().__init__(detail_dict)


class AuthenticationFailed(DetailDictMixin, exceptions.AuthenticationFailed):
    pass


class InvalidToken(AuthenticationFailed):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _("Token is invalid or expired")
    default_code = "token_not_valid"
