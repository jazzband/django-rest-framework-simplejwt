from django.conf import settings
from django.middleware import csrf
from django.utils.translation import gettext_lazy as _
from rest_framework import generics, status
from rest_framework.exceptions import NotAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView

from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from . import serializers
from .authentication import AUTH_HEADER_TYPES
from .exceptions import InvalidToken, TokenError
from .utils import aware_utcnow, datetime_from_epoch


class TokenViewBase(generics.GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    serializer_class = None

    www_authenticate_realm = 'api'

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        data = serializer.validated_data

        # Don't return the token in the response body if the auth tokens are in a httpOnly cookie
        # Only return the CSRF token
        if api_settings.AUTH_COOKIE:
            csrf_token = csrf.get_token(self.request)
            cookie_data = self.get_cookie_data()
            response = Response({'csrf_token': csrf_token}, status=status.HTTP_200_OK)
            return self.set_auth_cookies(response, data, cookie_data)

        return Response(data, status=status.HTTP_200_OK)

    def get_cookie_data(self):
        cookie_data = {
            'expires': self.get_refresh_token_expiration(),
            'domain': api_settings.AUTH_COOKIE_DOMAIN,
            'path': api_settings.AUTH_COOKIE_PATH,
            'secure': api_settings.AUTH_COOKIE_SECURE or None,
            'httponly': True
        }
        # prior to django 2.1 samesite was not supported
        if hasattr(api_settings, 'AUTH_COOKIE_SAMESITE'):
            cookie_data['samesite'] = api_settings.AUTH_COOKIE_SAMESITE
        return cookie_data

    def set_auth_cookies(self, response, data, cookie_data):
        return response

    def get_refresh_token_expiration(self):
        return aware_utcnow() + api_settings.REFRESH_TOKEN_LIFETIME


class TokenRefreshViewBase(TokenViewBase):
    def extract_token_from_cookie(self, request):
        return request

    def post(self, request, *args, **kwargs):
        if api_settings.AUTH_COOKIE:
            request = self.extract_token_from_cookie(request)
        return super().post(request, *args, **kwargs)


class BaseTokenCookieViewMixin:

    def extract_token_from_cookie(self, request):
        """Extracts token from cookie and sets it in request.data as it would be sent by the user"""
        if not request.data:
            token = request.COOKIES.get(self.token_refresh_cookie_name)
            if not token:
                raise NotAuthenticated(detail=_('Refresh cookie not set. Try to authenticate first.'))
            request.data[self.token_refresh_data_key] = token
        return request

    def get_refresh_token_expiration(self):
        return aware_utcnow() + api_settings.REFRESH_TOKEN_LIFETIME


class TokenCookieViewMixin(BaseTokenCookieViewMixin):
    token_refresh_view_name = 'token_refresh'
    token_refresh_data_key = 'refresh'

    @property
    def token_refresh_cookie_name(self):
        return '{}_refresh'.format(api_settings.AUTH_COOKIE)

    def set_auth_cookies(self, response, data, cookie_data):
        response.set_cookie(
            api_settings.AUTH_COOKIE,
            data['access'],
            **cookie_data
        )
        if 'refresh' in data:
            response.set_cookie(
                '{}_refresh'.format(api_settings.AUTH_COOKIE),
                data['refresh'],
                **{
                    **cookie_data,
                    **{
                        'domain': api_settings.AUTH_COOKIE_DOMAIN,
                        'path': reverse(self.token_refresh_view_name)
                    }
                }
            )
        return response


class TokenObtainPairView(TokenCookieViewMixin, TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """
    serializer_class = serializers.TokenObtainPairSerializer


token_obtain_pair = TokenObtainPairView.as_view()


class TokenRefreshView(TokenCookieViewMixin, TokenRefreshViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """
    serializer_class = serializers.TokenRefreshSerializer

    def get_refresh_token_expiration(self):
        if api_settings.ROTATE_REFRESH_TOKENS:
            return super().get_refresh_token_expiration()
        token = RefreshToken(self.request.data['refresh'])
        return datetime_from_epoch(token.payload['exp'])


token_refresh = TokenRefreshView.as_view()


class SlidingTokenCookieViewMixin(BaseTokenCookieViewMixin):
    token_refresh_data_key = 'token'

    @property
    def token_refresh_cookie_name(self):
        return api_settings.AUTH_COOKIE

    def set_auth_cookies(self, response, data, cookie_data):
        response.set_cookie(
            api_settings.AUTH_COOKIE,
            data['token'],
            **cookie_data
        )
        return response


class TokenObtainSlidingView(SlidingTokenCookieViewMixin, TokenViewBase):
    """
    Takes a set of user credentials and returns a sliding JSON web token to
    prove the authentication of those credentials.
    """
    serializer_class = serializers.TokenObtainSlidingSerializer


token_obtain_sliding = TokenObtainSlidingView.as_view()


class TokenRefreshSlidingView(SlidingTokenCookieViewMixin, TokenRefreshViewBase):
    """
    Takes a sliding JSON web token and returns a new, refreshed version if the
    token's refresh period has not expired.
    """
    serializer_class = serializers.TokenRefreshSlidingSerializer


token_refresh_sliding = TokenRefreshSlidingView.as_view()


class TokenVerifyView(TokenViewBase):
    """
    Takes a token and indicates if it is valid.  This view provides no
    information about a token's fitness for a particular use.
    """
    serializer_class = serializers.TokenVerifySerializer


token_verify = TokenVerifyView.as_view()


class TokenCookieDeleteView(APIView):
    """
    Deletes httpOnly auth cookies.
    Used as logout view while using AUTH_COOKIE
    """
    token_refresh_view_name = 'token_refresh'
    authentication_classes = ()
    permission_classes = ()

    def post(self, request):
        response = Response()

        if api_settings.AUTH_COOKIE:
            self.delete_auth_cookies(response)
            self.delete_csrf_cookie(response)

        return response

    def delete_auth_cookies(self, response):
        response.delete_cookie(
            api_settings.AUTH_COOKIE,
            domain=api_settings.AUTH_COOKIE_DOMAIN,
            path=api_settings.AUTH_COOKIE_PATH
        )
        response.delete_cookie(
            '{}_refresh'.format(api_settings.AUTH_COOKIE),
            domain=api_settings.AUTH_COOKIE_DOMAIN,
            path=reverse(self.token_refresh_view_name),
        )

    def delete_csrf_cookie(self, response):
        response.delete_cookie(
            settings.CSRF_COOKIE_NAME,
            domain=api_settings.AUTH_COOKIE_DOMAIN,
            path=api_settings.AUTH_COOKIE_PATH
        )


token_delete = TokenCookieDeleteView.as_view()
