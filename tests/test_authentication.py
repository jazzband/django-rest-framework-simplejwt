from datetime import timedelta
from importlib import reload

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from rest_framework_simplejwt import authentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken
from rest_framework_simplejwt.models import TokenUser
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken, SlidingToken
from rest_framework_simplejwt.utils import _get_token_auth_hash, get_token_auth_hash

from .utils import override_api_settings

User = get_user_model()
AuthToken = api_settings.AUTH_TOKEN_CLASSES[0]


class TestJWTAuthentication(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.backend = authentication.JWTAuthentication()

        self.fake_token = b"TokenMcTokenface"
        self.fake_header = b"Bearer " + self.fake_token

    def test_get_header(self):
        # Should return None if no authorization header
        request = self.factory.get("/test-url/")
        self.assertIsNone(self.backend.get_header(request))

        # Should pull correct header off request
        request = self.factory.get("/test-url/", HTTP_AUTHORIZATION=self.fake_header)
        self.assertEqual(self.backend.get_header(request), self.fake_header)

        # Should work for unicode headers
        request = self.factory.get(
            "/test-url/", HTTP_AUTHORIZATION=self.fake_header.decode("utf-8")
        )
        self.assertEqual(self.backend.get_header(request), self.fake_header)

    @override_api_settings(AUTH_HEADER_NAME="HTTP_X_ACCESS_TOKEN")
    def test_get_header_x_access_token(self):
        # Should pull correct header off request when using X_ACCESS_TOKEN
        request = self.factory.get("/test-url/", HTTP_X_ACCESS_TOKEN=self.fake_header)
        self.assertEqual(self.backend.get_header(request), self.fake_header)

        # Should work for unicode headers when using
        request = self.factory.get(
            "/test-url/", HTTP_X_ACCESS_TOKEN=self.fake_header.decode("utf-8")
        )
        self.assertEqual(self.backend.get_header(request), self.fake_header)

    def test_get_raw_token(self):
        reload(authentication)

        # Should return None if an empty AUTHORIZATION header is sent
        self.assertIsNone(self.backend.get_raw_token(b""))

        # Should raise error if header is malformed
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_raw_token(b"Bearer one two")

        with self.assertRaises(AuthenticationFailed):
            self.backend.get_raw_token(b"Bearer")

        # Otherwise, should return unvalidated token in header
        self.assertEqual(self.backend.get_raw_token(self.fake_header), self.fake_token)

    @override_api_settings(AUTH_HEADER_TYPES="JWT")
    def test_get_raw_token_incorrect_header_keyword(self):
        # Should return None if header lacks correct type keyword
        # AUTH_HEADER_TYPES is "JWT", but header is "Bearer"
        reload(authentication)
        self.assertIsNone(self.backend.get_raw_token(self.fake_header))

    @override_api_settings(AUTH_HEADER_TYPES=("JWT", "Bearer"))
    def test_get_raw_token_multi_header_keyword(self):
        # Should return token if header has one of many valid token types
        reload(authentication)
        self.assertEqual(
            self.backend.get_raw_token(self.fake_header),
            self.fake_token,
        )

    def test_get_validated_token(self):
        # Should raise InvalidToken if token not valid
        token = AuthToken()
        token.set_exp(lifetime=-timedelta(days=1))
        with self.assertRaises(InvalidToken):
            self.backend.get_validated_token(str(token))

        # Otherwise, should return validated token
        token.set_exp()
        self.assertEqual(
            self.backend.get_validated_token(str(token)).payload, token.payload
        )

    @override_api_settings(
        AUTH_TOKEN_CLASSES=("rest_framework_simplejwt.tokens.AccessToken",),
    )
    def test_get_validated_token_reject_unknown_token(self):
        # Should not accept tokens not included in AUTH_TOKEN_CLASSES
        sliding_token = SlidingToken()
        with self.assertRaises(InvalidToken) as e:
            self.backend.get_validated_token(str(sliding_token))

        messages = e.exception.detail["messages"]
        self.assertEqual(1, len(messages))
        self.assertEqual(
            {
                "token_class": "AccessToken",
                "token_type": "access",
                "message": "Token has wrong type",
            },
            messages[0],
        )

    @override_api_settings(
        AUTH_TOKEN_CLASSES=(
            "rest_framework_simplejwt.tokens.AccessToken",
            "rest_framework_simplejwt.tokens.SlidingToken",
        ),
    )
    def test_get_validated_token_accept_known_token(self):
        # Should accept tokens included in AUTH_TOKEN_CLASSES
        access_token = AccessToken()
        sliding_token = SlidingToken()

        self.backend.get_validated_token(str(access_token))
        self.backend.get_validated_token(str(sliding_token))

    def test_get_user(self):
        payload = {"some_other_id": "foo"}

        # Should raise error if no recognizable user identification
        with self.assertRaises(InvalidToken):
            self.backend.get_user(payload)

        payload[api_settings.USER_ID_CLAIM] = 42

        # Should raise exception if user not found
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_user(payload)

        user = User.objects.create_user(username="markhamill", is_active=False)

        payload[api_settings.USER_ID_CLAIM] = getattr(user, api_settings.USER_ID_FIELD)

        # Should raise exception if user is inactive
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_user(payload)

        user.is_active = True
        user.save()

        # Otherwise, should return correct user
        self.assertEqual(self.backend.get_user(payload).id, user.id)

    @override_api_settings(
        CHECK_REVOKE_TOKEN=True, REVOKE_TOKEN_CLAIM="revoke_token_claim"
    )
    def test_get_user_with_check_revoke_token(self):
        user = User.objects.create_user(username="markhamill")
        payload = {
            api_settings.USER_ID_CLAIM: getattr(user, api_settings.USER_ID_FIELD)
        }

        # Should raise exception if claim is missing
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_user(payload)

        payload[api_settings.REVOKE_TOKEN_CLAIM] = "differenthash"
        # Should raise exception if claim is different
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_user(payload)

        payload[api_settings.REVOKE_TOKEN_CLAIM] = _get_token_auth_hash(
            user, "other old not very secure secret"
        )
        # Should return correct user if claim was signed with an old key
        self.assertEqual(self.backend.get_user(payload).id, user.id)

        payload[api_settings.REVOKE_TOKEN_CLAIM] = get_token_auth_hash(user)
        # Otherwise, should return correct user
        self.assertEqual(self.backend.get_user(payload).id, user.id)


class TestJWTStatelessUserAuthentication(TestCase):
    def setUp(self):
        self.backend = authentication.JWTStatelessUserAuthentication()

    def test_get_user(self):
        payload = {"some_other_id": "foo"}

        # Should raise error if no recognizable user identification
        with self.assertRaises(InvalidToken):
            self.backend.get_user(payload)

        payload[api_settings.USER_ID_CLAIM] = 42

        # Otherwise, should return a token user object
        user = self.backend.get_user(payload)

        self.assertIsInstance(user, TokenUser)
        self.assertEqual(user.id, 42)

    def test_custom_tokenuser(self):
        from django.utils.functional import cached_property

        class BobSaget(TokenUser):
            @cached_property
            def username(self):
                return "bsaget"

        temp = api_settings.TOKEN_USER_CLASS
        api_settings.TOKEN_USER_CLASS = BobSaget

        # Should return a token user object
        payload = {api_settings.USER_ID_CLAIM: 42}
        user = self.backend.get_user(payload)

        self.assertIsInstance(user, api_settings.TOKEN_USER_CLASS)
        self.assertEqual(user.id, 42)
        self.assertEqual(user.username, "bsaget")

        # Restore default TokenUser for future tests
        api_settings.TOKEN_USER_CLASS = temp
