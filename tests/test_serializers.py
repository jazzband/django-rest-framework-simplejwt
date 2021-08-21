from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import exceptions as drf_exceptions

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import (
    TokenBlacklistSerializer, TokenObtainPairSerializer, TokenObtainSerializer,
    TokenObtainSlidingSerializer, TokenRefreshSerializer,
    TokenRefreshSlidingSerializer, TokenVerifySerializer,
)
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken, OutstandingToken,
)
from rest_framework_simplejwt.tokens import (
    AccessToken, RefreshToken, SlidingToken,
)
from rest_framework_simplejwt.utils import (
    aware_utcnow, datetime_from_epoch, datetime_to_epoch,
)

from .utils import override_api_settings

User = get_user_model()


class TestTokenObtainSerializer(TestCase):
    def setUp(self):
        self.username = 'test_user'
        self.password = 'test_password'

        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
        )

    def test_it_should_not_validate_if_any_fields_missing(self):
        s = TokenObtainSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertIn(s.username_field, s.errors)
        self.assertIn('password', s.errors)

        s = TokenObtainSerializer(data={
            TokenObtainSerializer.username_field: 'oieanrst',
        })
        self.assertFalse(s.is_valid())
        self.assertIn('password', s.errors)

        s = TokenObtainSerializer(data={
            'password': 'oieanrst',
        })
        self.assertFalse(s.is_valid())
        self.assertIn(s.username_field, s.errors)

    def test_it_should_not_validate_if_user_not_found(self):
        s = TokenObtainSerializer(context=MagicMock(), data={
            TokenObtainSerializer.username_field: 'missing',
            'password': 'pass',
        })

        with self.assertRaises(drf_exceptions.AuthenticationFailed):
            s.is_valid()

    def test_it_should_raise_if_user_not_active(self):
        self.user.is_active = False
        self.user.save()

        s = TokenObtainSerializer(context=MagicMock(), data={
            TokenObtainSerializer.username_field: self.username,
            'password': self.password,
        })

        with self.assertRaises(drf_exceptions.AuthenticationFailed):
            s.is_valid()


class TestTokenObtainSlidingSerializer(TestCase):
    def setUp(self):
        self.username = 'test_user'
        self.password = 'test_password'

        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
        )

    def test_it_should_produce_a_json_web_token_when_valid(self):
        s = TokenObtainSlidingSerializer(context=MagicMock(), data={
            TokenObtainSlidingSerializer.username_field: self.username,
            'password': self.password,
        })

        self.assertTrue(s.is_valid())
        self.assertIn('token', s.validated_data)

        # Expecting token type claim to be correct for sliding token.  If this
        # is the case, instantiating a `SlidingToken` instance with encoded
        # token should not raise an exception.
        SlidingToken(s.validated_data['token'])


class TestTokenObtainPairSerializer(TestCase):
    def setUp(self):
        self.username = 'test_user'
        self.password = 'test_password'

        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
        )

    def test_it_should_produce_a_json_web_token_when_valid(self):
        s = TokenObtainPairSerializer(context=MagicMock(), data={
            TokenObtainPairSerializer.username_field: self.username,
            'password': self.password,
        })

        self.assertTrue(s.is_valid())
        self.assertIn('access', s.validated_data)
        self.assertIn('refresh', s.validated_data)

        # Expecting token type claim to be correct for both tokens.  If this is
        # the case, instantiating appropriate token subclass instances with
        # encoded tokens should not raise an exception.
        AccessToken(s.validated_data['access'])
        RefreshToken(s.validated_data['refresh'])


class TestTokenRefreshSlidingSerializer(TestCase):
    def test_it_should_not_validate_if_token_invalid(self):
        token = SlidingToken()
        del token['exp']

        s = TokenRefreshSlidingSerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("has no 'exp' claim", e.exception.args[0])

        token.set_exp(lifetime=-timedelta(days=1))

        s = TokenRefreshSlidingSerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn('invalid or expired', e.exception.args[0])

    def test_it_should_raise_token_error_if_token_has_no_refresh_exp_claim(self):
        token = SlidingToken()
        del token[api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM]

        s = TokenRefreshSlidingSerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("has no '{}' claim".format(api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM), e.exception.args[0])

    def test_it_should_raise_token_error_if_token_has_refresh_period_expired(self):
        token = SlidingToken()
        token.set_exp(api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM, lifetime=-timedelta(days=1))

        s = TokenRefreshSlidingSerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("'{}' claim has expired".format(api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM), e.exception.args[0])

    def test_it_should_raise_token_error_if_token_has_wrong_type(self):
        token = SlidingToken()
        token[api_settings.TOKEN_TYPE_CLAIM] = 'wrong_type'

        s = TokenRefreshSlidingSerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("wrong type", e.exception.args[0])

    def test_it_should_update_token_exp_claim_if_everything_ok(self):
        old_token = SlidingToken()

        lifetime = api_settings.SLIDING_TOKEN_LIFETIME - timedelta(seconds=1)
        old_exp = old_token.current_time + lifetime

        old_token.set_exp(lifetime=lifetime)

        # Serializer validates
        s = TokenRefreshSlidingSerializer(data={'token': str(old_token)})
        self.assertTrue(s.is_valid())

        # Expiration claim has moved into future
        new_token = SlidingToken(s.validated_data['token'])
        new_exp = datetime_from_epoch(new_token['exp'])

        self.assertTrue(old_exp < new_exp)


class TestTokenRefreshSerializer(TestCase):
    def test_it_should_raise_token_error_if_token_invalid(self):
        token = RefreshToken()
        del token['exp']

        s = TokenRefreshSerializer(data={'refresh': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("has no 'exp' claim", e.exception.args[0])

        token.set_exp(lifetime=-timedelta(days=1))

        s = TokenRefreshSerializer(data={'refresh': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn('invalid or expired', e.exception.args[0])

    def test_it_should_raise_token_error_if_token_has_wrong_type(self):
        token = RefreshToken()
        token[api_settings.TOKEN_TYPE_CLAIM] = 'wrong_type'

        s = TokenRefreshSerializer(data={'refresh': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("wrong type", e.exception.args[0])

    def test_it_should_return_access_token_if_everything_ok(self):
        refresh = RefreshToken()
        refresh['test_claim'] = 'arst'

        # Serializer validates
        s = TokenRefreshSerializer(data={'refresh': str(refresh)})

        now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

        with patch('rest_framework_simplejwt.tokens.aware_utcnow') as fake_aware_utcnow:
            fake_aware_utcnow.return_value = now
            self.assertTrue(s.is_valid())

        access = AccessToken(s.validated_data['access'])

        self.assertEqual(refresh['test_claim'], access['test_claim'])
        self.assertEqual(access['exp'], datetime_to_epoch(now + api_settings.ACCESS_TOKEN_LIFETIME))

    def test_it_should_return_refresh_token_if_tokens_should_be_rotated(self):
        refresh = RefreshToken()

        refresh['test_claim'] = 'arst'

        old_jti = refresh['jti']
        old_exp = refresh['exp']

        # Serializer validates
        ser = TokenRefreshSerializer(data={'refresh': str(refresh)})

        now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

        with override_api_settings(ROTATE_REFRESH_TOKENS=True, BLACKLIST_AFTER_ROTATION=False):
            with patch('rest_framework_simplejwt.tokens.aware_utcnow') as fake_aware_utcnow:
                fake_aware_utcnow.return_value = now
                self.assertTrue(ser.is_valid())

        access = AccessToken(ser.validated_data['access'])
        new_refresh = RefreshToken(ser.validated_data['refresh'])

        self.assertEqual(refresh['test_claim'], access['test_claim'])
        self.assertEqual(refresh['test_claim'], new_refresh['test_claim'])

        self.assertNotEqual(old_jti, new_refresh['jti'])
        self.assertNotEqual(old_exp, new_refresh['exp'])

        self.assertEqual(access['exp'], datetime_to_epoch(now + api_settings.ACCESS_TOKEN_LIFETIME))
        self.assertEqual(new_refresh['exp'], datetime_to_epoch(now + api_settings.REFRESH_TOKEN_LIFETIME))

    def test_it_should_blacklist_refresh_token_if_tokens_should_be_rotated_and_blacklisted(self):
        self.assertEqual(OutstandingToken.objects.count(), 0)
        self.assertEqual(BlacklistedToken.objects.count(), 0)

        refresh = RefreshToken()

        refresh['test_claim'] = 'arst'

        old_jti = refresh['jti']
        old_exp = refresh['exp']

        # Serializer validates
        ser = TokenRefreshSerializer(data={'refresh': str(refresh)})

        now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

        with override_api_settings(ROTATE_REFRESH_TOKENS=True, BLACKLIST_AFTER_ROTATION=True):
            with patch('rest_framework_simplejwt.tokens.aware_utcnow') as fake_aware_utcnow:
                fake_aware_utcnow.return_value = now
                self.assertTrue(ser.is_valid())

        access = AccessToken(ser.validated_data['access'])
        new_refresh = RefreshToken(ser.validated_data['refresh'])

        self.assertEqual(refresh['test_claim'], access['test_claim'])
        self.assertEqual(refresh['test_claim'], new_refresh['test_claim'])

        self.assertNotEqual(old_jti, new_refresh['jti'])
        self.assertNotEqual(old_exp, new_refresh['exp'])

        self.assertEqual(access['exp'], datetime_to_epoch(now + api_settings.ACCESS_TOKEN_LIFETIME))
        self.assertEqual(new_refresh['exp'], datetime_to_epoch(now + api_settings.REFRESH_TOKEN_LIFETIME))

        self.assertEqual(OutstandingToken.objects.count(), 1)
        self.assertEqual(BlacklistedToken.objects.count(), 1)

        # Assert old refresh token is blacklisted
        self.assertEqual(BlacklistedToken.objects.first().token.jti, old_jti)


class TestTokenVerifySerializer(TestCase):
    def test_it_should_raise_token_error_if_token_invalid(self):
        token = RefreshToken()
        del token['exp']

        s = TokenVerifySerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("has no 'exp' claim", e.exception.args[0])

        token.set_exp(lifetime=-timedelta(days=1))

        s = TokenVerifySerializer(data={'token': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn('invalid or expired', e.exception.args[0])

    def test_it_should_not_raise_token_error_if_token_has_wrong_type(self):
        token = RefreshToken()
        token[api_settings.TOKEN_TYPE_CLAIM] = 'wrong_type'

        s = TokenVerifySerializer(data={'token': str(token)})

        self.assertTrue(s.is_valid())

    def test_it_should_return_given_token_if_everything_ok(self):
        refresh = RefreshToken()
        refresh['test_claim'] = 'arst'

        # Serializer validates
        s = TokenVerifySerializer(data={'token': str(refresh)})

        now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

        with patch('rest_framework_simplejwt.tokens.aware_utcnow') as fake_aware_utcnow:
            fake_aware_utcnow.return_value = now
            self.assertTrue(s.is_valid())

        self.assertEqual(len(s.validated_data), 0)


class TestTokenBlacklistSerializer(TestCase):
    def test_it_should_raise_token_error_if_token_invalid(self):
        token = RefreshToken()
        del token['exp']

        s = TokenBlacklistSerializer(data={'refresh': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("has no 'exp' claim", e.exception.args[0])

        token.set_exp(lifetime=-timedelta(days=1))

        s = TokenBlacklistSerializer(data={'refresh': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn('invalid or expired', e.exception.args[0])

    def test_it_should_raise_token_error_if_token_has_wrong_type(self):
        token = RefreshToken()
        token[api_settings.TOKEN_TYPE_CLAIM] = 'wrong_type'

        s = TokenBlacklistSerializer(data={'refresh': str(token)})

        with self.assertRaises(TokenError) as e:
            s.is_valid()

        self.assertIn("wrong type", e.exception.args[0])

    def test_it_should_return_nothing_if_everything_ok(self):
        refresh = RefreshToken()
        refresh['test_claim'] = 'arst'

        # Serializer validates
        s = TokenBlacklistSerializer(data={'refresh': str(refresh)})

        now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

        with patch('rest_framework_simplejwt.tokens.aware_utcnow') as fake_aware_utcnow:
            fake_aware_utcnow.return_value = now
            self.assertTrue(s.is_valid())

        self.assertDictEqual(s.validated_data, {})

    def test_it_should_blacklist_refresh_token_if_everything_ok(self):
        self.assertEqual(OutstandingToken.objects.count(), 0)
        self.assertEqual(BlacklistedToken.objects.count(), 0)

        refresh = RefreshToken()

        refresh['test_claim'] = 'arst'

        old_jti = refresh['jti']

        # Serializer validates
        ser = TokenBlacklistSerializer(data={'refresh': str(refresh)})

        now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

        with patch('rest_framework_simplejwt.tokens.aware_utcnow') as fake_aware_utcnow:
            fake_aware_utcnow.return_value = now
            self.assertTrue(ser.is_valid())

        self.assertEqual(OutstandingToken.objects.count(), 1)
        self.assertEqual(BlacklistedToken.objects.count(), 1)

        # Assert old refresh token is blacklisted
        self.assertEqual(BlacklistedToken.objects.first().token.jti, old_jti)
