Simple JWT
==========
[![Generic badge](https://circleci.com/gh/SimpleJWT/django-rest-framework-simplejwt.svg?style=shield)](https://circleci.com/gh/SimpleJWT/django-rest-framework-simplejwt)
[![Generic badge](https://codecov.io/gh/SimpleJWT/django-rest-framework-simplejwt/branch/master/graph/badge.svg)](https://codecov.io/gh/SimpleJWT/django-rest-framework-simplejwt)
[![Generic badge](https://img.shields.io/pypi/v/djangorestframework-simplejwt.svg)](https://pypi.python.org/pypi/djangorestframework-simplejwt)
[![Generic badge](https://img.shields.io/pypi/pyversions/djangorestframework-simplejwt.svg)](https://pypi.python.org/pypi/djangorestframework-simplejwt)
[![Generic badge](https://readthedocs.org/projects/django-rest-framework-simplejwt/badge/?version=latest)](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/)

## Requirements[](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/getting_started.html#requirements "Permalink to this headline")

-   Python (3.6, 3.7, 3.8)
-   Django (2.0, 2.1, 2.2, 3.0)
-   Django REST Framework (3.8, 3.9, 3.10)

These are the officially supported python and package versions. Other versions will probably work. You’re free to modify the tox config and see what is possible.

## Installation[](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/getting_started.html#installation "Permalink to this headline")

Simple JWT can be installed with pip:

```bash 
pip install djangorestframework-simplejwt
```

Then, your django project must be configured to use the library. In  `settings.py`, add  `rest_framework_simplejwt.authentication.JWTAuthentication`  to the list of authentication classes:

```python
REST_FRAMEWORK = {
    ...
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    )
    ...
}
```
Also, in your root  `urls.py`  file (or any other url config), include routes for Simple JWT’s  `TokenObtainPairView`  and  `TokenRefreshView`  views:

```python
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    ...
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    ...
]
```

You can also include a route for Simple JWT’s  `TokenVerifyView`  if you wish to allow API users to verify HMAC-signed tokens without having access to your signing key:

```python
urlpatterns = [
    ...
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    ...
]
```

## Usage[](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/getting_started.html#usage "Permalink to this headline")

To verify that Simple JWT is working, you can use curl to issue a couple of test requests:

```bash
curl \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "davidattenborough", "password": "boatymcboatface"}' \
  http://localhost:8000/api/token/

...
{
  "access":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX3BrIjoxLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiY29sZF9zdHVmZiI6IuKYgyIsImV4cCI6MTIzNDU2LCJqdGkiOiJmZDJmOWQ1ZTFhN2M0MmU4OTQ5MzVlMzYyYmNhOGJjYSJ9.NHlztMGER7UADHZJlxNG0WSi22a2KaYSfd1S-AuT7lU",
  "refresh":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX3BrIjoxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImNvbGRfc3R1ZmYiOiLimIMiLCJleHAiOjIzNDU2NywianRpIjoiZGUxMmY0ZTY3MDY4NDI3ODg5ZjE1YWMyNzcwZGEwNTEifQ.aEoAYkSJjoWH1boshQAaTkf8G3yn0kapko6HFRt7Rh4"
}
```

You can use the returned access token to prove authentication for a protected view:
```bash
curl \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX3BrIjoxLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiY29sZF9zdHVmZiI6IuKYgyIsImV4cCI6MTIzNDU2LCJqdGkiOiJmZDJmOWQ1ZTFhN2M0MmU4OTQ5MzVlMzYyYmNhOGJjYSJ9.NHlztMGER7UADHZJlxNG0WSi22a2KaYSfd1S-AuT7lU" \
  http://localhost:8000/api/some-protected-view/
  ```

When this short-lived access token expires, you can use the longer-lived refresh token to obtain another access token:
```bash
curl \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"refresh":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX3BrIjoxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImNvbGRfc3R1ZmYiOiLimIMiLCJleHAiOjIzNDU2NywianRpIjoiZGUxMmY0ZTY3MDY4NDI3ODg5ZjE1YWMyNzcwZGEwNTEifQ.aEoAYkSJjoWH1boshQAaTkf8G3yn0kapko6HFRt7Rh4"}' \
  http://localhost:8000/api/token/refresh/

...
{"access":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX3BrIjoxLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiY29sZF9zdHVmZiI6IuKYgyIsImV4cCI6MTIzNTY3LCJqdGkiOiJjNzE4ZTVkNjgzZWQ0NTQyYTU0NWJkM2VmMGI0ZGQ0ZSJ9.ekxRxgb9OKmHkfy-zs1Ro_xs1eMLXiR17dIDBVxeT-w"}
```

Abstract
--------

Simple JWT is a JSON Web Token authentication plugin for the `Django REST
Framework <http://www.django-rest-framework.org/>`__.

For full documentation, visit `django-rest-framework-simplejwt.readthedocs.io
<https://django-rest-framework-simplejwt.readthedocs.io/en/latest/>`__.

Looking for Maintainers
-----------------------

For more information, see `here
<https://github.com/SimpleJWT/django-rest-framework-simplejwt/issues/207>`__.
