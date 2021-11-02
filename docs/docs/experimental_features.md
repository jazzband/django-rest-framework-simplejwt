subtitle: JWTTokenUserAuthentication backend
title: Experimental features
---

The `JWTTokenUserAuthentication` backend\'s `authenticate` method does
not perform a database lookup to obtain a user instance. Instead, it
returns a `ninja_jwt.models.TokenUser` instance which acts as a
stateless user object backed only by a validated token instead of a
record in a database. This can facilitate developing single sign-on
functionality between separately hosted Django apps which all share the
same token secret key. To use this feature, add the
`ninja_jwt.authentication.JWTTokenUserAuthentication` backend (instead
of the default `JWTAuthentication` backend) to the Django REST
Framework\'s `DEFAULT_AUTHENTICATION_CLASSES` config setting:

``` {.sourceCode .python}
REST_FRAMEWORK = {
    ...
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...
        'ninja_jwt.authentication.JWTTokenUserAuthentication',
    )
    ...
}
```