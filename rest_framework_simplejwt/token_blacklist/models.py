from django.conf import settings
from django.db import models


class OutstandingToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="outstanding_tokens",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    jti = models.CharField(unique=True, max_length=255)
    token = models.TextField()

    created_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        # Work around for a bug in Django:
        # https://code.djangoproject.com/ticket/19422
        #
        # Also see corresponding ticket:
        # https://github.com/encode/django-rest-framework/issues/705
        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )
        ordering = ("user",)

    def __str__(self) -> str:
        return "Token for {} ({})".format(
            self.user,
            self.jti,
        )


class BlacklistedToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    token = models.OneToOneField(
        OutstandingToken, related_name="blacklisted_token", on_delete=models.CASCADE
    )

    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Work around for a bug in Django:
        # https://code.djangoproject.com/ticket/19422
        #
        # Also see corresponding ticket:
        # https://github.com/encode/django-rest-framework/issues/705
        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )

    def __str__(self) -> str:
        return f"Blacklisted token for {self.token.user}"
