from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import BlacklistedToken, OutstandingToken


class OutstandingTokenAdmin(admin.ModelAdmin):
    list_display = (
        'jti',
        'user',
        'created_at',
        'expires_at',
    )
    search_fields = (
        'user__id',
        'jti',
    )
    ordering = (
        'user',
    )

    def get_queryset(self, *args, **kwargs):
        qs = super().get_queryset(*args, **kwargs)

        return qs.select_related('user')

    # Read-only behavior defined below
    actions = None

    def get_readonly_fields(self, *args, **kwargs):
        return [f.name for f in self.model._meta.fields]

    def has_add_permission(self, *args, **kwargs):
        return False

    def has_delete_permission(self, *args, **kwargs):
        return True

    def has_change_permission(self, request, obj=None):
        return (
            request.method in ['GET', 'HEAD'] and  # noqa: W504
            super().has_change_permission(request, obj)
        )


admin.site.register(OutstandingToken, OutstandingTokenAdmin)


class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = (
        'token_jti',
        'token_user',
        'token_created_at',
        'token_expires_at',
        'blacklisted_at',
    )
    search_fields = (
        'token__user__id',
        'token__jti',
    )
    ordering = (
        'token__user',
    )

    def get_queryset(self, *args, **kwargs):
        qs = super().get_queryset(*args, **kwargs)

        return qs.select_related('token__user')

    def token_jti(self, obj):
        return obj.token.jti
    token_jti.short_description = _('jti')
    token_jti.admin_order_field = 'token__jti'

    def token_user(self, obj):
        return obj.token.user
    token_user.short_description = _('user')
    token_user.admin_order_field = 'token__user'

    def token_created_at(self, obj):
        return obj.token.created_at
    token_created_at.short_description = _('created at')
    token_created_at.admin_order_field = 'token__created_at'

    def token_expires_at(self, obj):
        return obj.token.expires_at
    token_expires_at.short_description = _('expires at')
    token_expires_at.admin_order_field = 'token__expires_at'


admin.site.register(BlacklistedToken, BlacklistedTokenAdmin)
