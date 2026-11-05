from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class SGUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (('SDLC Guard', {'fields': ('role', 'mfa_enabled')}),)
    list_display = ('username', 'email', 'role', 'is_active')
