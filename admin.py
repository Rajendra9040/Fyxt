from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group as AuthGroup
from django.utils.translation import gettext_lazy as _
from django_tenants.admin import TenantAdminMixin

from .forms import UserCreationForm
from account.models import (
    Country,
    State,
    City,
    Currency,
    Plan,
    Account,
    Domain,
    Mailbox,
    Company,
    CompanyAddress,
    PermissionLabel,
    Category,
    Group,
    User,
    Profile,
    EmailVerification,
    Owner,
    AccountsNotificationSetUp,
    CompanyContactType
)

admin.site.unregister(AuthGroup)


@admin.register(Country)
class CountryAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'iso', 'iso3', 'calling_code')
    search_fields = ('name', 'iso', 'iso3', 'calling_code')

    fields = ('name', 'iso', 'iso3', 'calling_code', 'is_active')


@admin.register(State)
class StateAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('title_case_name', 'country', 'abbreviation')
    search_fields = ('name', 'country__name')

    fields = ('name', 'country', 'abbreviation', 'is_active')

    def title_case_name(self, obj):
        return obj.name.title()

    title_case_name.short_description = 'Name'


@admin.register(City)
class CityAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'state')
    search_fields = ('name', 'state__name')

    fields = ('name', 'state', 'is_active')


@admin.register(Currency)
class CurrencyAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'code', 'symbol')
    search_fields = ('name', 'code')

    fields = ('name', 'code', 'symbol', 'is_active')


class GroupInline(admin.StackedInline):
    fields = ('name', 'can_view', 'can_add', 'can_change', 'can_delete', 'can_approve', 'can_added_job', 'permissions', 'is_active')
    model = Group
    extra = 0


@admin.register(Plan)
class PlanAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'no_of_pm_users', 'no_of_tenants', 'no_of_vendors', 'is_active')
    search_fields = ('name',)
    fields = ('name', 'no_of_pm_users', 'no_of_tenants', 'no_of_vendors', 'description', 'is_active')


class DomainInline(admin.TabularInline):
    fields = ('origin', 'domain', 'is_primary', 'is_active')
    readonly_fields = ('domain',)
    model = Domain
    extra = 0


class MailboxInline(admin.TabularInline):
    fields = ('host', 'email', 'password', 'port', 'use_tls', 'primary', 'is_active')
    model = Mailbox
    extra = 0


class AccountsNotificationSetUpInline(admin.TabularInline):
    fields = ('pm_emails', 'pm_sms', 'pm_push', 'tenant_emails', 'tenant_sms', 'tenant_push',
              'engineers_emails', 'engineers_sms', 'engineers_push', 'vendor_emails', 'vendor_sms', 'vendor_push',
              'user_invitation_email')
    model = AccountsNotificationSetUp
    extra = 0


@admin.register(Account)
class AccountAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'short_name', 'schema_name', 'company', 'migrated_to_new_version')
    fields = ('schema_name', 'name', 'short_name', 'company', 'on_trial', 'paid_until', 'plan', 'migrated_to_new_version', 'is_active')
    # autocomplete_fields = ('company', 'plan')
    inlines = [DomainInline, MailboxInline, GroupInline, AccountsNotificationSetUpInline]


class CompanyAddressInline(admin.StackedInline):
    fields = ('name', 'type', 'address', 'country', 'state', 'city', 'zipcode', 'is_active')
    # autocomplete_fields = ('country', 'state', 'city')
    model = CompanyAddress
    extra = 0


@admin.register(Company)
class CompanyAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'entity_name', 'type', 'ein')
    search_fields = ('name', 'entity_name', 'ein')
    fields = ('name', 'entity_name', 'type', 'ein', 'vat', 'duns', 'currency', 'email', 'phone', 'fax', 'website', 'logo')

    inlines = [CompanyAddressInline]


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'is_active')
    search_fields = ('name',)

    fields = ('name', 'description', 'is_active')


@admin.register(PermissionLabel)
class PermissionLabelAdmin(TenantAdminMixin, admin.ModelAdmin):
    list_display = ('type', 'name', 'permission', 'order')
    search_fields = ('type', 'name')

    fields = ('type', 'name', 'permission', 'order', 'is_active')


@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'account', 'is_active')
    search_fields = ('name',)
    fields = ('name', 'account', 'can_view', 'can_add', 'can_change', 'can_delete', 'can_approve', 'can_added_job', 'permissions', 'is_active')
    filter_horizontal = ('permissions',)

    def formfield_for_manytomany(self, db_field, request=None, **kwargs):
        if db_field.name == 'permissions':
            qs = kwargs.get('queryset', db_field.remote_field.model.objects)
            # Avoid a major performance hit resolving permission names which
            # triggers a content_type load:
            kwargs['queryset'] = qs.select_related('content_type')
        return super().formfield_for_manytomany(db_field, request=request, **kwargs)

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class ProfileInline(admin.TabularInline):
    fields = ('hourly_rate', 'overtime_charge', 'trip_charge', 'weekend_rate', 'is_active')
    model = Profile
    fk_name = 'user'
    extra = 0


class EmailVerificationInline(admin.TabularInline):
    fields = ('is_verified', 'is_active')
    model = EmailVerification
    fk_name = 'user'
    extra = 1


@admin.register(User)
class UserAdmin(UserAdmin):
    add_form_template = 'admin/auth/user/add_form.html'
    change_user_password_template = None
    fieldsets = (
        (None, {'fields': ('hubspot_id', 'accounts', 'category', 'types', 'email', 'phone', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'recovery_email', 'photo', 'gender')}),
        # (_('Device'), {'fields': ('device_token', 'device_id', 'device_type')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'last_login', 'is_first_time_login', 'groups', 'user_permissions', 'is_suspended', 'suspended_date'),
        }),
        (_('Others'), {'fields': ('popup', 'is_first_ticket_created', 'live', 'notes')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('accounts', 'category', 'types', 'first_name', 'last_name', 'email', 'phone', 'password'),
        }),
    )
    readonly_fields = ('hubspot_id',)
    add_form = UserCreationForm
    list_display = ('email', 'phone', 'first_name', 'last_name', 'category', 'types', 'invitation_link', 'accounts_str', 'is_suspended', 'is_active')
    list_filter = ('category', 'is_staff', 'is_superuser', 'is_active')
    search_fields = ('email', 'first_name', 'last_name', 'phone', 'types', 'category')
    ordering = ('email',)
    filter_horizontal = ('accounts', 'groups', 'user_permissions',)

    inlines = [ProfileInline, EmailVerificationInline]


@admin.register(Owner)
class OwnerAdmin(admin.ModelAdmin):
    list_display = ('user', 'company', 'is_active')
    search_fields = ('company__name',)
    fields = ('user', 'company', 'is_active')


@admin.register(CompanyContactType)
class CompanyContactTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'order')
    search_fields = ('name',)
    fields = ('name', 'category', 'order')

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

